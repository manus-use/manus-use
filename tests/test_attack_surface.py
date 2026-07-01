"""
Tests for src/manus_agent/tools/score_attack_surface.py

All external HTTP calls are mocked — no real network I/O.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from manus_agent.tools.score_attack_surface import (
    _WEIGHTS,
    _archetype_label,
    _build_rationale,
    _build_target_corpus,
    _compute_overall,
    _cpe_vendor_product,
    _dimension_label,
    _exposure_label,
    _extract_cpe_strings,
    _extract_cvss_fields,
    _extract_cwes,
    _extract_description,
    _fetch_nvd_data,
    _render_text,
    _run_attack_surface,
    _score_attack_vector,
    _score_auth_scope,
    _score_deployment_archetype,
    _score_internet_prevalence,
    _score_public_facing,
    score_attack_surface,
)

# ===========================================================================
# Test data helpers
# ===========================================================================


def _make_nvd_cve(
    av: str = "NETWORK",
    pr: str = "NONE",
    scope: str = "UNCHANGED",
    base_score: float = 9.8,
    description: str = "A remote code execution vulnerability in the web server.",
    cpe_strings: list[str] | None = None,
    cwes: list[str] | None = None,
) -> dict[str, Any]:
    """Build a minimal NVD CVE data dict for testing."""
    nodes = []
    if cpe_strings:
        nodes = [{"cpeMatch": [{"criteria": cpe, "vulnerable": True} for cpe in cpe_strings]}]
    weakness_list = []
    if cwes:
        weakness_list = [{"description": [{"lang": "en", "value": cwe}]} for cwe in cwes]

    return {
        "descriptions": [{"lang": "en", "value": description}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "attackVector": av,
                        "privilegesRequired": pr,
                        "scope": scope,
                        "baseScore": base_score,
                    }
                }
            ]
        },
        "configurations": [{"nodes": nodes}] if nodes else [],
        "weaknesses": weakness_list,
    }


def _make_nvd_response(cve_data: dict[str, Any], cve_id: str = "CVE-2021-44228") -> dict[str, Any]:
    """Wrap a CVE data dict in an NVD API response envelope."""
    return {
        "resultsPerPage": 1,
        "vulnerabilities": [{"cve": {**cve_data, "id": cve_id}}],
    }


# ===========================================================================
# _fetch_nvd_data
# ===========================================================================


class TestFetchNvdData:
    def test_success(self):
        cve_data = _make_nvd_cve()
        response = _make_nvd_response(cve_data)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = response

        with patch("manus_agent.tools.score_attack_surface.requests.get", return_value=mock_resp):
            result = _fetch_nvd_data("CVE-2021-44228")

        assert result.get("descriptions") is not None

    def test_empty_vulnerabilities(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulnerabilities": []}

        with patch("manus_agent.tools.score_attack_surface.requests.get", return_value=mock_resp):
            result = _fetch_nvd_data("CVE-9999-0001")

        assert result == {}

    def test_request_exception(self):
        import requests as _req

        with patch(
            "manus_agent.tools.score_attack_surface.requests.get",
            side_effect=_req.RequestException("timeout"),
        ):
            result = _fetch_nvd_data("CVE-2021-44228")

        assert result == {}

    def test_http_error(self):
        import requests as _req

        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = _req.RequestException("404")

        with patch("manus_agent.tools.score_attack_surface.requests.get", return_value=mock_resp):
            result = _fetch_nvd_data("CVE-2021-44228")

        assert result == {}


# ===========================================================================
# _extract_cvss_fields
# ===========================================================================


class TestExtractCvssFields:
    def test_v31_fields(self):
        cve_data = _make_nvd_cve(av="NETWORK", pr="NONE", scope="CHANGED", base_score=10.0)
        fields = _extract_cvss_fields(cve_data)
        assert fields["attackVector"] == "NETWORK"
        assert fields["privilegesRequired"] == "NONE"
        assert fields["scope"] == "CHANGED"
        assert fields["baseScore"] == 10.0

    def test_v30_fallback(self):
        cve_data = {
            "metrics": {
                "cvssMetricV30": [
                    {
                        "cvssData": {
                            "attackVector": "LOCAL",
                            "privilegesRequired": "HIGH",
                            "scope": "UNCHANGED",
                            "baseScore": 5.0,
                        }
                    }
                ]
            }
        }
        fields = _extract_cvss_fields(cve_data)
        assert fields["attackVector"] == "LOCAL"

    def test_no_metrics(self):
        fields = _extract_cvss_fields({})
        assert fields == {}

    def test_empty_metrics(self):
        fields = _extract_cvss_fields({"metrics": {}})
        assert fields == {}


# ===========================================================================
# _extract_description
# ===========================================================================


class TestExtractDescription:
    def test_english_description(self):
        cve_data = {
            "descriptions": [
                {"lang": "es", "value": "descripcion"},
                {"lang": "en", "value": "A remote code execution vulnerability."},
            ]
        }
        assert _extract_description(cve_data) == "A remote code execution vulnerability."

    def test_no_descriptions(self):
        assert _extract_description({}) == ""

    def test_no_english(self):
        cve_data = {"descriptions": [{"lang": "de", "value": "test"}]}
        assert _extract_description(cve_data) == ""

    def test_en_us_lang(self):
        cve_data = {"descriptions": [{"lang": "en-US", "value": "US description"}]}
        assert _extract_description(cve_data) == "US description"


# ===========================================================================
# _extract_cpe_strings
# ===========================================================================


class TestExtractCpeStrings:
    def test_basic_cpe(self):
        cve_data = _make_nvd_cve(cpe_strings=["cpe:2.3:a:apache:httpd:2.4.50:*:*:*:*:*:*:*"])
        cpes = _extract_cpe_strings(cve_data)
        assert "cpe:2.3:a:apache:httpd:2.4.50:*:*:*:*:*:*:*" in cpes

    def test_no_configurations(self):
        cpes = _extract_cpe_strings({})
        assert cpes == []

    def test_multiple_nodes(self):
        cve_data = {
            "configurations": [
                {
                    "nodes": [
                        {"cpeMatch": [{"criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}]},
                        {"cpeMatch": [{"criteria": "cpe:2.3:a:other:tool:2.0:*:*:*:*:*:*:*"}]},
                    ]
                }
            ]
        }
        cpes = _extract_cpe_strings(cve_data)
        assert len(cpes) == 2


# ===========================================================================
# _extract_cwes
# ===========================================================================


class TestExtractCwes:
    def test_single_cwe(self):
        cve_data = _make_nvd_cve(cwes=["CWE-79"])
        cwes = _extract_cwes(cve_data)
        assert "CWE-79" in cwes

    def test_no_weaknesses(self):
        assert _extract_cwes({}) == []

    def test_multiple_cwes(self):
        cve_data = _make_nvd_cve(cwes=["CWE-79", "CWE-89"])
        cwes = _extract_cwes(cve_data)
        assert "CWE-79" in cwes
        assert "CWE-89" in cwes

    def test_non_cwe_filtered(self):
        cve_data = {"weaknesses": [{"description": [{"lang": "en", "value": "NVD-CWE-noinfo"}]}]}
        cwes = _extract_cwes(cve_data)
        assert cwes == []


# ===========================================================================
# _cpe_vendor_product
# ===========================================================================


class TestCpeVendorProduct:
    def test_application_cpe(self):
        v, p = _cpe_vendor_product("cpe:2.3:a:apache:httpd:2.4.50:*:*:*:*:*:*:*")
        assert v == "apache"
        assert p == "httpd"

    def test_os_cpe(self):
        v, p = _cpe_vendor_product("cpe:2.3:o:linux:linux_kernel:5.15:*:*:*:*:*:*:*")
        assert v == "linux"
        assert p == "linux_kernel"

    def test_invalid_cpe(self):
        v, p = _cpe_vendor_product("not-a-cpe")
        assert v == ""
        assert p == ""

    def test_empty_string(self):
        v, p = _cpe_vendor_product("")
        assert v == ""
        assert p == ""


# ===========================================================================
# _build_target_corpus
# ===========================================================================


class TestBuildTargetCorpus:
    def test_includes_description(self):
        corpus = _build_target_corpus("A vulnerability in nginx", [])
        assert "nginx" in corpus

    def test_includes_cpe_product(self):
        corpus = _build_target_corpus("desc", ["cpe:2.3:a:apache:httpd:2.4.50:*:*:*:*:*:*:*"])
        assert "apache" in corpus
        assert "httpd" in corpus

    def test_lowercase(self):
        corpus = _build_target_corpus("APACHE Tomcat", [])
        assert corpus == corpus.lower()

    def test_underscore_normalized(self):
        corpus = _build_target_corpus("", ["cpe:2.3:a:vendor:web_server:1.0:*:*:*:*:*:*:*"])
        assert "web server" in corpus


# ===========================================================================
# _score_deployment_archetype
# ===========================================================================


class TestScoreDeploymentArchetype:
    def test_web_server_nginx(self):
        score, label = _score_deployment_archetype("nginx web server")
        assert score == 5
        assert label == "web_server_or_api_gateway"

    def test_apache(self):
        score, label = _score_deployment_archetype("apache httpd")
        assert score == 5

    def test_wordpress(self):
        score, label = _score_deployment_archetype("wordpress cms")
        assert score == 5

    def test_router_firmware(self):
        score, label = _score_deployment_archetype("router firmware vpn")
        assert score == 4
        assert label == "network_device_or_iot"

    def test_database_postgresql(self):
        score, label = _score_deployment_archetype("postgresql database")
        assert score == 3
        assert label == "database_or_middleware"

    def test_browser(self):
        score, label = _score_deployment_archetype("firefox browser")
        assert score == 2
        assert label == "desktop_or_browser"

    def test_cli_tool(self):
        score, label = _score_deployment_archetype("cli command line tool")
        assert score == 1
        assert label == "cli_or_library"

    def test_unknown_defaults_to_cli(self):
        score, label = _score_deployment_archetype("xyzzy obscure_tool_123")
        assert score == 1

    def test_highest_tier_wins(self):
        # corpus contains both cli and nginx — nginx (tier 5) should win
        score, label = _score_deployment_archetype("nginx cli tool library")
        assert score == 5


# ===========================================================================
# _archetype_label
# ===========================================================================


class TestArchetypeLabel:
    def test_all_scores(self):
        assert _archetype_label(5) == "web_server_or_api_gateway"
        assert _archetype_label(4) == "network_device_or_iot"
        assert _archetype_label(3) == "database_or_middleware"
        assert _archetype_label(2) == "desktop_or_browser"
        assert _archetype_label(1) == "cli_or_library"

    def test_unknown(self):
        assert _archetype_label(99) == "unknown"


# ===========================================================================
# _score_attack_vector
# ===========================================================================


class TestScoreAttackVector:
    def test_network(self):
        assert _score_attack_vector("NETWORK") == 5

    def test_adjacent(self):
        assert _score_attack_vector("ADJACENT") == 3

    def test_local(self):
        assert _score_attack_vector("LOCAL") == 2

    def test_physical(self):
        assert _score_attack_vector("PHYSICAL") == 1

    def test_unknown_default(self):
        assert _score_attack_vector("") == 3

    def test_case_insensitive(self):
        assert _score_attack_vector("network") == 5


# ===========================================================================
# _score_internet_prevalence
# ===========================================================================


class TestScoreInternetPrevalence:
    def test_high_prevalence_apache(self):
        assert _score_internet_prevalence("apache httpd") == 5

    def test_high_prevalence_openssl(self):
        assert _score_internet_prevalence("openssl library") == 5

    def test_high_prevalence_log4j(self):
        assert _score_internet_prevalence("log4j java") == 5

    def test_medium_prevalence_server(self):
        score = _score_internet_prevalence("some server application platform enterprise cloud service")
        assert score >= 3

    def test_low_prevalence(self):
        score = _score_internet_prevalence("xyzzy_lib_unknown")
        assert score == 2


# ===========================================================================
# _score_auth_scope
# ===========================================================================


class TestScoreAuthScope:
    def test_none_changed(self):
        assert _score_auth_scope("NONE", "CHANGED") == 5

    def test_none_unchanged(self):
        assert _score_auth_scope("NONE", "UNCHANGED") == 4

    def test_low_privileges(self):
        assert _score_auth_scope("LOW", "UNCHANGED") == 3

    def test_high_privileges(self):
        assert _score_auth_scope("HIGH", "UNCHANGED") == 2

    def test_unknown_pr(self):
        assert _score_auth_scope("", "") == 1

    def test_case_insensitive(self):
        assert _score_auth_scope("none", "changed") == 5


# ===========================================================================
# _score_public_facing
# ===========================================================================


class TestScorePublicFacing:
    def test_remote_attacker_phrase(self):
        assert _score_public_facing("remote attacker can execute arbitrary code", []) == 5

    def test_unauthenticated_remote(self):
        assert _score_public_facing("unauthenticated remote user", []) == 5

    def test_rce_phrase(self):
        assert _score_public_facing("allows remote code execution via a crafted request", []) == 5

    def test_without_authentication(self):
        assert _score_public_facing("exploitable without authentication", []) == 5

    def test_public_facing_cwe(self):
        assert _score_public_facing("generic description", ["CWE-79"]) == 5

    def test_rce_cwe(self):
        assert _score_public_facing("generic", ["CWE-94"]) == 5

    def test_no_signal(self):
        assert _score_public_facing("local privilege escalation", []) == 1

    def test_no_signal_no_cwe(self):
        assert _score_public_facing("requires local access", ["CWE-125"]) == 1

    def test_pre_auth(self):
        assert _score_public_facing("pre-auth heap overflow", []) == 5

    def test_internet_facing(self):
        assert _score_public_facing("internet-facing service is affected", []) == 5


# ===========================================================================
# _compute_overall
# ===========================================================================


class TestComputeOverall:
    def test_all_fives(self):
        dims = {k: 5 for k in _WEIGHTS}
        score = _compute_overall(dims)
        assert score == 5.0

    def test_all_ones(self):
        dims = {k: 1 for k in _WEIGHTS}
        score = _compute_overall(dims)
        assert score == 1.0

    def test_mixed(self):
        dims = {
            "deployment_archetype": 5,
            "attack_vector": 5,
            "internet_prevalence": 3,
            "auth_scope": 4,
            "public_facing": 5,
        }
        score = _compute_overall(dims)
        assert 1.0 <= score <= 5.0
        # Weighted: 5*0.30 + 5*0.25 + 3*0.20 + 4*0.15 + 5*0.10
        expected = round(5 * 0.30 + 5 * 0.25 + 3 * 0.20 + 4 * 0.15 + 5 * 0.10, 2)
        assert score == expected

    def test_weights_sum_to_one(self):
        """Weights in _WEIGHTS must sum to 1.0 (floating-point tolerance)."""
        assert abs(sum(_WEIGHTS.values()) - 1.0) < 1e-9


# ===========================================================================
# _exposure_label
# ===========================================================================


class TestExposureLabel:
    def test_minimal(self):
        assert _exposure_label(1.0) == "minimal"

    def test_low(self):
        assert _exposure_label(2.0) == "low"

    def test_moderate(self):
        assert _exposure_label(3.0) == "moderate"

    def test_high(self):
        assert _exposure_label(4.0) == "high"

    def test_critical(self):
        assert _exposure_label(5.0) == "critical"

    def test_boundary_low_to_moderate(self):
        assert _exposure_label(2.49) == "low"
        assert _exposure_label(2.51) == "moderate"

    def test_boundary_high_to_critical(self):
        assert _exposure_label(4.49) == "high"
        assert _exposure_label(4.51) == "critical"


# ===========================================================================
# _dimension_label
# ===========================================================================


class TestDimensionLabel:
    def test_all_scores(self):
        assert _dimension_label(1) == "minimal"
        assert _dimension_label(2) == "low"
        assert _dimension_label(3) == "moderate"
        assert _dimension_label(4) == "high"
        assert _dimension_label(5) == "critical"

    def test_clamp_below(self):
        assert _dimension_label(0) == "minimal"

    def test_clamp_above(self):
        assert _dimension_label(6) == "critical"


# ===========================================================================
# _build_rationale
# ===========================================================================


class TestBuildRationale:
    def test_high_archetype(self):
        r = _build_rationale(
            {
                "deployment_archetype": 5,
                "attack_vector": 5,
                "internet_prevalence": 5,
                "auth_scope": 4,
                "public_facing": 5,
            },
            "web_server_or_api_gateway",
            "NETWORK",
            "NONE",
            "UNCHANGED",
            "Remote code execution",
        )
        assert "web server or api gateway" in r.lower()
        assert "high-exposure" in r.lower()

    def test_low_archetype(self):
        r = _build_rationale(
            {
                "deployment_archetype": 1,
                "attack_vector": 2,
                "internet_prevalence": 2,
                "auth_scope": 2,
                "public_facing": 1,
            },
            "cli_or_library",
            "LOCAL",
            "HIGH",
            "UNCHANGED",
            "Local privilege escalation",
        )
        assert "cli or library" in r.lower()
        assert "low-exposure" in r.lower()

    def test_no_auth_mentioned(self):
        r = _build_rationale(
            {
                "deployment_archetype": 3,
                "attack_vector": 5,
                "internet_prevalence": 3,
                "auth_scope": 4,
                "public_facing": 5,
            },
            "database_or_middleware",
            "NETWORK",
            "NONE",
            "UNCHANGED",
            "Remote attacker can access the database",
        )
        assert "no authentication" in r.lower()

    def test_public_facing_signal(self):
        r = _build_rationale(
            {
                "deployment_archetype": 5,
                "attack_vector": 5,
                "internet_prevalence": 5,
                "auth_scope": 5,
                "public_facing": 5,
            },
            "web_server_or_api_gateway",
            "NETWORK",
            "NONE",
            "CHANGED",
            "Remote code execution",
        )
        assert "public" in r.lower() or "internet" in r.lower()

    def test_no_av_missing(self):
        # Should not error when av is empty string
        r = _build_rationale(
            {
                "deployment_archetype": 2,
                "attack_vector": 3,
                "internet_prevalence": 2,
                "auth_scope": 1,
                "public_facing": 1,
            },
            "desktop_or_browser",
            "",
            "",
            "",
            "Local overflow",
        )
        assert isinstance(r, str)


# ===========================================================================
# _render_text
# ===========================================================================


class TestRenderText:
    def _sample_result(self, **overrides) -> dict:
        base = {
            "cve_id": "CVE-2021-44228",
            "exposure_score": 4.85,
            "exposure_label": "critical",
            "archetype": "web_server_or_api_gateway",
            "dimensions": {
                "deployment_archetype": 5,
                "attack_vector": 5,
                "internet_prevalence": 5,
                "auth_scope": 4,
                "public_facing": 5,
            },
            "cvss_available": True,
            "cpe_count": 3,
            "cwes": ["CWE-502"],
            "attack_vector": "NETWORK",
            "privileges_required": "NONE",
            "scope": "CHANGED",
            "cvss_base_score": 10.0,
            "rationale": "A web server component with NETWORK access and no auth required.",
        }
        base.update(overrides)
        return base

    def test_header(self):
        text = _render_text(self._sample_result())
        assert "CVE-2021-44228" in text
        assert "Attack Surface Exposure Score" in text

    def test_score_displayed(self):
        text = _render_text(self._sample_result())
        assert "4.85" in text
        assert "CRITICAL" in text

    def test_archetype_displayed(self):
        text = _render_text(self._sample_result())
        assert "web server or api gateway" in text

    def test_dimensions_listed(self):
        text = _render_text(self._sample_result())
        assert "Deployment archetype" in text
        assert "Authentication scope" in text

    def test_rationale_present(self):
        text = _render_text(self._sample_result())
        assert "web server component" in text

    def test_cpe_count(self):
        text = _render_text(self._sample_result())
        assert "3" in text

    def test_cwes_listed(self):
        text = _render_text(self._sample_result())
        assert "CWE-502" in text

    def test_no_cwes(self):
        text = _render_text(self._sample_result(cwes=[]))
        assert "none" in text

    def test_no_cvss(self):
        text = _render_text(self._sample_result(cvss_available=False, cvss_base_score=None))
        assert "N/A" in text


# ===========================================================================
# _run_attack_surface  (full pipeline, mocked NVD)
# ===========================================================================


class TestRunAttackSurface:
    def _mock_nvd(self, cve_data: dict[str, Any]):
        """Return a context-manager mock for requests.get that returns cve_data."""
        response = _make_nvd_response(cve_data)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = response
        return patch("manus_agent.tools.score_attack_surface.requests.get", return_value=mock_resp)

    def test_log4shell_high_exposure(self):
        cve_data = _make_nvd_cve(
            av="NETWORK",
            pr="NONE",
            scope="CHANGED",
            base_score=10.0,
            description="Remote code execution in log4j via JNDI lookup",
            cpe_strings=["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"],
            cwes=["CWE-502"],
        )
        with self._mock_nvd(cve_data):
            result = _run_attack_surface("CVE-2021-44228")

        assert result["cve_id"] == "CVE-2021-44228"
        assert result["exposure_score"] >= 4.0
        assert result["exposure_label"] in ("high", "critical")
        assert result["dimensions"]["attack_vector"] == 5
        assert result["dimensions"]["auth_scope"] == 5  # NONE + CHANGED

    def test_local_cli_low_exposure(self):
        cve_data = _make_nvd_cve(
            av="LOCAL",
            pr="HIGH",
            scope="UNCHANGED",
            base_score=4.4,
            description="Local privilege escalation in a CLI utility",
            cpe_strings=["cpe:2.3:a:vendor:cli_tool:1.0:*:*:*:*:*:*:*"],
            cwes=["CWE-125"],
        )
        with self._mock_nvd(cve_data):
            result = _run_attack_surface("CVE-2024-9999")

        assert result["exposure_score"] < 3.5
        assert result["exposure_label"] in ("minimal", "low", "moderate")
        assert result["dimensions"]["attack_vector"] == 2

    def test_network_device_medium_exposure(self):
        cve_data = _make_nvd_cve(
            av="NETWORK",
            pr="NONE",
            scope="UNCHANGED",
            base_score=9.1,
            description="Remote attacker can exploit a VPN appliance",
            cpe_strings=["cpe:2.3:a:fortinet:fortigate:7.0.0:*:*:*:*:*:*:*"],
        )
        with self._mock_nvd(cve_data):
            result = _run_attack_surface("CVE-2023-1234")

        assert result["dimensions"]["deployment_archetype"] >= 4

    def test_nvd_unavailable_graceful(self):
        import requests as _req

        with patch(
            "manus_agent.tools.score_attack_surface.requests.get",
            side_effect=_req.RequestException("network error"),
        ):
            result = _run_attack_surface("CVE-2021-44228")

        assert result["cve_id"] == "CVE-2021-44228"
        assert result["cvss_available"] is False
        assert isinstance(result["exposure_score"], float)
        assert 1.0 <= result["exposure_score"] <= 5.0

    def test_output_fields_present(self):
        cve_data = _make_nvd_cve()
        with self._mock_nvd(cve_data):
            result = _run_attack_surface("CVE-2021-44228")

        required_keys = [
            "cve_id",
            "exposure_score",
            "exposure_label",
            "archetype",
            "dimensions",
            "cvss_available",
            "cpe_count",
            "cwes",
            "attack_vector",
            "privileges_required",
            "scope",
            "cvss_base_score",
            "rationale",
        ]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"

    def test_dimensions_all_present(self):
        cve_data = _make_nvd_cve()
        with self._mock_nvd(cve_data):
            result = _run_attack_surface("CVE-2021-44228")

        expected_dims = {
            "deployment_archetype",
            "attack_vector",
            "internet_prevalence",
            "auth_scope",
            "public_facing",
        }
        assert set(result["dimensions"].keys()) == expected_dims

    def test_dimensions_in_range(self):
        cve_data = _make_nvd_cve()
        with self._mock_nvd(cve_data):
            result = _run_attack_surface("CVE-2021-44228")

        for key, val in result["dimensions"].items():
            assert 1 <= val <= 5, f"Dimension {key}={val} out of range"

    def test_cpe_count_populated(self):
        cve_data = _make_nvd_cve(
            cpe_strings=[
                "cpe:2.3:a:apache:httpd:2.4.50:*:*:*:*:*:*:*",
                "cpe:2.3:a:apache:httpd:2.4.51:*:*:*:*:*:*:*",
            ]
        )
        with self._mock_nvd(cve_data):
            result = _run_attack_surface("CVE-2021-44228")

        assert result["cpe_count"] == 2


# ===========================================================================
# score_attack_surface  (public @tool entry point)
# ===========================================================================


class TestScoreAttackSurface:
    def _mock_run(self):
        return {
            "cve_id": "CVE-2021-44228",
            "exposure_score": 4.85,
            "exposure_label": "critical",
            "archetype": "web_server_or_api_gateway",
            "dimensions": {
                "deployment_archetype": 5,
                "attack_vector": 5,
                "internet_prevalence": 5,
                "auth_scope": 4,
                "public_facing": 5,
            },
            "cvss_available": True,
            "cpe_count": 2,
            "cwes": ["CWE-502"],
            "attack_vector": "NETWORK",
            "privileges_required": "NONE",
            "scope": "CHANGED",
            "cvss_base_score": 10.0,
            "rationale": "Log4Shell is a web-facing library with NETWORK access and no auth.",
        }

    def test_text_output_default(self):
        with patch(
            "manus_agent.tools.score_attack_surface._run_attack_surface",
            return_value=self._mock_run(),
        ):
            result = score_attack_surface(cve_id="CVE-2021-44228")

        assert "CVE-2021-44228" in result
        assert "Attack Surface" in result

    def test_json_output(self):
        with patch(
            "manus_agent.tools.score_attack_surface._run_attack_surface",
            return_value=self._mock_run(),
        ):
            result = score_attack_surface(cve_id="CVE-2021-44228", output="json")

        parsed = json.loads(result)
        assert parsed["cve_id"] == "CVE-2021-44228"
        assert parsed["exposure_score"] == 4.85

    def test_invalid_cve_id(self):
        result = score_attack_surface(cve_id="not-a-cve")
        assert "Error" in result

    def test_invalid_cve_id_empty(self):
        result = score_attack_surface(cve_id="")
        assert "Error" in result

    def test_lowercase_cve_accepted(self):
        with patch(
            "manus_agent.tools.score_attack_surface._run_attack_surface",
            return_value=self._mock_run(),
        ) as mock_run:
            score_attack_surface(cve_id="cve-2021-44228")
        # The tool should pass through (regex is case-insensitive)
        mock_run.assert_called_once()

    def test_cve_id_whitespace_stripped(self):
        with patch(
            "manus_agent.tools.score_attack_surface._run_attack_surface",
            return_value=self._mock_run(),
        ) as mock_run:
            score_attack_surface(cve_id="  CVE-2021-44228  ")
        mock_run.assert_called_once()


# ===========================================================================
# CLI integration
# ===========================================================================


class TestAttackSurfaceCli:
    def test_text_output(self, capsys):
        from manus_agent.cli import _run_attack_surface as cli_run

        mock_result = {
            "cve_id": "CVE-2021-44228",
            "exposure_score": 4.85,
            "exposure_label": "critical",
            "archetype": "web_server_or_api_gateway",
            "dimensions": {
                "deployment_archetype": 5,
                "attack_vector": 5,
                "internet_prevalence": 5,
                "auth_scope": 4,
                "public_facing": 5,
            },
            "cvss_available": True,
            "cpe_count": 2,
            "cwes": ["CWE-502"],
            "attack_vector": "NETWORK",
            "privileges_required": "NONE",
            "scope": "CHANGED",
            "cvss_base_score": 10.0,
            "rationale": "Web server with NETWORK access and no authentication.",
        }

        with patch(
            "manus_agent.tools.score_attack_surface._run_attack_surface",
            return_value=mock_result,
        ):
            rc = cli_run(["CVE-2021-44228"])

        assert rc == 0
        out = capsys.readouterr().out
        assert "CVE-2021-44228" in out

    def test_json_output(self, capsys):
        from manus_agent.cli import _run_attack_surface as cli_run

        mock_result = {
            "cve_id": "CVE-2021-44228",
            "exposure_score": 4.85,
            "exposure_label": "critical",
            "archetype": "web_server_or_api_gateway",
            "dimensions": {
                "deployment_archetype": 5,
                "attack_vector": 5,
                "internet_prevalence": 5,
                "auth_scope": 4,
                "public_facing": 5,
            },
            "cvss_available": True,
            "cpe_count": 2,
            "cwes": [],
            "attack_vector": "NETWORK",
            "privileges_required": "NONE",
            "scope": "CHANGED",
            "cvss_base_score": 10.0,
            "rationale": "Web server with NETWORK access.",
        }

        with patch(
            "manus_agent.tools.score_attack_surface._run_attack_surface",
            return_value=mock_result,
        ):
            rc = cli_run(["CVE-2021-44228", "--output", "json"])

        assert rc == 0
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["exposure_score"] == 4.85

    def test_invalid_cve_exits_nonzero(self):
        from manus_agent.cli import _run_attack_surface as cli_run

        with pytest.raises(SystemExit) as exc_info:
            cli_run(["not-a-cve"])
        assert exc_info.value.code != 0

    def test_attack_surface_in_known_subcommands(self):
        from manus_agent.cli import _SUBCOMMANDS

        assert "attack-surface" in _SUBCOMMANDS

    def test_help_flag(self):
        from manus_agent.cli import _run_attack_surface as cli_run

        with pytest.raises(SystemExit) as exc_info:
            cli_run(["--help"])
        assert exc_info.value.code == 0
