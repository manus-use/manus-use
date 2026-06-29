"""
Tests for compare_cves tool and manus-use compare CLI subcommand.

All tests are fully mocked — no real HTTP calls are made.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

# ──────────────────────────────────────────────────────────────────────────────
# Fixtures / shared mock data
# ──────────────────────────────────────────────────────────────────────────────

MOCK_NVD_LOG4SHELL = {
    "id": "CVE-2021-44228",
    "published": "2021-12-10T10:15:09.143",
    "descriptions": [{"lang": "en", "value": "Apache Log4j2 RCE vulnerability via JNDI"}],
    "metrics": {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "version": "3.1",
                    "baseScore": 10.0,
                    "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "attackVector": "NETWORK",
                    "privilegesRequired": "NONE",
                    "userInteraction": "NONE",
                }
            }
        ]
    },
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-917"}]}],
    "configurations": [
        {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "vulnerable": True}]}]}
    ],
}

MOCK_NVD_XZ = {
    "id": "CVE-2024-3094",
    "published": "2024-03-29T17:15:21.940",
    "descriptions": [{"lang": "en", "value": "XZ Utils backdoor inserted by malicious actor"}],
    "metrics": {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "version": "3.1",
                    "baseScore": 10.0,
                    "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "attackVector": "NETWORK",
                    "privilegesRequired": "NONE",
                    "userInteraction": "NONE",
                }
            }
        ]
    },
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-506"}]}],
    "configurations": [
        {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:tukaani:xz_utils:*:*:*:*:*:*:*:*", "vulnerable": True}]}]}
    ],
}

MOCK_EPSS_LOG4SHELL = {"cve": "CVE-2021-44228", "epss": "0.97535", "percentile": "0.99999", "date": "2024-01-01"}
MOCK_EPSS_XZ = {"cve": "CVE-2024-3094", "epss": "0.04234", "percentile": "0.87543", "date": "2024-01-01"}

MOCK_KEV_CATALOG = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "requiredAction": "Apply updates per vendor guidance.",
        }
    ]
}


def _nvd_response(record: dict) -> MagicMock:
    """Create a mock requests.Response for NVD data."""
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"vulnerabilities": [{"cve": record}]}
    return resp


def _epss_response(entry: dict) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"data": [entry]}
    return resp


def _kev_response(catalog: dict) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = catalog
    return resp


# ──────────────────────────────────────────────────────────────────────────────
# Unit tests for private helper functions
# ──────────────────────────────────────────────────────────────────────────────


class TestFetchNvd:
    def test_returns_cve_record_on_success(self):
        from manus_use.tools.compare_cves import _fetch_nvd

        with patch("manus_use.tools.compare_cves.requests.get") as mock_get:
            mock_get.return_value = _nvd_response(MOCK_NVD_LOG4SHELL)
            result = _fetch_nvd("CVE-2021-44228")

        assert result.get("id") == "CVE-2021-44228"

    def test_returns_error_dict_when_no_vulnerabilities(self):
        from manus_use.tools.compare_cves import _fetch_nvd

        with patch("manus_use.tools.compare_cves.requests.get") as mock_get:
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            resp.json.return_value = {"vulnerabilities": []}
            mock_get.return_value = resp
            result = _fetch_nvd("CVE-9999-9999")

        assert "error" in result

    def test_returns_error_dict_on_request_exception(self):
        import requests

        from manus_use.tools.compare_cves import _fetch_nvd

        with patch("manus_use.tools.compare_cves.requests.get", side_effect=requests.RequestException("timeout")):
            result = _fetch_nvd("CVE-2021-44228")

        assert "error" in result
        assert "timeout" in result["error"]


class TestFetchEpss:
    def test_returns_entry_on_success(self):
        from manus_use.tools.compare_cves import _fetch_epss

        with patch("manus_use.tools.compare_cves.requests.get") as mock_get:
            mock_get.return_value = _epss_response(MOCK_EPSS_LOG4SHELL)
            result = _fetch_epss("CVE-2021-44228")

        assert result.get("epss") == "0.97535"

    def test_returns_error_dict_when_no_data(self):
        from manus_use.tools.compare_cves import _fetch_epss

        with patch("manus_use.tools.compare_cves.requests.get") as mock_get:
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            resp.json.return_value = {"data": []}
            mock_get.return_value = resp
            result = _fetch_epss("CVE-9999-9999")

        assert "error" in result

    def test_returns_error_on_request_exception(self):
        import requests

        from manus_use.tools.compare_cves import _fetch_epss

        with patch("manus_use.tools.compare_cves.requests.get", side_effect=requests.RequestException("conn")):
            result = _fetch_epss("CVE-2021-44228")

        assert "error" in result


class TestFetchKev:
    def test_returns_in_kev_true_for_known_cve(self):
        from manus_use.tools.compare_cves import _fetch_kev

        with patch("manus_use.tools.compare_cves.requests.get") as mock_get:
            mock_get.return_value = _kev_response(MOCK_KEV_CATALOG)
            result = _fetch_kev("CVE-2021-44228")

        assert result["in_kev"] is True
        assert result["date_added"] == "2021-12-10"
        assert result["vendor_project"] == "Apache"

    def test_returns_in_kev_false_for_unknown_cve(self):
        from manus_use.tools.compare_cves import _fetch_kev

        with patch("manus_use.tools.compare_cves.requests.get") as mock_get:
            mock_get.return_value = _kev_response(MOCK_KEV_CATALOG)
            result = _fetch_kev("CVE-2024-3094")

        assert result["in_kev"] is False
        assert "date_added" not in result

    def test_returns_in_kev_false_on_request_exception(self):
        import requests

        from manus_use.tools.compare_cves import _fetch_kev

        with patch("manus_use.tools.compare_cves.requests.get", side_effect=requests.RequestException("net")):
            result = _fetch_kev("CVE-2021-44228")

        assert result["in_kev"] is False
        assert "error" in result

    def test_case_insensitive_matching(self):
        from manus_use.tools.compare_cves import _fetch_kev

        with patch("manus_use.tools.compare_cves.requests.get") as mock_get:
            mock_get.return_value = _kev_response(MOCK_KEV_CATALOG)
            result = _fetch_kev("cve-2021-44228")  # lower-case input

        assert result["in_kev"] is True


class TestExtractCvss:
    def test_prefers_v31_over_v2(self):
        from manus_use.tools.compare_cves import _extract_cvss

        result = _extract_cvss(MOCK_NVD_LOG4SHELL)
        assert result["version"] == "3.1"
        assert result["score"] == 10.0
        assert result["severity"] == "CRITICAL"
        assert result["attack_vector"] == "NETWORK"

    def test_falls_back_to_v2_when_no_v3(self):
        from manus_use.tools.compare_cves import _extract_cvss

        nvd = {
            "metrics": {
                "cvssMetricV2": [
                    {
                        "baseSeverity": "HIGH",
                        "cvssData": {
                            "baseScore": 9.3,
                            "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                            "accessVector": "NETWORK",
                        },
                    }
                ]
            }
        }
        result = _extract_cvss(nvd)
        assert result["version"] == "2.0"
        assert result["score"] == 9.3

    def test_returns_none_score_when_no_metrics(self):
        from manus_use.tools.compare_cves import _extract_cvss

        result = _extract_cvss({})
        assert result["score"] is None
        assert result["severity"] is None


class TestExtractCwe:
    def test_returns_cwe_ids(self):
        from manus_use.tools.compare_cves import _extract_cwe

        result = _extract_cwe(MOCK_NVD_LOG4SHELL)
        assert "CWE-917" in result

    def test_filters_out_placeholder_cwes(self):
        from manus_use.tools.compare_cves import _extract_cwe

        nvd = {
            "weaknesses": [
                {"description": [{"lang": "en", "value": "NVD-CWE-Other"}]},
                {"description": [{"lang": "en", "value": "NVD-CWE-noinfo"}]},
                {"description": [{"lang": "en", "value": "CWE-79"}]},
            ]
        }
        result = _extract_cwe(nvd)
        assert result == ["CWE-79"]

    def test_returns_empty_list_when_no_weaknesses(self):
        from manus_use.tools.compare_cves import _extract_cwe

        assert _extract_cwe({}) == []


class TestExtractAffected:
    def test_returns_vendor_product(self):
        from manus_use.tools.compare_cves import _extract_affected

        result = _extract_affected(MOCK_NVD_LOG4SHELL)
        assert "Apache" in result
        # title-case may render as "Log4J" — check case-insensitively
        assert "log4j" in result.lower()

    def test_returns_unknown_when_no_config(self):
        from manus_use.tools.compare_cves import _extract_affected

        assert _extract_affected({}) == "Unknown"


class TestExtractPublished:
    def test_returns_date_portion(self):
        from manus_use.tools.compare_cves import _extract_published

        result = _extract_published(MOCK_NVD_LOG4SHELL)
        assert result == "2021-12-10"

    def test_returns_unknown_when_missing(self):
        from manus_use.tools.compare_cves import _extract_published

        assert _extract_published({}) == "Unknown"


class TestExtractDescription:
    def test_returns_english_description(self):
        from manus_use.tools.compare_cves import _extract_description

        result = _extract_description(MOCK_NVD_LOG4SHELL)
        assert "Log4j2" in result

    def test_truncates_long_descriptions(self):
        from manus_use.tools.compare_cves import _extract_description

        nvd = {"descriptions": [{"lang": "en", "value": "x" * 300}]}
        result = _extract_description(nvd)
        assert len(result) <= 201  # 200 chars + ellipsis
        assert result.endswith("…")

    def test_returns_empty_string_when_no_description(self):
        from manus_use.tools.compare_cves import _extract_description

        assert _extract_description({}) == ""


# ──────────────────────────────────────────────────────────────────────────────
# Unit tests for scoring logic
# ──────────────────────────────────────────────────────────────────────────────


class TestScoreCve:
    def _make_profile(
        self,
        in_kev=False,
        cvss_score=None,
        epss=None,
        attack_vector=None,
        privileges_required=None,
        user_interaction=None,
    ):
        return {
            "kev": {"in_kev": in_kev},
            "cvss": {
                "score": cvss_score,
                "attack_vector": attack_vector,
                "privileges_required": privileges_required,
                "user_interaction": user_interaction,
            },
            "epss": {"epss": epss},
        }

    def test_kev_adds_ten_points(self):
        from manus_use.tools.compare_cves import _score_cve

        score, reasons = _score_cve(self._make_profile(in_kev=True))
        assert score >= 10
        assert any("KEV" in r for r in reasons)

    def test_critical_cvss_adds_eight_points(self):
        from manus_use.tools.compare_cves import _score_cve

        score, reasons = _score_cve(self._make_profile(cvss_score=9.8))
        assert score >= 8
        assert any("Critical" in r for r in reasons)

    def test_high_cvss_adds_five_points(self):
        from manus_use.tools.compare_cves import _score_cve

        score, _ = _score_cve(self._make_profile(cvss_score=7.5))
        assert score == 5

    def test_medium_cvss_adds_two_points(self):
        from manus_use.tools.compare_cves import _score_cve

        score, _ = _score_cve(self._make_profile(cvss_score=5.0))
        assert score == 2

    def test_high_epss_adds_eight_points(self):
        from manus_use.tools.compare_cves import _score_cve

        score, reasons = _score_cve(self._make_profile(epss=0.85))
        assert score >= 8
        assert any("very high" in r for r in reasons)

    def test_medium_epss_adds_five_points(self):
        from manus_use.tools.compare_cves import _score_cve

        score, _ = _score_cve(self._make_profile(epss=0.55))
        assert score == 5

    def test_low_elevated_epss_adds_two_points(self):
        from manus_use.tools.compare_cves import _score_cve

        score, _ = _score_cve(self._make_profile(epss=0.15))
        assert score == 2

    def test_network_av_adds_three_points(self):
        from manus_use.tools.compare_cves import _score_cve

        score, reasons = _score_cve(self._make_profile(attack_vector="NETWORK"))
        assert score == 3
        assert any("remotely exploitable" in r for r in reasons)

    def test_none_pr_adds_two_points(self):
        from manus_use.tools.compare_cves import _score_cve

        score, _ = _score_cve(self._make_profile(privileges_required="NONE"))
        assert score == 2

    def test_none_ui_adds_one_point(self):
        from manus_use.tools.compare_cves import _score_cve

        score, _ = _score_cve(self._make_profile(user_interaction="NONE"))
        assert score == 1

    def test_full_score_log4shell_profile(self):
        """Log4Shell: KEV + CVSS 10 + high EPSS + NETWORK + no priv + no UI"""
        from manus_use.tools.compare_cves import _score_cve

        profile = self._make_profile(
            in_kev=True,
            cvss_score=10.0,
            epss=0.97,
            attack_vector="NETWORK",
            privileges_required="NONE",
            user_interaction="NONE",
        )
        score, _ = _score_cve(profile)
        # 10 + 8 + 8 + 3 + 2 + 1 = 32
        assert score == 32


# ──────────────────────────────────────────────────────────────────────────────
# Unit tests for _build_comparison
# ──────────────────────────────────────────────────────────────────────────────


class TestBuildComparison:
    def _profile(self, cve_id, score_val):
        """Build a minimal profile with a predictable score."""
        return {
            "cve_id": cve_id,
            "nvd_error": None,
            "epss_error": None,
            "cvss": {
                "score": score_val,
                "severity": "CRITICAL" if score_val >= 9 else "HIGH",
                "attack_vector": "NETWORK",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "version": "3.1",
            },
            "epss": {},
            "cwe": [],
            "affected": "Vendor / Product",
            "published": "2024-01-01",
            "description": "Test description",
        }

    def test_higher_cvss_wins(self):
        from manus_use.tools.compare_cves import _build_comparison

        pa = self._profile("CVE-2021-44228", 10.0)
        pb = self._profile("CVE-2024-3094", 7.5)
        result = _build_comparison(pa, {"in_kev": False}, pb, {"in_kev": False})
        assert result["higher_priority"] == "CVE-2021-44228"

    def test_kev_membership_can_flip_priority(self):
        from manus_use.tools.compare_cves import _build_comparison

        # pa: CVSS 9.0, no KEV; pb: CVSS 7.5 but in KEV
        pa = self._profile("CVE-A", 9.0)
        pb = self._profile("CVE-B", 7.5)
        kev_b = {"in_kev": True, "date_added": "2024-01-01", "due_date": "2024-01-15"}
        result = _build_comparison(pa, {"in_kev": False}, pb, kev_b)
        # CVE-B: 10 (KEV) + 5 (High) + 3 (NETWORK) + 2 (PR=NONE) + 1 (UI=NONE) = 21
        # CVE-A: 8 (Critical) + 3 + 2 + 1 = 14
        assert result["higher_priority"] == "CVE-B"

    def test_tie_produces_tie_result(self):
        from manus_use.tools.compare_cves import _build_comparison

        pa = self._profile("CVE-A", 9.0)
        pb = self._profile("CVE-B", 9.0)
        result = _build_comparison(pa, {"in_kev": False}, pb, {"in_kev": False})
        assert result["higher_priority"] == "tie"
        assert result["confidence"] == "tie"

    def test_recommendation_mentions_winner(self):
        from manus_use.tools.compare_cves import _build_comparison

        pa = self._profile("CVE-2021-44228", 10.0)
        pb = self._profile("CVE-2024-3094", 6.0)
        result = _build_comparison(pa, {"in_kev": False}, pb, {"in_kev": False})
        assert "CVE-2021-44228" in result["recommendation"]

    def test_strong_confidence_when_margin_ge_10(self):
        from manus_use.tools.compare_cves import _build_comparison

        pa = self._profile("CVE-A", 10.0)
        pa_kev = {"in_kev": True, "date_added": "2024-01-01", "due_date": "2024-01-15"}
        pb = self._profile("CVE-B", 4.0)
        result = _build_comparison(pa, pa_kev, pb, {"in_kev": False})
        assert result["confidence"] == "strong"

    def test_priority_scores_included_in_result(self):
        from manus_use.tools.compare_cves import _build_comparison

        pa = self._profile("CVE-A", 9.0)
        pb = self._profile("CVE-B", 7.5)
        result = _build_comparison(pa, {"in_kev": False}, pb, {"in_kev": False})
        assert "priority_score_a" in result
        assert "priority_score_b" in result
        assert result["priority_score_a"] > result["priority_score_b"]


# ──────────────────────────────────────────────────────────────────────────────
# Unit tests for _render_text
# ──────────────────────────────────────────────────────────────────────────────


class TestRenderText:
    def _make_comparison(self):
        from manus_use.tools.compare_cves import _build_comparison

        profile_a = {
            "cve_id": "CVE-2021-44228",
            "nvd_error": None,
            "epss_error": None,
            "cvss": {
                "score": 10.0,
                "severity": "CRITICAL",
                "attack_vector": "NETWORK",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "version": "3.1",
            },
            "epss": {"epss": "0.97535", "percentile": "0.99999"},
            "cwe": ["CWE-917"],
            "affected": "Apache / Log4j2",
            "published": "2021-12-10",
            "description": "Apache Log4j2 RCE",
        }
        profile_b = {
            "cve_id": "CVE-2024-3094",
            "nvd_error": None,
            "epss_error": None,
            "cvss": {
                "score": 10.0,
                "severity": "CRITICAL",
                "attack_vector": "NETWORK",
                "privileges_required": "NONE",
                "user_interaction": "NONE",
                "version": "3.1",
            },
            "epss": {"epss": "0.04234", "percentile": "0.87543"},
            "cwe": ["CWE-506"],
            "affected": "Tukaani / Xz Utils",
            "published": "2024-03-29",
            "description": "XZ Utils backdoor",
        }
        kev_a = {"in_kev": True, "date_added": "2021-12-10", "due_date": "2021-12-24"}
        return _build_comparison(profile_a, kev_a, profile_b, {"in_kev": False})

    def test_contains_both_cve_ids(self):
        from manus_use.tools.compare_cves import _render_text

        comp = self._make_comparison()
        text = _render_text(comp)
        assert "CVE-2021-44228" in text
        assert "CVE-2024-3094" in text

    def test_contains_cvss_row(self):
        from manus_use.tools.compare_cves import _render_text

        text = _render_text(self._make_comparison())
        assert "CVSS" in text

    def test_contains_epss_row(self):
        from manus_use.tools.compare_cves import _render_text

        text = _render_text(self._make_comparison())
        assert "EPSS" in text

    def test_contains_kev_row(self):
        from manus_use.tools.compare_cves import _render_text

        text = _render_text(self._make_comparison())
        assert "KEV" in text

    def test_contains_recommendation(self):
        from manus_use.tools.compare_cves import _render_text

        text = _render_text(self._make_comparison())
        assert "RECOMMENDATION" in text

    def test_kev_yes_shown_for_kev_member(self):
        from manus_use.tools.compare_cves import _render_text

        text = _render_text(self._make_comparison())
        assert "YES" in text


# ──────────────────────────────────────────────────────────────────────────────
# Integration-style tests for the Strands tool entry point
# ──────────────────────────────────────────────────────────────────────────────


class TestCompareCvesToolEntryPoint:
    def _make_tool_use(self, cve_id_a: str, cve_id_b: str) -> dict:
        return {"toolUseId": "test-123", "input": {"cve_id_a": cve_id_a, "cve_id_b": cve_id_b}}

    def _setup_mocks(self, mock_get):
        """Configure mock_get to return appropriate responses depending on URL."""

        def side_effect(url, **kwargs):
            params = kwargs.get("params", {})
            cve = params.get("cve", "").upper() if params else ""

            if "nvd.nist.gov" in url:
                cve_in_url = url.split("cveId=")[-1].upper() if "cveId=" in url else ""
                if "CVE-2021-44228" in cve_in_url:
                    return _nvd_response(MOCK_NVD_LOG4SHELL)
                return _nvd_response(MOCK_NVD_XZ)
            elif "api.first.org" in url:
                if "CVE-2021-44228" in cve.upper():
                    return _epss_response(MOCK_EPSS_LOG4SHELL)
                return _epss_response(MOCK_EPSS_XZ)
            elif "cisa.gov" in url:
                return _kev_response(MOCK_KEV_CATALOG)
            m = MagicMock()
            m.raise_for_status = MagicMock()
            m.json.return_value = {}
            return m

        mock_get.side_effect = side_effect

    def test_returns_success_status(self):
        from manus_use.tools.compare_cves import compare_cves

        with patch("manus_use.tools.compare_cves.requests.get") as mock_get:
            self._setup_mocks(mock_get)
            result = compare_cves(self._make_tool_use("CVE-2021-44228", "CVE-2024-3094"))

        assert result["status"] == "success"

    def test_returns_text_content(self):
        from manus_use.tools.compare_cves import compare_cves

        with patch("manus_use.tools.compare_cves.requests.get") as mock_get:
            self._setup_mocks(mock_get)
            result = compare_cves(self._make_tool_use("CVE-2021-44228", "CVE-2024-3094"))

        texts = [c["text"] for c in result["content"] if "text" in c]
        assert texts
        assert "CVE-2021-44228" in texts[0]

    def test_returns_json_content(self):
        from manus_use.tools.compare_cves import compare_cves

        with patch("manus_use.tools.compare_cves.requests.get") as mock_get:
            self._setup_mocks(mock_get)
            result = compare_cves(self._make_tool_use("CVE-2021-44228", "CVE-2024-3094"))

        jsons = [c["json"] for c in result["content"] if "json" in c]
        assert jsons
        comp = jsons[0]
        assert "cve_a" in comp
        assert "cve_b" in comp
        assert "recommendation" in comp

    def test_invalid_cve_id_returns_error(self):
        from manus_use.tools.compare_cves import compare_cves

        result = compare_cves(self._make_tool_use("not-a-cve", "CVE-2024-3094"))
        assert result["status"] == "error"

    def test_both_cve_ids_validated(self):
        from manus_use.tools.compare_cves import compare_cves

        result = compare_cves(self._make_tool_use("CVE-2021-44228", "bad-id"))
        assert result["status"] == "error"

    def test_higher_priority_field_present(self):
        from manus_use.tools.compare_cves import compare_cves

        with patch("manus_use.tools.compare_cves.requests.get") as mock_get:
            self._setup_mocks(mock_get)
            result = compare_cves(self._make_tool_use("CVE-2021-44228", "CVE-2024-3094"))

        jsons = [c["json"] for c in result["content"] if "json" in c]
        assert jsons[0]["higher_priority"] in ("CVE-2021-44228", "CVE-2024-3094", "tie")


# ──────────────────────────────────────────────────────────────────────────────
# CLI subcommand tests
# ──────────────────────────────────────────────────────────────────────────────


class TestCompareCLIParser:
    def test_parser_accepts_two_cve_ids(self):
        from manus_use.cli import _build_compare_parser

        parser = _build_compare_parser()
        args = parser.parse_args(["CVE-2021-44228", "CVE-2024-3094"])
        assert args.cve_id_a == "CVE-2021-44228"
        assert args.cve_id_b == "CVE-2024-3094"

    def test_parser_defaults_output_to_text(self):
        from manus_use.cli import _build_compare_parser

        parser = _build_compare_parser()
        args = parser.parse_args(["CVE-2021-44228", "CVE-2024-3094"])
        assert args.output == "text"

    def test_parser_accepts_json_output_flag(self):
        from manus_use.cli import _build_compare_parser

        parser = _build_compare_parser()
        args = parser.parse_args(["CVE-2021-44228", "CVE-2024-3094", "--output", "json"])
        assert args.output == "json"

    def test_parser_rejects_invalid_output_format(self):
        from manus_use.cli import _build_compare_parser

        parser = _build_compare_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["CVE-A", "CVE-B", "--output", "xml"])

    def test_help_exits_zero(self, capsys):
        from manus_use.cli import _build_compare_parser

        parser = _build_compare_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--help"])
        assert exc.value.code == 0


class TestRunCompare:
    def _mock_imports(self, mock_get):
        """Patch requests to return deterministic mock data."""

        def side_effect(url, **kwargs):
            params = kwargs.get("params", {})
            cve = params.get("cve", "").upper() if params else ""

            if "nvd.nist.gov" in url:
                cve_in_url = url.split("cveId=")[-1].upper() if "cveId=" in url else ""
                if "CVE-2021-44228" in cve_in_url:
                    return _nvd_response(MOCK_NVD_LOG4SHELL)
                return _nvd_response(MOCK_NVD_XZ)
            elif "api.first.org" in url:
                if "CVE-2021-44228" in cve.upper():
                    return _epss_response(MOCK_EPSS_LOG4SHELL)
                return _epss_response(MOCK_EPSS_XZ)
            elif "cisa.gov" in url:
                return _kev_response(MOCK_KEV_CATALOG)
            m = MagicMock()
            m.raise_for_status = MagicMock()
            m.json.return_value = {}
            return m

        mock_get.side_effect = side_effect

    def test_text_output_exits_zero(self, capsys):
        from manus_use.cli import _run_compare

        with patch("manus_use.tools.compare_cves.requests.get") as mock_get:
            self._mock_imports(mock_get)
            code = _run_compare(["CVE-2021-44228", "CVE-2024-3094"])

        assert code == 0

    def test_text_output_contains_both_cves(self, capsys):
        from manus_use.cli import _run_compare

        with patch("manus_use.tools.compare_cves.requests.get") as mock_get:
            self._mock_imports(mock_get)
            _run_compare(["CVE-2021-44228", "CVE-2024-3094"])

        captured = capsys.readouterr()
        assert "CVE-2021-44228" in captured.out
        assert "CVE-2024-3094" in captured.out

    def test_json_output_is_valid_json(self, capsys):
        from manus_use.cli import _run_compare

        with patch("manus_use.tools.compare_cves.requests.get") as mock_get:
            self._mock_imports(mock_get)
            code = _run_compare(["CVE-2021-44228", "CVE-2024-3094", "--output", "json"])

        assert code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "recommendation" in data

    def test_json_output_contains_higher_priority_field(self, capsys):
        from manus_use.cli import _run_compare

        with patch("manus_use.tools.compare_cves.requests.get") as mock_get:
            self._mock_imports(mock_get)
            _run_compare(["CVE-2021-44228", "CVE-2024-3094", "--output", "json"])

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["higher_priority"] in ("CVE-2021-44228", "CVE-2024-3094", "tie")

    def test_invalid_cve_id_a_exits_one(self, capsys):
        from manus_use.cli import _run_compare

        code = _run_compare(["invalid", "CVE-2024-3094"])
        assert code == 1

    def test_invalid_cve_id_b_exits_one(self, capsys):
        from manus_use.cli import _run_compare

        code = _run_compare(["CVE-2024-3094", "not-a-cve"])
        assert code == 1

    def test_error_message_written_to_stderr(self, capsys):
        from manus_use.cli import _run_compare

        _run_compare(["bad-input", "CVE-2024-3094"])
        captured = capsys.readouterr()
        assert "error" in captured.err.lower() or "Invalid" in captured.err


class TestMainDispatchesCompare:
    def test_compare_in_subcommands_set(self):
        from manus_use.cli import _SUBCOMMANDS

        assert "compare" in _SUBCOMMANDS

    def test_main_routes_compare_subcommand(self):

        with patch("manus_use.cli._run_compare", return_value=0) as mock_run:
            with patch("sys.argv", ["manus-agent", "compare", "CVE-2021-44228", "CVE-2024-3094"]):
                try:
                    from manus_use.cli import main

                    main()
                except SystemExit as e:
                    assert e.code == 0

            mock_run.assert_called_once_with(["CVE-2021-44228", "CVE-2024-3094"])

    def test_main_compare_passes_output_flag(self):

        with patch("manus_use.cli._run_compare", return_value=0) as mock_run:
            with patch("sys.argv", ["manus-agent", "compare", "CVE-2021-44228", "CVE-2024-3094", "--output", "json"]):
                try:
                    from manus_use.cli import main

                    main()
                except SystemExit:
                    pass

            mock_run.assert_called_once_with(["CVE-2021-44228", "CVE-2024-3094", "--output", "json"])
