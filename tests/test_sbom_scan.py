#!/usr/bin/env python3
"""
Comprehensive test suite for sbom_scan module.

100% mocked — no real HTTP calls.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure no real HTTP and fast retries
os.environ.setdefault("SBOM_SCAN_MAX_RETRIES", "1")
os.environ.setdefault("SBOM_SCAN_RETRY_BASE_DELAY", "0")

from manus_agent.tools.sbom_scan import (
    TOOL_SPEC,
    _build_osv_queries,
    _detect_sbom_format,
    _extract_cve_ids,
    _extract_cvss_score,
    _extract_cyclonedx_components,
    _extract_spdx_components,
    _fetch_epss_bulk,
    _fetch_kev_set,
    _fetch_vuln_detail,
    _guess_ecosystem_from_type,
    _parse_purl,
    _query_osv_batch,
    _request_with_retry,
    _severity_label,
    parse_sbom,
    sbom_scan,
    scan_sbom,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "components": [
        {
            "type": "library",
            "name": "requests",
            "version": "2.28.0",
            "purl": "pkg:pypi/requests@2.28.0",
        },
        {
            "type": "library",
            "name": "lodash",
            "version": "4.17.20",
            "purl": "pkg:npm/lodash@4.17.20",
        },
        {
            "type": "library",
            "name": "spring-core",
            "version": "5.3.20",
            "purl": "pkg:maven/org.springframework/spring-core@5.3.20",
        },
    ],
}

SAMPLE_SPDX = {
    "spdxVersion": "SPDX-2.3",
    "packages": [
        {
            "name": "flask",
            "versionInfo": "2.2.0",
            "externalRefs": [
                {
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/flask@2.2.0",
                }
            ],
        },
        {
            "name": "express",
            "versionInfo": "4.18.0",
        },
    ],
}

SAMPLE_OSV_VULN = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "aliases": ["CVE-2023-12345"],
    "summary": "Test vulnerability in requests",
    "severity": [{"score": "7.5"}],
    "database_specific": {},
    "references": [],
}

SAMPLE_OSV_VULN_CVE = {
    "id": "CVE-2023-99999",
    "aliases": [],
    "summary": "Direct CVE vuln",
    "severity": [],
    "database_specific": {"severity": "HIGH"},
    "references": [],
}


@pytest.fixture
def cyclonedx_file(tmp_path: Path) -> Path:
    p = tmp_path / "bom.json"
    p.write_text(json.dumps(SAMPLE_CYCLONEDX))
    return p


@pytest.fixture
def spdx_file(tmp_path: Path) -> Path:
    p = tmp_path / "sbom.spdx.json"
    p.write_text(json.dumps(SAMPLE_SPDX))
    return p


@pytest.fixture
def empty_cyclonedx_file(tmp_path: Path) -> Path:
    p = tmp_path / "empty.json"
    p.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
    return p


@pytest.fixture
def invalid_json_file(tmp_path: Path) -> Path:
    p = tmp_path / "bad.json"
    p.write_text("this is not json {{{")
    return p


@pytest.fixture
def unknown_format_file(tmp_path: Path) -> Path:
    p = tmp_path / "unknown.json"
    p.write_text(json.dumps({"random": "data"}))
    return p


# ---------------------------------------------------------------------------
# TOOL_SPEC tests
# ---------------------------------------------------------------------------


class TestToolSpec:
    def test_tool_spec_name(self):
        assert TOOL_SPEC["name"] == "sbom_scan"

    def test_tool_spec_has_description(self):
        assert "SBOM" in TOOL_SPEC["description"]
        assert "CycloneDX" in TOOL_SPEC["description"] or "SPDX" in TOOL_SPEC["description"]

    def test_tool_spec_input_schema(self):
        schema = TOOL_SPEC["inputSchema"]["json"]
        assert schema["type"] == "object"
        assert "bom_file" in schema["properties"]
        assert "bom_file" in schema["required"]

    def test_bom_file_property(self):
        prop = TOOL_SPEC["inputSchema"]["json"]["properties"]["bom_file"]
        assert prop["type"] == "string"
        assert "description" in prop


# ---------------------------------------------------------------------------
# SBOM format detection
# ---------------------------------------------------------------------------


class TestDetectSbomFormat:
    def test_cyclonedx_by_bom_format(self):
        assert _detect_sbom_format({"bomFormat": "CycloneDX"}) == "cyclonedx"

    def test_spdx_by_spdx_version(self):
        assert _detect_sbom_format({"spdxVersion": "SPDX-2.3"}) == "spdx"

    def test_cyclonedx_fallback_components(self):
        assert _detect_sbom_format({"components": []}) == "cyclonedx"

    def test_spdx_fallback_packages(self):
        assert _detect_sbom_format({"packages": []}) == "spdx"

    def test_unknown_format_raises(self):
        with pytest.raises(ValueError, match="Unrecognised SBOM format"):
            _detect_sbom_format({"random": "data"})


# ---------------------------------------------------------------------------
# Purl parsing
# ---------------------------------------------------------------------------


class TestParsePurl:
    def test_pypi_purl(self):
        result = _parse_purl("pkg:pypi/requests@2.28.0")
        assert result["ecosystem"] == "PyPI"
        assert result["name"] == "requests"
        assert result["version"] == "2.28.0"

    def test_npm_purl(self):
        result = _parse_purl("pkg:npm/lodash@4.17.20")
        assert result["ecosystem"] == "npm"
        assert result["name"] == "lodash"
        assert result["version"] == "4.17.20"

    def test_maven_purl_with_namespace(self):
        result = _parse_purl("pkg:maven/org.springframework/spring-core@5.3.20")
        assert result["ecosystem"] == "Maven"
        assert "spring-core" in result["name"]
        assert result["version"] == "5.3.20"

    def test_golang_purl(self):
        result = _parse_purl("pkg:golang/github.com/gin-gonic/gin@1.9.0")
        assert result["ecosystem"] == "Go"
        assert result["version"] == "1.9.0"

    def test_cargo_purl(self):
        result = _parse_purl("pkg:cargo/serde@1.0.0")
        assert result["ecosystem"] == "crates.io"
        assert result["name"] == "serde"

    def test_nuget_purl(self):
        result = _parse_purl("pkg:nuget/Newtonsoft.Json@13.0.1")
        assert result["ecosystem"] == "NuGet"

    def test_gem_purl(self):
        result = _parse_purl("pkg:gem/rails@7.0.0")
        assert result["ecosystem"] == "RubyGems"

    def test_composer_purl(self):
        result = _parse_purl("pkg:composer/laravel/framework@9.0.0")
        assert result["ecosystem"] == "Packagist"

    def test_purl_with_qualifiers(self):
        result = _parse_purl("pkg:pypi/requests@2.28.0?repository_url=https://pypi.org")
        assert result["version"] == "2.28.0"
        assert result["name"] == "requests"

    def test_purl_with_subpath(self):
        result = _parse_purl("pkg:npm/lodash@4.17.20#dist/lodash.min.js")
        assert result["version"] == "4.17.20"

    def test_purl_no_version(self):
        result = _parse_purl("pkg:pypi/requests")
        assert result["version"] == ""

    def test_empty_purl(self):
        result = _parse_purl("")
        assert result == {}

    def test_no_slash(self):
        result = _parse_purl("pkg:")
        assert result == {}

    def test_unknown_ecosystem(self):
        result = _parse_purl("pkg:custom/mypkg@1.0")
        assert result["ecosystem"] == "custom"

    def test_deb_purl(self):
        result = _parse_purl("pkg:deb/debian/curl@7.88.1")
        assert result["ecosystem"] == "Debian"

    def test_apk_purl(self):
        result = _parse_purl("pkg:apk/alpine/openssl@3.1.0")
        assert result["ecosystem"] == "Alpine"

    def test_github_purl(self):
        result = _parse_purl("pkg:github/actions/checkout@v3")
        assert result["ecosystem"] == "GitHub Actions"


# ---------------------------------------------------------------------------
# CycloneDX extraction
# ---------------------------------------------------------------------------


class TestExtractCyclonedxComponents:
    def test_basic_extraction(self):
        comps = _extract_cyclonedx_components(SAMPLE_CYCLONEDX)
        assert len(comps) == 3
        names = {c["name"] for c in comps}
        assert "requests" in names
        assert "lodash" in names

    def test_empty_components(self):
        assert _extract_cyclonedx_components({"components": []}) == []

    def test_no_components_key(self):
        assert _extract_cyclonedx_components({}) == []

    def test_component_without_purl_uses_fallback(self):
        data = {"components": [{"type": "library", "name": "mypkg", "version": "1.0.0"}]}
        comps = _extract_cyclonedx_components(data)
        assert len(comps) == 1
        assert comps[0]["name"] == "mypkg"
        assert comps[0]["version"] == "1.0.0"

    def test_component_without_name_or_version_skipped(self):
        data = {
            "components": [
                {"type": "library"},
                {"type": "library", "name": "noversion"},
            ]
        }
        comps = _extract_cyclonedx_components(data)
        assert len(comps) == 0

    def test_component_with_invalid_purl_falls_back(self):
        data = {
            "components": [
                {
                    "type": "library",
                    "name": "mypkg",
                    "version": "2.0",
                    "purl": "invalid-purl",
                }
            ]
        }
        comps = _extract_cyclonedx_components(data)
        assert len(comps) == 1
        assert comps[0]["name"] == "mypkg"


# ---------------------------------------------------------------------------
# SPDX extraction
# ---------------------------------------------------------------------------


class TestExtractSpdxComponents:
    def test_basic_extraction(self):
        comps = _extract_spdx_components(SAMPLE_SPDX)
        assert len(comps) == 2

    def test_purl_preferred(self):
        comps = _extract_spdx_components(SAMPLE_SPDX)
        flask_comp = [c for c in comps if c["name"] == "flask"][0]
        assert flask_comp["ecosystem"] == "PyPI"

    def test_fallback_without_purl(self):
        comps = _extract_spdx_components(SAMPLE_SPDX)
        express_comp = [c for c in comps if c["name"] == "express"][0]
        assert express_comp["ecosystem"] == ""
        assert express_comp["version"] == "4.18.0"

    def test_empty_packages(self):
        assert _extract_spdx_components({"packages": []}) == []

    def test_no_packages_key(self):
        assert _extract_spdx_components({}) == []

    def test_package_without_name_or_version_skipped(self):
        data = {"packages": [{"name": "nover"}, {"versionInfo": "1.0"}]}
        comps = _extract_spdx_components(data)
        assert len(comps) == 0


# ---------------------------------------------------------------------------
# parse_sbom
# ---------------------------------------------------------------------------


class TestParseSbom:
    def test_parse_cyclonedx(self, cyclonedx_file: Path):
        comps = parse_sbom(str(cyclonedx_file))
        assert len(comps) == 3

    def test_parse_spdx(self, spdx_file: Path):
        comps = parse_sbom(str(spdx_file))
        assert len(comps) == 2

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            parse_sbom("/nonexistent/path.json")

    def test_invalid_json(self, invalid_json_file: Path):
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_sbom(str(invalid_json_file))

    def test_unknown_format(self, unknown_format_file: Path):
        with pytest.raises(ValueError, match="Unrecognised SBOM format"):
            parse_sbom(str(unknown_format_file))

    def test_empty_sbom(self, empty_cyclonedx_file: Path):
        comps = parse_sbom(str(empty_cyclonedx_file))
        assert comps == []

    def test_deduplication(self, tmp_path: Path):
        data = {
            "bomFormat": "CycloneDX",
            "components": [
                {"purl": "pkg:pypi/requests@2.28.0"},
                {"purl": "pkg:pypi/requests@2.28.0"},
            ],
        }
        p = tmp_path / "dup.json"
        p.write_text(json.dumps(data))
        comps = parse_sbom(str(p))
        assert len(comps) == 1

    def test_max_components_cap(self, tmp_path: Path):
        data = {
            "bomFormat": "CycloneDX",
            "components": [{"purl": f"pkg:pypi/pkg{i}@1.0.0"} for i in range(6000)],
        }
        p = tmp_path / "large.json"
        p.write_text(json.dumps(data))
        comps = parse_sbom(str(p))
        assert len(comps) <= 5000


# ---------------------------------------------------------------------------
# OSV query building
# ---------------------------------------------------------------------------


class TestBuildOsvQueries:
    def test_basic_queries(self):
        comps = [
            {"ecosystem": "PyPI", "name": "requests", "version": "2.28.0"},
            {"ecosystem": "npm", "name": "lodash", "version": "4.17.20"},
        ]
        queries = _build_osv_queries(comps)
        assert len(queries) == 2
        assert queries[0]["package"]["ecosystem"] == "PyPI"
        assert queries[0]["version"] == "2.28.0"

    def test_no_ecosystem_still_queries(self):
        comps = [{"ecosystem": "", "name": "express", "version": "4.18.0"}]
        queries = _build_osv_queries(comps)
        assert len(queries) == 1
        assert "ecosystem" not in queries[0]["package"]

    def test_empty_components(self):
        assert _build_osv_queries([]) == []

    def test_component_without_name_skipped(self):
        comps = [{"ecosystem": "PyPI", "name": "", "version": "1.0"}]
        queries = _build_osv_queries(comps)
        assert len(queries) == 0


# ---------------------------------------------------------------------------
# OSV batch query
# ---------------------------------------------------------------------------


class TestQueryOsvBatch:
    @patch("manus_agent.tools.sbom_scan._request_with_retry")
    def test_successful_batch(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "results": [
                {"vulns": [SAMPLE_OSV_VULN]},
                {"vulns": []},
            ]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp

        queries = [{"package": {"name": "a"}, "version": "1"}, {"package": {"name": "b"}, "version": "2"}]
        results = _query_osv_batch(queries)
        assert len(results) == 2
        assert len(results[0]) == 1
        assert len(results[1]) == 0

    @patch("manus_agent.tools.sbom_scan._request_with_retry")
    def test_batch_failure_returns_empty(self, mock_req):
        mock_req.side_effect = Exception("network error")
        queries = [{"package": {"name": "a"}, "version": "1"}]
        results = _query_osv_batch(queries)
        assert len(results) == 1
        assert results[0] == []

    @patch("manus_agent.tools.sbom_scan._request_with_retry")
    def test_empty_queries(self, mock_req):
        results = _query_osv_batch([])
        assert results == []
        mock_req.assert_not_called()


# ---------------------------------------------------------------------------
# Vuln detail fetch
# ---------------------------------------------------------------------------


class TestFetchVulnDetail:
    @patch("manus_agent.tools.sbom_scan._request_with_retry")
    def test_success(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"id": "CVE-2023-12345", "summary": "test"}
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp
        result = _fetch_vuln_detail("CVE-2023-12345")
        assert result["id"] == "CVE-2023-12345"

    @patch("manus_agent.tools.sbom_scan._request_with_retry")
    def test_failure_returns_empty(self, mock_req):
        mock_req.side_effect = Exception("error")
        result = _fetch_vuln_detail("CVE-0000-0000")
        assert result == {}


# ---------------------------------------------------------------------------
# EPSS enrichment
# ---------------------------------------------------------------------------


class TestFetchEpssBulk:
    @patch("manus_agent.tools.sbom_scan._request_with_retry")
    def test_success(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": [
                {"cve": "CVE-2023-12345", "epss": "0.85"},
                {"cve": "CVE-2023-99999", "epss": "0.02"},
            ]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp
        scores = _fetch_epss_bulk(["CVE-2023-12345", "CVE-2023-99999"])
        assert scores["CVE-2023-12345"] == pytest.approx(0.85)
        assert scores["CVE-2023-99999"] == pytest.approx(0.02)

    @patch("manus_agent.tools.sbom_scan._request_with_retry")
    def test_failure_returns_empty(self, mock_req):
        mock_req.side_effect = Exception("error")
        scores = _fetch_epss_bulk(["CVE-2023-12345"])
        assert scores == {}

    def test_empty_list(self):
        scores = _fetch_epss_bulk([])
        assert scores == {}

    @patch("manus_agent.tools.sbom_scan._request_with_retry")
    def test_batching(self, mock_req):
        """Verify large CVE lists are batched."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": []}
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp
        cves = [f"CVE-2023-{i:05d}" for i in range(250)]
        _fetch_epss_bulk(cves)
        assert mock_req.call_count == 3  # 100 + 100 + 50


# ---------------------------------------------------------------------------
# KEV enrichment
# ---------------------------------------------------------------------------


class TestFetchKevSet:
    @patch("manus_agent.tools.sbom_scan._request_with_retry")
    def test_success(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {"cveID": "CVE-2023-12345"},
                {"cveID": "CVE-2021-44228"},
            ]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp
        kev = _fetch_kev_set()
        assert "CVE-2023-12345" in kev
        assert "CVE-2021-44228" in kev

    @patch("manus_agent.tools.sbom_scan._request_with_retry")
    def test_failure_returns_empty(self, mock_req):
        mock_req.side_effect = Exception("error")
        kev = _fetch_kev_set()
        assert kev == set()


# ---------------------------------------------------------------------------
# CVE ID extraction
# ---------------------------------------------------------------------------


class TestExtractCveIds:
    def test_cve_from_id(self):
        vulns = [{"id": "CVE-2023-12345", "aliases": []}]
        assert "CVE-2023-12345" in _extract_cve_ids(vulns)

    def test_cve_from_aliases(self):
        vulns = [{"id": "GHSA-xxxx", "aliases": ["CVE-2023-99999"]}]
        assert "CVE-2023-99999" in _extract_cve_ids(vulns)

    def test_deduplication(self):
        vulns = [
            {"id": "CVE-2023-12345", "aliases": ["CVE-2023-12345"]},
        ]
        cves = _extract_cve_ids(vulns)
        assert cves.count("CVE-2023-12345") == 1

    def test_empty_vulns(self):
        assert _extract_cve_ids([]) == []

    def test_non_cve_ids_excluded(self):
        vulns = [{"id": "GHSA-xxxx", "aliases": ["RUSTSEC-2023-001"]}]
        assert _extract_cve_ids(vulns) == []


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------


class TestSeverityLabel:
    def test_critical(self):
        assert _severity_label(9.5) == "critical"

    def test_high(self):
        assert _severity_label(7.5) == "high"

    def test_medium(self):
        assert _severity_label(5.0) == "medium"

    def test_low(self):
        assert _severity_label(2.0) == "low"

    def test_none(self):
        assert _severity_label(0.0) == "none"

    def test_none_value(self):
        assert _severity_label(None) == "unknown"

    def test_boundary_critical(self):
        assert _severity_label(9.0) == "critical"

    def test_boundary_high(self):
        assert _severity_label(7.0) == "high"

    def test_boundary_medium(self):
        assert _severity_label(4.0) == "medium"


class TestExtractCvssScore:
    def test_numeric_severity(self):
        vuln = {"severity": [{"score": "7.5"}], "database_specific": {}}
        assert _extract_cvss_score(vuln) == pytest.approx(7.5)

    def test_highest_score_selected(self):
        vuln = {
            "severity": [{"score": "5.0"}, {"score": "9.1"}],
            "database_specific": {},
        }
        assert _extract_cvss_score(vuln) == pytest.approx(9.1)

    def test_vector_string_skipped(self):
        vuln = {
            "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "database_specific": {},
        }
        assert _extract_cvss_score(vuln) is None

    def test_database_specific_cvss_score(self):
        vuln = {
            "severity": [],
            "database_specific": {"cvss_score": 8.5},
        }
        assert _extract_cvss_score(vuln) == pytest.approx(8.5)

    def test_database_specific_severity_string(self):
        vuln = {
            "severity": [],
            "database_specific": {"severity": "CRITICAL"},
        }
        assert _extract_cvss_score(vuln) == pytest.approx(9.5)

    def test_database_specific_moderate(self):
        vuln = {
            "severity": [],
            "database_specific": {"severity": "MODERATE"},
        }
        assert _extract_cvss_score(vuln) == pytest.approx(5.5)

    def test_database_specific_low(self):
        vuln = {
            "severity": [],
            "database_specific": {"severity": "LOW"},
        }
        assert _extract_cvss_score(vuln) == pytest.approx(2.5)

    def test_no_severity_data(self):
        vuln = {"severity": [], "database_specific": {}}
        assert _extract_cvss_score(vuln) is None

    def test_invalid_score_string(self):
        vuln = {"severity": [{"score": "invalid"}], "database_specific": {}}
        assert _extract_cvss_score(vuln) is None

    def test_database_specific_not_dict(self):
        vuln = {"severity": [], "database_specific": "not a dict"}
        assert _extract_cvss_score(vuln) is None

    def test_numeric_score_beats_ghsa_severity(self):
        vuln = {
            "severity": [{"score": "8.0"}],
            "database_specific": {"severity": "LOW"},
        }
        assert _extract_cvss_score(vuln) == pytest.approx(8.0)


# ---------------------------------------------------------------------------
# Guess ecosystem
# ---------------------------------------------------------------------------


class TestGuessEcosystemFromType:
    def test_returns_empty_string(self):
        assert _guess_ecosystem_from_type("library", "requests") == ""


# ---------------------------------------------------------------------------
# HTTP retry
# ---------------------------------------------------------------------------


class TestRequestWithRetry:
    @patch("manus_agent.tools.sbom_scan.requests.request")
    def test_success_on_first_try(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_request.return_value = mock_resp
        resp = _request_with_retry("GET", "http://example.com")
        assert resp.status_code == 200
        assert mock_request.call_count == 1

    @patch("manus_agent.tools.sbom_scan.requests.request")
    def test_raises_on_all_failures(self, mock_request):
        mock_request.side_effect = Exception("connection failed")
        with pytest.raises(Exception, match="connection failed"):
            _request_with_retry("GET", "http://example.com")

    @patch("manus_agent.tools.sbom_scan.requests.request")
    def test_non_retryable_status_returned(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_request.return_value = mock_resp
        resp = _request_with_retry("GET", "http://example.com")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# scan_sbom (integration-level, all HTTP mocked)
# ---------------------------------------------------------------------------


class TestScanSbom:
    @patch("manus_agent.tools.sbom_scan._fetch_kev_set")
    @patch("manus_agent.tools.sbom_scan._fetch_epss_bulk")
    @patch("manus_agent.tools.sbom_scan._query_osv_batch")
    def test_scan_with_vulns(self, mock_osv, mock_epss, mock_kev, cyclonedx_file):
        mock_osv.return_value = [
            [SAMPLE_OSV_VULN],  # requests
            [],  # lodash
            [SAMPLE_OSV_VULN_CVE],  # spring-core
        ]
        mock_epss.return_value = {
            "CVE-2023-12345": 0.85,
            "CVE-2023-99999": 0.02,
        }
        mock_kev.return_value = {"CVE-2023-12345"}

        result = scan_sbom(str(cyclonedx_file))
        assert result["components_scanned"] == 3
        assert result["vulnerabilities_found"] == 2
        assert len(result["findings"]) == 2

        # KEV findings should be first
        assert result["findings"][0]["in_kev"] is True
        assert result["findings"][0]["epss_score"] == pytest.approx(0.85)

    @patch("manus_agent.tools.sbom_scan._fetch_kev_set")
    @patch("manus_agent.tools.sbom_scan._fetch_epss_bulk")
    @patch("manus_agent.tools.sbom_scan._query_osv_batch")
    def test_scan_no_vulns(self, mock_osv, mock_epss, mock_kev, cyclonedx_file):
        mock_osv.return_value = [[], [], []]
        mock_epss.return_value = {}
        mock_kev.return_value = set()

        result = scan_sbom(str(cyclonedx_file))
        assert result["vulnerabilities_found"] == 0
        assert result["findings"] == []
        assert "No known vulnerabilities" in result["summary"]

    def test_scan_empty_sbom(self, empty_cyclonedx_file):
        result = scan_sbom(str(empty_cyclonedx_file))
        assert result["components_scanned"] == 0
        assert result["findings"] == []

    def test_scan_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            scan_sbom("/does/not/exist.json")

    def test_scan_invalid_json(self, invalid_json_file):
        with pytest.raises(ValueError):
            scan_sbom(str(invalid_json_file))

    @patch("manus_agent.tools.sbom_scan._fetch_kev_set")
    @patch("manus_agent.tools.sbom_scan._fetch_epss_bulk")
    @patch("manus_agent.tools.sbom_scan._query_osv_batch")
    def test_scan_spdx(self, mock_osv, mock_epss, mock_kev, spdx_file):
        mock_osv.return_value = [
            [SAMPLE_OSV_VULN],
            [],
        ]
        mock_epss.return_value = {"CVE-2023-12345": 0.5}
        mock_kev.return_value = set()

        result = scan_sbom(str(spdx_file))
        assert result["components_scanned"] == 2
        assert result["vulnerabilities_found"] == 1

    @patch("manus_agent.tools.sbom_scan._fetch_kev_set")
    @patch("manus_agent.tools.sbom_scan._fetch_epss_bulk")
    @patch("manus_agent.tools.sbom_scan._query_osv_batch")
    def test_ranking_kev_first_then_epss(self, mock_osv, mock_epss, mock_kev, cyclonedx_file):
        """KEV vulns ranked above non-KEV even with lower EPSS."""
        vuln_kev = {
            "id": "CVE-2023-00001",
            "aliases": [],
            "summary": "KEV vuln, low EPSS",
            "severity": [{"score": "5.0"}],
            "database_specific": {},
            "references": [],
        }
        vuln_high_epss = {
            "id": "CVE-2023-00002",
            "aliases": [],
            "summary": "Non-KEV, high EPSS",
            "severity": [{"score": "9.0"}],
            "database_specific": {},
            "references": [],
        }
        mock_osv.return_value = [
            [vuln_high_epss],  # requests
            [vuln_kev],  # lodash
            [],  # spring-core
        ]
        mock_epss.return_value = {
            "CVE-2023-00001": 0.10,
            "CVE-2023-00002": 0.95,
        }
        mock_kev.return_value = {"CVE-2023-00001"}

        result = scan_sbom(str(cyclonedx_file))
        findings = result["findings"]
        assert len(findings) == 2
        # KEV vuln should come first despite lower EPSS
        assert findings[0]["vuln_id"] == "CVE-2023-00001"
        assert findings[0]["in_kev"] is True
        assert findings[1]["vuln_id"] == "CVE-2023-00002"
        assert findings[1]["in_kev"] is False

    @patch("manus_agent.tools.sbom_scan._fetch_kev_set")
    @patch("manus_agent.tools.sbom_scan._fetch_epss_bulk")
    @patch("manus_agent.tools.sbom_scan._query_osv_batch")
    def test_severity_counts(self, mock_osv, mock_epss, mock_kev, cyclonedx_file):
        vuln_crit = {
            "id": "CVE-2023-00001",
            "aliases": [],
            "summary": "",
            "severity": [{"score": "9.5"}],
            "database_specific": {},
            "references": [],
        }
        vuln_high = {
            "id": "CVE-2023-00002",
            "aliases": [],
            "summary": "",
            "severity": [{"score": "7.5"}],
            "database_specific": {},
            "references": [],
        }
        vuln_med = {
            "id": "CVE-2023-00003",
            "aliases": [],
            "summary": "",
            "severity": [{"score": "5.0"}],
            "database_specific": {},
            "references": [],
        }
        mock_osv.return_value = [
            [vuln_crit],
            [vuln_high],
            [vuln_med],
        ]
        mock_epss.return_value = {}
        mock_kev.return_value = set()

        result = scan_sbom(str(cyclonedx_file))
        assert result["critical_count"] == 1
        assert result["high_count"] == 1
        assert result["medium_count"] == 1

    @patch("manus_agent.tools.sbom_scan._fetch_kev_set")
    @patch("manus_agent.tools.sbom_scan._fetch_epss_bulk")
    @patch("manus_agent.tools.sbom_scan._query_osv_batch")
    def test_vuln_deduplication(self, mock_osv, mock_epss, mock_kev, cyclonedx_file):
        """Same vuln affecting multiple components counted once."""
        mock_osv.return_value = [
            [SAMPLE_OSV_VULN],  # requests
            [SAMPLE_OSV_VULN],  # lodash (same vuln)
            [],  # spring
        ]
        mock_epss.return_value = {"CVE-2023-12345": 0.5}
        mock_kev.return_value = set()

        result = scan_sbom(str(cyclonedx_file))
        assert result["vulnerabilities_found"] == 1
        # But affected_components should list both
        finding = result["findings"][0]
        assert len(finding["affected_components"]) == 2

    @patch("manus_agent.tools.sbom_scan._fetch_kev_set")
    @patch("manus_agent.tools.sbom_scan._fetch_epss_bulk")
    @patch("manus_agent.tools.sbom_scan._query_osv_batch")
    def test_summary_includes_kev_count(self, mock_osv, mock_epss, mock_kev, cyclonedx_file):
        mock_osv.return_value = [
            [SAMPLE_OSV_VULN],
            [],
            [],
        ]
        mock_epss.return_value = {"CVE-2023-12345": 0.9}
        mock_kev.return_value = {"CVE-2023-12345"}

        result = scan_sbom(str(cyclonedx_file))
        assert "KEV" in result["summary"]
        assert "actively exploited" in result["summary"]

    @patch("manus_agent.tools.sbom_scan._fetch_kev_set")
    @patch("manus_agent.tools.sbom_scan._fetch_epss_bulk")
    @patch("manus_agent.tools.sbom_scan._query_osv_batch")
    def test_vuln_without_cve(self, mock_osv, mock_epss, mock_kev, cyclonedx_file):
        """GHSA-only vulns still appear in findings."""
        ghsa_only = {
            "id": "GHSA-abcd-efgh-ijkl",
            "aliases": [],
            "summary": "Advisory only",
            "severity": [{"score": "6.0"}],
            "database_specific": {},
            "references": [],
        }
        mock_osv.return_value = [[ghsa_only], [], []]
        mock_epss.return_value = {}
        mock_kev.return_value = set()

        result = scan_sbom(str(cyclonedx_file))
        assert result["vulnerabilities_found"] == 1
        f = result["findings"][0]
        assert f["cve_id"] is None
        assert f["in_kev"] is False


# ---------------------------------------------------------------------------
# Strands tool entry point
# ---------------------------------------------------------------------------


class TestSbomScanTool:
    @patch("manus_agent.tools.sbom_scan.scan_sbom")
    def test_success(self, mock_scan):
        mock_scan.return_value = {
            "components_scanned": 5,
            "vulnerabilities_found": 1,
            "findings": [],
            "summary": "test",
        }
        tool_use = {
            "toolUseId": "test-id-1",
            "name": "sbom_scan",
            "input": {"bom_file": "/path/to/bom.json"},
        }
        result = sbom_scan(tool_use)
        assert result["status"] == "success"
        assert result["toolUseId"] == "test-id-1"

    def test_empty_bom_file(self):
        tool_use = {
            "toolUseId": "test-id-2",
            "name": "sbom_scan",
            "input": {"bom_file": ""},
        }
        result = sbom_scan(tool_use)
        assert result["status"] == "error"
        assert "required" in result["content"][0]["text"].lower()

    def test_missing_bom_file(self):
        tool_use = {
            "toolUseId": "test-id-3",
            "name": "sbom_scan",
            "input": {},
        }
        result = sbom_scan(tool_use)
        assert result["status"] == "error"

    @patch("manus_agent.tools.sbom_scan.scan_sbom")
    def test_file_not_found(self, mock_scan):
        mock_scan.side_effect = FileNotFoundError("not found")
        tool_use = {
            "toolUseId": "test-id-4",
            "name": "sbom_scan",
            "input": {"bom_file": "/bad/path.json"},
        }
        result = sbom_scan(tool_use)
        assert result["status"] == "error"
        assert "not found" in result["content"][0]["text"]

    @patch("manus_agent.tools.sbom_scan.scan_sbom")
    def test_value_error(self, mock_scan):
        mock_scan.side_effect = ValueError("bad format")
        tool_use = {
            "toolUseId": "test-id-5",
            "name": "sbom_scan",
            "input": {"bom_file": "/path/to/bad.json"},
        }
        result = sbom_scan(tool_use)
        assert result["status"] == "error"
        assert "bad format" in result["content"][0]["text"]

    @patch("manus_agent.tools.sbom_scan.scan_sbom")
    def test_unexpected_error(self, mock_scan):
        mock_scan.side_effect = RuntimeError("unexpected")
        tool_use = {
            "toolUseId": "test-id-6",
            "name": "sbom_scan",
            "input": {"bom_file": "/path/to/bom.json"},
        }
        result = sbom_scan(tool_use)
        assert result["status"] == "error"
        assert "unexpected" in result["content"][0]["text"].lower()

    def test_non_string_bom_file(self):
        tool_use = {
            "toolUseId": "test-id-7",
            "name": "sbom_scan",
            "input": {"bom_file": 12345},
        }
        result = sbom_scan(tool_use)
        assert result["status"] == "error"


# ---------------------------------------------------------------------------
# CLI subcommand tests
# ---------------------------------------------------------------------------


class TestCliSbomScan:
    @patch("manus_agent.tools.sbom_scan.scan_sbom")
    def test_cli_text_output(self, mock_scan, capsys, cyclonedx_file):
        mock_scan.return_value = {
            "components_scanned": 3,
            "vulnerabilities_found": 1,
            "critical_count": 0,
            "high_count": 1,
            "medium_count": 0,
            "low_count": 0,
            "unknown_count": 0,
            "summary": "Scanned 3 components.\nFound 1 known vulnerabilities.\n  High: 1",
            "findings": [
                {
                    "vuln_id": "CVE-2023-12345",
                    "cve_id": "CVE-2023-12345",
                    "aliases": [],
                    "summary": "Test vuln",
                    "cvss_score": 7.5,
                    "severity": "high",
                    "epss_score": 0.85,
                    "in_kev": False,
                    "affected_components": ["PyPI:requests@2.28.0"],
                }
            ],
        }
        from manus_agent.cli import _run_sbom_scan

        ret = _run_sbom_scan([str(cyclonedx_file)])
        assert ret == 0
        out = capsys.readouterr().out
        assert "SBOM Vulnerability Scan" in out
        assert "CVE-2023-12345" in out
        assert "HIGH" in out

    @patch("manus_agent.tools.sbom_scan.scan_sbom")
    def test_cli_json_output(self, mock_scan, capsys, cyclonedx_file):
        payload = {
            "components_scanned": 3,
            "vulnerabilities_found": 0,
            "findings": [],
            "summary": "No vulns",
        }
        mock_scan.return_value = payload
        from manus_agent.cli import _run_sbom_scan

        ret = _run_sbom_scan([str(cyclonedx_file), "--output", "json"])
        assert ret == 0
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["components_scanned"] == 3

    @patch("manus_agent.tools.sbom_scan.scan_sbom")
    def test_cli_file_not_found(self, mock_scan, capsys):
        mock_scan.side_effect = FileNotFoundError("nope")
        from manus_agent.cli import _run_sbom_scan

        ret = _run_sbom_scan(["/bad/path.json"])
        assert ret == 1
        err = capsys.readouterr().err
        assert "nope" in err

    @patch("manus_agent.tools.sbom_scan.scan_sbom")
    def test_cli_value_error(self, mock_scan, capsys):
        mock_scan.side_effect = ValueError("bad")
        from manus_agent.cli import _run_sbom_scan

        ret = _run_sbom_scan(["/bad.json"])
        assert ret == 1

    @patch("manus_agent.tools.sbom_scan.scan_sbom")
    def test_cli_unexpected_error(self, mock_scan, capsys):
        mock_scan.side_effect = RuntimeError("boom")
        from manus_agent.cli import _run_sbom_scan

        ret = _run_sbom_scan(["/bad.json"])
        assert ret == 1

    @patch("manus_agent.tools.sbom_scan.scan_sbom")
    def test_cli_kev_warning_shown(self, mock_scan, capsys, cyclonedx_file):
        mock_scan.return_value = {
            "components_scanned": 1,
            "vulnerabilities_found": 1,
            "critical_count": 1,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "unknown_count": 0,
            "summary": "Scanned 1 component.",
            "findings": [
                {
                    "vuln_id": "CVE-2021-44228",
                    "cve_id": "CVE-2021-44228",
                    "aliases": [],
                    "summary": "Log4Shell",
                    "cvss_score": 10.0,
                    "severity": "critical",
                    "epss_score": 0.975,
                    "in_kev": True,
                    "affected_components": ["Maven:log4j-core@2.14.1"],
                }
            ],
        }
        from manus_agent.cli import _run_sbom_scan

        ret = _run_sbom_scan([str(cyclonedx_file)])
        assert ret == 0
        out = capsys.readouterr().out
        assert "[KEV]" in out
        assert "CISA KEV" in out

    @patch("manus_agent.tools.sbom_scan.scan_sbom")
    def test_cli_no_findings_text(self, mock_scan, capsys, cyclonedx_file):
        mock_scan.return_value = {
            "components_scanned": 3,
            "vulnerabilities_found": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "unknown_count": 0,
            "summary": "Scanned 3 components. No known vulnerabilities found.",
            "findings": [],
        }
        from manus_agent.cli import _run_sbom_scan

        ret = _run_sbom_scan([str(cyclonedx_file)])
        assert ret == 0
        out = capsys.readouterr().out
        assert "No known vulnerabilities" in out

    @patch("manus_agent.tools.sbom_scan.scan_sbom")
    def test_cli_multiple_affected_components(self, mock_scan, capsys, cyclonedx_file):
        mock_scan.return_value = {
            "components_scanned": 3,
            "vulnerabilities_found": 1,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 1,
            "low_count": 0,
            "unknown_count": 0,
            "summary": "Scanned 3 components.",
            "findings": [
                {
                    "vuln_id": "CVE-2023-99999",
                    "cve_id": "CVE-2023-99999",
                    "aliases": [],
                    "summary": "Multi-component vuln",
                    "cvss_score": 5.0,
                    "severity": "medium",
                    "epss_score": 0.1,
                    "in_kev": False,
                    "affected_components": [
                        "PyPI:a@1.0",
                        "PyPI:b@1.0",
                        "PyPI:c@1.0",
                        "PyPI:d@1.0",
                        "PyPI:e@1.0",
                        "PyPI:f@1.0",
                    ],
                }
            ],
        }
        from manus_agent.cli import _run_sbom_scan

        ret = _run_sbom_scan([str(cyclonedx_file)])
        assert ret == 0
        out = capsys.readouterr().out
        assert "and 1 more" in out

    @patch("manus_agent.tools.sbom_scan.scan_sbom")
    def test_cli_finding_without_cve(self, mock_scan, capsys, cyclonedx_file):
        mock_scan.return_value = {
            "components_scanned": 1,
            "vulnerabilities_found": 1,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "unknown_count": 1,
            "summary": "Scanned 1 component.",
            "findings": [
                {
                    "vuln_id": "GHSA-abcd-efgh-ijkl",
                    "cve_id": None,
                    "aliases": [],
                    "summary": "GHSA only",
                    "cvss_score": None,
                    "severity": "unknown",
                    "epss_score": 0.0,
                    "in_kev": False,
                    "affected_components": ["PyPI:pkg@1.0"],
                }
            ],
        }
        from manus_agent.cli import _run_sbom_scan

        ret = _run_sbom_scan([str(cyclonedx_file)])
        assert ret == 0
        out = capsys.readouterr().out
        assert "GHSA-abcd-efgh-ijkl" in out
        assert "(no CVE)" in out

    @patch("manus_agent.tools.sbom_scan.scan_sbom")
    def test_cli_kev_plural(self, mock_scan, capsys, cyclonedx_file):
        """Test plural 'vulnerabilities' when kev_count > 1."""
        mock_scan.return_value = {
            "components_scanned": 2,
            "vulnerabilities_found": 2,
            "critical_count": 2,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "unknown_count": 0,
            "summary": "Scanned 2 components.",
            "findings": [
                {
                    "vuln_id": "CVE-2023-00001",
                    "cve_id": "CVE-2023-00001",
                    "aliases": [],
                    "summary": "First KEV",
                    "cvss_score": 9.5,
                    "severity": "critical",
                    "epss_score": 0.9,
                    "in_kev": True,
                    "affected_components": ["PyPI:a@1.0"],
                },
                {
                    "vuln_id": "CVE-2023-00002",
                    "cve_id": "CVE-2023-00002",
                    "aliases": [],
                    "summary": "Second KEV",
                    "cvss_score": 9.0,
                    "severity": "critical",
                    "epss_score": 0.8,
                    "in_kev": True,
                    "affected_components": ["PyPI:b@1.0"],
                },
            ],
        }
        from manus_agent.cli import _run_sbom_scan

        ret = _run_sbom_scan([str(cyclonedx_file)])
        assert ret == 0
        out = capsys.readouterr().out
        assert "vulnerabilities" in out
