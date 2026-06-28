"""
Tests for src/manus_use/tools/scan_sbom.py

All external HTTP calls are mocked — no real network I/O.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from manus_use.tools.scan_sbom import (
    _build_osv_queries,
    _epss_to_severity,
    _extract_cve_ids,
    _extract_osv_ids,
    _fetch_cisa_kev,
    _fetch_epss_scores,
    _fetch_osv_batch,
    _name_to_osv_guesses,
    _parse_cyclonedx_json,
    _parse_cyclonedx_xml,
    _parse_sbom,
    _parse_spdx_json,
    _purl_to_osv_package,
    _render_text,
    _run_scan,
    scan_sbom,
)

# ===========================================================================
# Fixtures / helpers
# ===========================================================================

_CYCLONEDX_JSON_MINIMAL = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "components": [
        {
            "name": "requests",
            "version": "2.28.0",
            "purl": "pkg:pypi/requests@2.28.0",
        },
        {
            "name": "lodash",
            "version": "4.17.20",
            "purl": "pkg:npm/lodash@4.17.20",
        },
        {
            "name": "no-purl-package",
            "version": "1.0.0",
        },
    ],
}

_SPDX_JSON_MINIMAL = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "packages": [
        {
            "name": "django",
            "versionInfo": "3.2.0",
            "externalRefs": [
                {
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/django@3.2.0",
                }
            ],
        },
        {
            "name": "express",
            "versionInfo": "4.18.0",
            "externalRefs": [],
        },
    ],
}

_CDX_XML_MINIMAL = """<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">
  <components>
    <component type="library">
      <name>flask</name>
      <version>2.0.0</version>
      <purl>pkg:pypi/flask@2.0.0</purl>
    </component>
    <component type="library">
      <name>spring-core</name>
      <version>5.3.0</version>
      <purl>pkg:maven/org.springframework/spring-core@5.3.0</purl>
    </component>
  </components>
</bom>
"""

_OSV_VULN_RESULT = {
    "vulns": [
        {
            "id": "GHSA-1234-abcd-wxyz",
            "aliases": ["CVE-2022-12345"],
        },
        {
            "id": "PYSEC-2022-99",
            "aliases": [],
        },
    ]
}

_OSV_EMPTY_RESULT: dict[str, Any] = {}

_EPSS_RESPONSE = {
    "data": [
        {"cve": "CVE-2022-12345", "epss": "0.7523", "percentile": "0.9812"},
    ]
}

_KEV_RESPONSE = {
    "vulnerabilities": [
        {"cveID": "CVE-2022-12345", "vendorProject": "TestVendor"},
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache"},
    ]
}


# ===========================================================================
# _parse_cyclonedx_json
# ===========================================================================


class TestParseCycloneDxJson:
    def test_extracts_components(self):
        comps = _parse_cyclonedx_json(_CYCLONEDX_JSON_MINIMAL)
        assert len(comps) == 3
        assert comps[0]["name"] == "requests"
        assert comps[0]["version"] == "2.28.0"
        assert comps[0]["purl"] == "pkg:pypi/requests@2.28.0"

    def test_missing_purl_is_empty_string(self):
        comps = _parse_cyclonedx_json(_CYCLONEDX_JSON_MINIMAL)
        no_purl = next(c for c in comps if c["name"] == "no-purl-package")
        assert no_purl["purl"] == ""

    def test_empty_components(self):
        assert _parse_cyclonedx_json({"bomFormat": "CycloneDX", "components": []}) == []

    def test_no_components_key(self):
        assert _parse_cyclonedx_json({"bomFormat": "CycloneDX"}) == []

    def test_component_without_name_skipped(self):
        data = {"components": [{"version": "1.0"}, {"name": "keep-me", "version": "2.0"}]}
        comps = _parse_cyclonedx_json(data)
        assert len(comps) == 1
        assert comps[0]["name"] == "keep-me"


# ===========================================================================
# _parse_cyclonedx_xml
# ===========================================================================


class TestParseCycloneDxXml:
    def test_extracts_components(self):
        comps = _parse_cyclonedx_xml(_CDX_XML_MINIMAL)
        assert len(comps) == 2
        names = {c["name"] for c in comps}
        assert names == {"flask", "spring-core"}

    def test_flask_version_and_purl(self):
        comps = _parse_cyclonedx_xml(_CDX_XML_MINIMAL)
        flask = next(c for c in comps if c["name"] == "flask")
        assert flask["version"] == "2.0.0"
        assert flask["purl"] == "pkg:pypi/flask@2.0.0"

    def test_no_namespace_xml(self):
        xml_no_ns = """<bom>
          <components>
            <component><name>mylib</name><version>0.1</version></component>
          </components>
        </bom>"""
        comps = _parse_cyclonedx_xml(xml_no_ns)
        assert len(comps) == 1
        assert comps[0]["name"] == "mylib"

    def test_missing_purl_in_xml(self):
        xml = """<bom xmlns="http://cyclonedx.org/schema/bom/1.4">
          <components>
            <component><name>nourl</name><version>1.0</version></component>
          </components>
        </bom>"""
        comps = _parse_cyclonedx_xml(xml)
        assert comps[0]["purl"] == ""


# ===========================================================================
# _parse_spdx_json
# ===========================================================================


class TestParseSpdxJson:
    def test_extracts_packages(self):
        comps = _parse_spdx_json(_SPDX_JSON_MINIMAL)
        assert len(comps) == 2
        assert comps[0]["name"] == "django"
        assert comps[0]["version"] == "3.2.0"
        assert comps[0]["purl"] == "pkg:pypi/django@3.2.0"

    def test_no_purl_ref_gives_empty_string(self):
        comps = _parse_spdx_json(_SPDX_JSON_MINIMAL)
        express = next(c for c in comps if c["name"] == "express")
        assert express["purl"] == ""

    def test_no_packages_key(self):
        assert _parse_spdx_json({}) == []


# ===========================================================================
# _parse_sbom (auto-detect)
# ===========================================================================


class TestParseSbom:
    def test_cyclonedx_json(self):
        comps = _parse_sbom(json.dumps(_CYCLONEDX_JSON_MINIMAL))
        assert len(comps) == 3

    def test_spdx_json(self):
        comps = _parse_sbom(json.dumps(_SPDX_JSON_MINIMAL))
        assert len(comps) == 2

    def test_cyclonedx_xml(self):
        comps = _parse_sbom(_CDX_XML_MINIMAL)
        assert len(comps) == 2

    def test_unknown_json_raises(self):
        with pytest.raises(ValueError, match="Unrecognised"):
            _parse_sbom('{"foo": "bar"}')

    def test_unknown_format_raises(self):
        with pytest.raises(ValueError, match="Unrecognised"):
            _parse_sbom("just some random text that is not JSON or XML")


# ===========================================================================
# _purl_to_osv_package
# ===========================================================================


class TestPurlToOsvPackage:
    def test_pypi_purl(self):
        pkg = _purl_to_osv_package("pkg:pypi/requests@2.28.0")
        assert pkg == {"name": "requests", "ecosystem": "PyPI"}

    def test_npm_scoped_purl(self):
        pkg = _purl_to_osv_package("pkg:npm/%40angular/core@14.0.0")
        assert pkg is not None
        assert pkg["ecosystem"] == "npm"

    def test_maven_purl(self):
        pkg = _purl_to_osv_package("pkg:maven/org.springframework/spring-core@5.3.0")
        assert pkg == {"name": "org.springframework:spring-core", "ecosystem": "Maven"}

    def test_golang_purl(self):
        pkg = _purl_to_osv_package("pkg:golang/github.com/gin-gonic/gin@1.8.1")
        assert pkg is not None
        assert pkg["ecosystem"] == "Go"

    def test_cargo_purl(self):
        pkg = _purl_to_osv_package("pkg:cargo/serde@1.0.0")
        assert pkg == {"name": "serde", "ecosystem": "crates.io"}

    def test_nuget_purl(self):
        pkg = _purl_to_osv_package("pkg:nuget/Newtonsoft.Json@13.0.1")
        assert pkg == {"name": "Newtonsoft.Json", "ecosystem": "NuGet"}

    def test_empty_purl_returns_none(self):
        assert _purl_to_osv_package("") is None

    def test_unknown_ecosystem_returns_none(self):
        assert _purl_to_osv_package("pkg:unknown/foo@1.0.0") is None

    def test_no_version_in_purl(self):
        pkg = _purl_to_osv_package("pkg:pypi/requests")
        assert pkg == {"name": "requests", "ecosystem": "PyPI"}

    def test_purl_with_qualifiers_stripped(self):
        pkg = _purl_to_osv_package("pkg:pypi/requests@2.28.0?checksum=sha256:abc")
        assert pkg == {"name": "requests", "ecosystem": "PyPI"}


# ===========================================================================
# _name_to_osv_guesses
# ===========================================================================


class TestNameToOsvGuesses:
    def test_returns_pypi_and_npm(self):
        guesses = _name_to_osv_guesses("mylib")
        ecosystems = {g["ecosystem"] for g in guesses}
        assert "PyPI" in ecosystems
        assert "npm" in ecosystems

    def test_name_preserved(self):
        guesses = _name_to_osv_guesses("mylib")
        assert all(g["name"] == "mylib" for g in guesses)


# ===========================================================================
# _build_osv_queries
# ===========================================================================


class TestBuildOsvQueries:
    def test_purl_component_produces_one_query(self):
        comps = [{"name": "requests", "version": "2.28.0", "purl": "pkg:pypi/requests@2.28.0"}]
        queries, indices = _build_osv_queries(comps)
        assert len(queries) == 1
        assert indices == [0]
        assert queries[0]["package"] == {"name": "requests", "ecosystem": "PyPI"}
        assert queries[0]["version"] == "2.28.0"

    def test_no_purl_produces_two_queries(self):
        comps = [{"name": "mylib", "version": "1.0", "purl": ""}]
        queries, indices = _build_osv_queries(comps)
        # PyPI + npm fallback
        assert len(queries) == 2
        assert indices == [0, 0]

    def test_no_version_omits_version_key(self):
        comps = [{"name": "requests", "version": "", "purl": "pkg:pypi/requests"}]
        queries, indices = _build_osv_queries(comps)
        assert "version" not in queries[0]

    def test_unsupported_purl_falls_back_to_guesses(self):
        comps = [{"name": "mylib", "version": "1.0", "purl": "pkg:unknown/mylib@1.0"}]
        queries, indices = _build_osv_queries(comps)
        assert len(queries) == 2  # PyPI + npm fallback


# ===========================================================================
# _extract_cve_ids / _extract_osv_ids
# ===========================================================================


class TestExtractIds:
    def test_extract_cve_from_vuln_id(self):
        result = {"vulns": [{"id": "CVE-2022-99999", "aliases": []}]}
        assert _extract_cve_ids(result) == ["CVE-2022-99999"]

    def test_extract_cve_from_alias(self):
        result = {"vulns": [{"id": "GHSA-xxxx", "aliases": ["CVE-2022-12345"]}]}
        assert _extract_cve_ids(result) == ["CVE-2022-12345"]

    def test_deduplicates_cves(self):
        result = {
            "vulns": [
                {"id": "CVE-2022-12345", "aliases": ["CVE-2022-12345"]},
            ]
        }
        cves = _extract_cve_ids(result)
        assert cves.count("CVE-2022-12345") == 1

    def test_empty_result(self):
        assert _extract_cve_ids({}) == []

    def test_extract_osv_ids(self):
        ids = _extract_osv_ids(_OSV_VULN_RESULT)
        assert "GHSA-1234-abcd-wxyz" in ids
        assert "PYSEC-2022-99" in ids

    def test_extract_osv_ids_empty(self):
        assert _extract_osv_ids({}) == []


# ===========================================================================
# _fetch_osv_batch
# ===========================================================================


def _mock_osv_response(results: list[dict]) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"results": results}
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


class TestFetchOsvBatch:
    def test_single_batch(self):
        queries = [{"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.28.0"}]
        with patch("manus_use.tools.scan_sbom.requests.post") as mock_post:
            mock_post.return_value = _mock_osv_response([_OSV_VULN_RESULT])
            results = _fetch_osv_batch(queries)
        assert len(results) == 1
        assert results[0] == _OSV_VULN_RESULT

    def test_empty_queries_returns_empty(self):
        results = _fetch_osv_batch([])
        assert results == []

    def test_pads_short_response(self):
        """If OSV returns fewer results than queries, we pad with empty dicts."""
        queries = [
            {"package": {"name": "a", "ecosystem": "PyPI"}},
            {"package": {"name": "b", "ecosystem": "PyPI"}},
        ]
        with patch("manus_use.tools.scan_sbom.requests.post") as mock_post:
            mock_post.return_value = _mock_osv_response([_OSV_VULN_RESULT])  # only 1 result
            results = _fetch_osv_batch(queries)
        assert len(results) == 2
        assert results[1] == {}

    def test_batches_large_query_list(self):
        """Queries > _OSV_BATCH_SIZE should trigger multiple POSTs."""
        from manus_use.tools.scan_sbom import _OSV_BATCH_SIZE

        n = _OSV_BATCH_SIZE + 5
        queries = [{"package": {"name": f"pkg{i}", "ecosystem": "PyPI"}} for i in range(n)]

        call_sizes: list[int] = []

        def _mock_post(url, **kwargs):
            chunk = kwargs.get("json", {}).get("queries", [])
            call_sizes.append(len(chunk))
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            resp.json.return_value = {"results": [{}] * len(chunk)}
            return resp

        with patch("manus_use.tools.scan_sbom.requests.post", side_effect=_mock_post):
            results = _fetch_osv_batch(queries)

        assert len(call_sizes) == 2
        assert sum(call_sizes) == n
        assert len(results) == n


# ===========================================================================
# _fetch_epss_scores
# ===========================================================================


class TestFetchEpssScores:
    def test_returns_score_mapping(self):
        with patch("manus_use.tools.scan_sbom.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = _EPSS_RESPONSE
            mock_get.return_value = mock_resp
            scores = _fetch_epss_scores(["CVE-2022-12345"])
        assert scores["CVE-2022-12345"] == pytest.approx(0.7523)

    def test_empty_input_returns_empty(self):
        scores = _fetch_epss_scores([])
        assert scores == {}

    def test_graceful_on_exception(self):
        with patch("manus_use.tools.scan_sbom.requests.get", side_effect=Exception("timeout")):
            scores = _fetch_epss_scores(["CVE-2022-12345"])
        assert scores == {}

    def test_invalid_epss_value_defaults_to_zero(self):
        bad_data = {"data": [{"cve": "CVE-2022-12345", "epss": "not-a-number"}]}
        with patch("manus_use.tools.scan_sbom.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = bad_data
            mock_get.return_value = mock_resp
            scores = _fetch_epss_scores(["CVE-2022-12345"])
        assert scores["CVE-2022-12345"] == 0.0


# ===========================================================================
# _fetch_cisa_kev
# ===========================================================================


class TestFetchCisaKev:
    def test_returns_cve_set(self):
        with patch("manus_use.tools.scan_sbom.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = _KEV_RESPONSE
            mock_get.return_value = mock_resp
            kev = _fetch_cisa_kev()
        assert "CVE-2022-12345" in kev
        assert "CVE-2021-44228" in kev

    def test_returns_empty_set_on_failure(self):
        with patch("manus_use.tools.scan_sbom.requests.get", side_effect=Exception("err")):
            kev = _fetch_cisa_kev()
        assert kev == set()


# ===========================================================================
# _epss_to_severity
# ===========================================================================


class TestEpssToSeverity:
    def test_kev_always_critical(self):
        assert _epss_to_severity(0.001, in_kev=True) == "CRITICAL"

    def test_high_epss_critical(self):
        assert _epss_to_severity(0.75, in_kev=False) == "CRITICAL"

    def test_medium_epss_high(self):
        assert _epss_to_severity(0.15, in_kev=False) == "HIGH"

    def test_low_epss_medium(self):
        assert _epss_to_severity(0.05, in_kev=False) == "MEDIUM"

    def test_very_low_epss_low(self):
        assert _epss_to_severity(0.002, in_kev=False) == "LOW"

    def test_zero_epss_info(self):
        assert _epss_to_severity(0.0, in_kev=False) == "INFO"


# ===========================================================================
# _render_text
# ===========================================================================


class TestRenderText:
    def _base_result(self, **kwargs) -> dict:
        base: dict = {
            "component_count": 5,
            "vulnerable_count": 2,
            "findings": [],
            "kev_hits": [],
            "summary": "Test summary.",
        }
        base.update(kwargs)
        return base

    def test_no_findings_shows_clean_message(self):
        output = _render_text(self._base_result())
        assert "No vulnerabilities found" in output

    def test_kev_hits_shown_prominently(self):
        result = self._base_result(
            kev_hits=["CVE-2022-12345"],
            findings=[
                {
                    "component": "requests@2.28.0",
                    "purl": "pkg:pypi/requests@2.28.0",
                    "cve_ids": ["CVE-2022-12345"],
                    "epss_max": 0.75,
                    "in_kev": True,
                    "severity_label": "CRITICAL",
                    "osv_ids": ["GHSA-xxxx"],
                }
            ],
        )
        output = _render_text(result)
        assert "ACTIVELY EXPLOITED" in output
        assert "CVE-2022-12345" in output
        assert "CRITICAL" in output

    def test_finding_without_cve_shows_ghsa_only(self):
        result = self._base_result(
            findings=[
                {
                    "component": "mylib@1.0",
                    "purl": "",
                    "cve_ids": [],
                    "epss_max": 0.0,
                    "in_kev": False,
                    "severity_label": "INFO",
                    "osv_ids": ["GHSA-abcd-1234"],
                }
            ]
        )
        output = _render_text(result)
        assert "GHSA/OSV only" in output


# ===========================================================================
# _run_scan (integration, fully mocked)
# ===========================================================================


class _PatchAllHttp:
    """Context manager that mocks all three external HTTP calls."""

    def __init__(
        self,
        osv_results: list[dict] | None = None,
        epss_data: list[dict] | None = None,
        kev_vulns: list[dict] | None = None,
    ):
        self._osv_results = osv_results or []
        self._epss_data = epss_data or []
        self._kev_vulns = kev_vulns or []
        self._patches: list = []

    def _make_post(self):
        osv_results = self._osv_results

        def mock_post(url, **kwargs):
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            n = len(kwargs.get("json", {}).get("queries", []))
            padded = osv_results + [{}] * max(0, n - len(osv_results))
            resp.json.return_value = {"results": padded[:n]}
            return resp

        return mock_post

    def _make_get(self):
        epss_data = self._epss_data
        kev_vulns = self._kev_vulns

        def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if "first.org" in url:
                resp.json.return_value = {"data": epss_data}
            elif "cisa.gov" in url:
                resp.json.return_value = {"vulnerabilities": kev_vulns}
            else:
                resp.json.return_value = {}
            return resp

        return mock_get

    def __enter__(self):
        import unittest.mock as um

        p1 = um.patch("manus_use.tools.scan_sbom.requests.post", side_effect=self._make_post())
        p2 = um.patch("manus_use.tools.scan_sbom.requests.get", side_effect=self._make_get())
        self._patches = [p1, p2]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *args):
        for p in self._patches:
            p.stop()


def _patch_all_http(
    osv_results: list[dict] | None = None,
    epss_data: list[dict] | None = None,
    kev_vulns: list[dict] | None = None,
) -> _PatchAllHttp:
    """Context manager that mocks all three external HTTP calls."""
    return _PatchAllHttp(osv_results=osv_results, epss_data=epss_data, kev_vulns=kev_vulns)


class TestRunScan:
    def test_no_vulns_returns_zero_findings(self):
        sbom = json.dumps(_CYCLONEDX_JSON_MINIMAL)
        with _patch_all_http(osv_results=[_OSV_EMPTY_RESULT] * 10):
            result = _run_scan(sbom)
        assert result["component_count"] == 3
        assert result["vulnerable_count"] == 0
        assert result["findings"] == []
        assert result["kev_hits"] == []

    def test_vuln_component_appears_in_findings(self):
        sbom = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [{"name": "requests", "version": "2.28.0", "purl": "pkg:pypi/requests@2.28.0"}],
            }
        )
        osv_hit = {"vulns": [{"id": "CVE-2022-12345", "aliases": []}]}
        epss_data = [{"cve": "CVE-2022-12345", "epss": "0.75"}]
        kev_vulns = [{"cveID": "CVE-2022-12345"}]

        with _patch_all_http(
            osv_results=[osv_hit],
            epss_data=epss_data,
            kev_vulns=kev_vulns,
        ):
            result = _run_scan(sbom)

        assert result["vulnerable_count"] == 1
        assert len(result["findings"]) == 1
        f = result["findings"][0]
        assert f["component"] == "requests@2.28.0"
        assert "CVE-2022-12345" in f["cve_ids"]
        assert f["epss_max"] == pytest.approx(0.75)
        assert f["in_kev"] is True
        assert f["severity_label"] == "CRITICAL"
        assert "CVE-2022-12345" in result["kev_hits"]

    def test_empty_sbom_returns_zero_count(self):
        sbom = json.dumps({"bomFormat": "CycloneDX", "components": []})
        with _patch_all_http():
            result = _run_scan(sbom)
        assert result["component_count"] == 0
        assert "No components" in result["summary"]

    def test_max_findings_respected(self):
        # Build SBOM with 5 components, all vulnerable
        comps = [{"name": f"lib{i}", "version": "1.0", "purl": f"pkg:pypi/lib{i}@1.0"} for i in range(5)]
        sbom = json.dumps({"bomFormat": "CycloneDX", "components": comps})
        osv_hit = {"vulns": [{"id": f"CVE-2022-1000{i}", "aliases": []} for i in range(5)]}
        osv_results = [osv_hit] * 5
        with _patch_all_http(osv_results=osv_results):
            result = _run_scan(sbom, max_findings=3)
        assert len(result["findings"]) <= 3

    def test_findings_sorted_kev_first(self):
        comps = [
            {"name": "safe", "version": "1.0", "purl": "pkg:pypi/safe@1.0"},
            {"name": "vuln", "version": "1.0", "purl": "pkg:pypi/vuln@1.0"},
        ]
        sbom = json.dumps({"bomFormat": "CycloneDX", "components": comps})
        osv_results = [
            {"vulns": [{"id": "CVE-2022-11111", "aliases": []}]},
            {"vulns": [{"id": "CVE-2021-44228", "aliases": []}]},
        ]
        epss_data = [
            {"cve": "CVE-2022-11111", "epss": "0.05"},
            {"cve": "CVE-2021-44228", "epss": "0.90"},
        ]
        kev_vulns = [{"cveID": "CVE-2021-44228"}]

        with _patch_all_http(
            osv_results=osv_results,
            epss_data=epss_data,
            kev_vulns=kev_vulns,
        ):
            result = _run_scan(sbom)

        assert len(result["findings"]) == 2
        # KEV hit should be first
        assert result["findings"][0]["in_kev"] is True

    def test_xml_sbom_parsed(self):
        with _patch_all_http(osv_results=[_OSV_EMPTY_RESULT] * 10):
            result = _run_scan(_CDX_XML_MINIMAL)
        assert result["component_count"] == 2

    def test_spdx_sbom_parsed(self):
        with _patch_all_http(osv_results=[_OSV_EMPTY_RESULT] * 10):
            result = _run_scan(json.dumps(_SPDX_JSON_MINIMAL))
        assert result["component_count"] == 2

    def test_summary_contains_component_count(self):
        sbom = json.dumps(_CYCLONEDX_JSON_MINIMAL)
        with _patch_all_http(osv_results=[_OSV_EMPTY_RESULT] * 10):
            result = _run_scan(sbom)
        assert "3" in result["summary"]

    def test_kev_summary_mention(self):
        sbom = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [{"name": "vuln", "version": "1.0", "purl": "pkg:pypi/vuln@1.0"}],
            }
        )
        osv_hit = {"vulns": [{"id": "CVE-2021-44228", "aliases": []}]}
        kev_vulns = [{"cveID": "CVE-2021-44228"}]
        epss_data = [{"cve": "CVE-2021-44228", "epss": "0.95"}]

        with _patch_all_http(
            osv_results=[osv_hit],
            epss_data=epss_data,
            kev_vulns=kev_vulns,
        ):
            result = _run_scan(sbom)

        assert "CISA KEV" in result["summary"]

    def test_osv_id_stored_without_cve(self):
        sbom = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [{"name": "mylib", "version": "1.0", "purl": "pkg:pypi/mylib@1.0"}],
            }
        )
        osv_result = {"vulns": [{"id": "PYSEC-2022-42", "aliases": []}]}
        with _patch_all_http(osv_results=[osv_result]):
            result = _run_scan(sbom)
        assert result["vulnerable_count"] == 1
        f = result["findings"][0]
        assert "PYSEC-2022-42" in f["osv_ids"]
        assert f["cve_ids"] == []


# ===========================================================================
# scan_sbom (Strands tool entry point)
# ===========================================================================


class TestScanSbomTool:
    def test_text_output(self):
        sbom = json.dumps({"bomFormat": "CycloneDX", "components": []})
        with _patch_all_http():
            output = scan_sbom(sbom)
        assert isinstance(output, str)
        assert "SBOM VULNERABILITY SCAN REPORT" in output

    def test_json_output(self):
        sbom = json.dumps({"bomFormat": "CycloneDX", "components": []})
        with _patch_all_http():
            output = scan_sbom(sbom, output="json")
        data = json.loads(output)
        assert "component_count" in data
        assert "findings" in data

    def test_default_output_is_text(self):
        sbom = json.dumps({"bomFormat": "CycloneDX", "components": []})
        with _patch_all_http():
            output = scan_sbom(sbom)
        assert "SBOM VULNERABILITY SCAN REPORT" in output
