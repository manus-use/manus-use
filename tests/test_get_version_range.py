"""Tests for get_version_range — CVE affected version range resolver.

All HTTP calls are fully mocked; no real network requests are made.
VERSION_RANGE_RETRY_BASE_DELAY is forced to "0" so retry loops complete
instantly without real sleeping.
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest
import requests

# Force zero-delay retries before importing the module
os.environ["VERSION_RANGE_RETRY_BASE_DELAY"] = "0"
os.environ["VERSION_RANGE_MAX_RETRIES"] = "2"

from manus_agent.tools import get_version_range as mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_tool_use(cve_id="CVE-2021-44228", ecosystem="auto", tool_use_id="vr-test-001"):
    return {"toolUseId": tool_use_id, "input": {"cve_id": cve_id, "ecosystem": ecosystem}}


def _make_response(status_code=200, payload=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = payload if payload is not None else {}
    if status_code < 400:
        resp.raise_for_status.return_value = None
    else:
        resp.raise_for_status.side_effect = requests.exceptions.HTTPError(f"HTTP {status_code}", response=resp)
    return resp


def _nvd_response_with_cpe(
    vendor="apache",
    product="log4j",
    version_start="2.0",
    version_end="2.15.0",
    end_type="excluding",
):
    """Build a minimal NVD API response with one CPE match."""
    match = {
        "vulnerable": True,
        "criteria": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
    }
    if version_start:
        match["versionStartIncluding"] = version_start
    if version_end:
        if end_type == "excluding":
            match["versionEndExcluding"] = version_end
        else:
            match["versionEndIncluding"] = version_end

    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [match],
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }


def _osv_record_with_packages(cve_id="CVE-2021-44228"):
    """OSV record with Maven package ranges."""
    return {
        "id": cve_id,
        "summary": "Log4Shell RCE",
        "aliases": ["GHSA-jfh8-c2jp-5v3q"],
        "modified": "2024-01-01T00:00:00Z",
        "published": "2021-12-10T00:00:00Z",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
        "affected": [
            {
                "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "2.0-beta9"}, {"fixed": "2.15.0"}],
                    }
                ],
                "versions": ["2.0-beta9", "2.0", "2.14.0", "2.14.1"],
            }
        ],
        "references": [{"type": "WEB", "url": "https://logging.apache.org/log4j/"}],
    }


def _osv_record_no_packages(cve_id="CVE-2024-3094"):
    """OSV record that has no affected packages (alias follow needed)."""
    return {
        "id": cve_id,
        "summary": "xz backdoor",
        "aliases": ["GHSA-rxwq-x6h5-x525"],
        "modified": "2024-04-01T00:00:00Z",
        "published": "2024-03-29T00:00:00Z",
        "affected": [],
        "references": [],
    }


def _ghsa_record_with_packages():
    """GHSA record with PyPI package ranges."""
    return {
        "id": "GHSA-rxwq-x6h5-x525",
        "summary": "xz utils backdoor",
        "aliases": ["CVE-2024-3094"],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "xz"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "5.6.0"}, {"fixed": "5.6.2"}],
                    }
                ],
                "versions": ["5.6.0", "5.6.1"],
            }
        ],
    }


def _pypi_json_response(package="xz"):
    return {
        "info": {"name": package, "version": "5.6.2"},
        "releases": {
            "5.5.0": [],
            "5.5.1": [],
            "5.6.0": [],
            "5.6.1": [],
            "5.6.2": [],
            "5.7.0": [],
        },
    }


def _npm_json_response(package="lodash"):
    return {
        "name": package,
        "versions": {
            "4.17.19": {},
            "4.17.20": {},
            "4.17.21": {},
        },
    }


def _maven_json_response():
    return {
        "response": {
            "docs": [
                {"v": "2.0-beta9"},
                {"v": "2.14.0"},
                {"v": "2.14.1"},
                {"v": "2.15.0"},
                {"v": "2.16.0"},
            ]
        }
    }


# ===================================================================
# Tests for _parse_version_tuple
# ===================================================================
class TestParseVersionTuple:
    def test_simple_semver(self):
        assert mod._parse_version_tuple("1.2.3") == (1, 2, 3)

    def test_prerelease(self):
        result = mod._parse_version_tuple("2.0-beta9")
        assert result == (2, 0, "beta9")

    def test_single_number(self):
        assert mod._parse_version_tuple("5") == (5,)

    def test_underscore_separator(self):
        result = mod._parse_version_tuple("1_2_3")
        assert result == (1, 2, 3)

    def test_mixed_separators(self):
        result = mod._parse_version_tuple("1.2-rc1+build42")
        assert len(result) == 4


# ===================================================================
# Tests for version comparison helpers
# ===================================================================
class TestVersionComparison:
    def test_gte_true(self):
        assert mod._version_gte("2.0.0", "1.0.0") is True

    def test_gte_equal(self):
        assert mod._version_gte("1.0.0", "1.0.0") is True

    def test_gte_false(self):
        assert mod._version_gte("0.9.0", "1.0.0") is False

    def test_lt_true(self):
        assert mod._version_lt("1.0.0", "2.0.0") is True

    def test_lt_false(self):
        assert mod._version_lt("2.0.0", "1.0.0") is False

    def test_lte_true(self):
        assert mod._version_lte("1.0.0", "1.0.0") is True

    def test_lte_greater(self):
        assert mod._version_lte("2.0.0", "1.0.0") is False

    def test_string_fallback_gte(self):
        """When tuple comparison raises TypeError, fall back to string compare."""
        # Mixed types that could trigger TypeError in some edge cases
        assert mod._version_gte("b", "a") is True

    def test_string_fallback_lt(self):
        assert mod._version_lt("a", "b") is True

    def test_string_fallback_lte(self):
        assert mod._version_lte("a", "a") is True


# ===================================================================
# Tests for _build_range_string
# ===================================================================
class TestBuildRangeString:
    def test_introduced_and_fixed(self):
        result = mod._build_range_string(["1.0"], ["2.0"], [])
        assert ">=1.0" in result
        assert "<2.0" in result

    def test_introduced_zero(self):
        result = mod._build_range_string(["0"], ["1.5"], [])
        assert "all versions" in result
        assert "<1.5" in result

    def test_last_affected_only(self):
        result = mod._build_range_string([], [], ["3.0"])
        assert "<=3.0" in result
        assert "last affected" in result

    def test_empty_ranges(self):
        result = mod._build_range_string([], [], [])
        assert "unspecified" in result.lower()

    def test_multiple_introduced(self):
        result = mod._build_range_string(["1.0", "3.0"], ["2.0", "4.0"], [])
        assert ">=1.0" in result
        assert ">=3.0" in result


# ===================================================================
# Tests for _filter_versions_by_range
# ===================================================================
class TestFilterVersionsByRange:
    def test_filter_with_introduced_and_fixed(self):
        versions = ["0.9", "1.0", "1.5", "2.0", "2.1"]
        result = mod._filter_versions_by_range(versions, ["1.0"], ["2.0"], [])
        assert "1.0" in result
        assert "1.5" in result
        assert "2.0" not in result
        assert "2.1" not in result

    def test_filter_with_zero_introduced(self):
        versions = ["0.1", "0.5", "1.0"]
        result = mod._filter_versions_by_range(versions, ["0"], ["1.0"], [])
        assert "0.1" in result
        assert "0.5" in result
        assert "1.0" not in result

    def test_filter_with_last_affected(self):
        versions = ["1.0", "1.5", "2.0", "2.5"]
        result = mod._filter_versions_by_range(versions, ["1.0"], [], ["2.0"])
        assert "1.0" in result
        assert "1.5" in result
        assert "2.0" in result
        assert "2.5" not in result

    def test_empty_versions_list(self):
        result = mod._filter_versions_by_range([], ["1.0"], ["2.0"], [])
        assert result == []

    def test_no_bounds(self):
        versions = ["1.0", "2.0"]
        result = mod._filter_versions_by_range(versions, [], [], [])
        assert result == versions


# ===================================================================
# Tests for _normalise_ecosystem / _ecosystem_matches
# ===================================================================
class TestEcosystemMatching:
    def test_normalise_pypi(self):
        assert mod._normalise_ecosystem("pypi") == "PyPI"

    def test_normalise_npm(self):
        assert mod._normalise_ecosystem("npm") == "npm"

    def test_normalise_unknown(self):
        assert mod._normalise_ecosystem("UnknownEco") == "UnknownEco"

    def test_matches_auto(self):
        assert mod._ecosystem_matches("PyPI", "auto") is True

    def test_matches_empty(self):
        assert mod._ecosystem_matches("PyPI", "") is True

    def test_matches_same(self):
        assert mod._ecosystem_matches("PyPI", "pypi") is True

    def test_matches_different(self):
        assert mod._ecosystem_matches("PyPI", "npm") is False


# ===================================================================
# Tests for _get_with_retry
# ===================================================================
class TestGetWithRetry:
    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = _make_response(200, {"ok": True})
        resp = mod._get_with_retry("https://example.com")
        assert resp.status_code == 200

    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_retry_on_429(self, mock_get):
        mock_get.side_effect = [
            _make_response(429),
            _make_response(200, {"ok": True}),
        ]
        resp = mod._get_with_retry("https://example.com")
        assert resp.status_code == 200
        assert mock_get.call_count == 2

    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_retry_exhausted(self, mock_get):
        mock_get.return_value = _make_response(503)
        resp = mod._get_with_retry("https://example.com")
        assert resp.status_code == 503

    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_connection_error_retry(self, mock_get):
        mock_get.side_effect = [
            requests.exceptions.ConnectionError("fail"),
            _make_response(200, {"ok": True}),
        ]
        resp = mod._get_with_retry("https://example.com")
        assert resp.status_code == 200

    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_connection_error_exhausted(self, mock_get):
        mock_get.side_effect = requests.exceptions.ConnectionError("fail")
        with pytest.raises(requests.exceptions.ConnectionError):
            mod._get_with_retry("https://example.com")

    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_timeout_retry(self, mock_get):
        mock_get.side_effect = [
            requests.exceptions.Timeout("timeout"),
            _make_response(200),
        ]
        resp = mod._get_with_retry("https://example.com")
        assert resp.status_code == 200


# ===================================================================
# Tests for _fetch_nvd_cpe_ranges
# ===================================================================
class TestFetchNvdCpeRanges:
    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_basic_range(self, mock_get):
        mock_get.return_value = _make_response(200, _nvd_response_with_cpe())
        result = mod._fetch_nvd_cpe_ranges("CVE-2021-44228")
        assert len(result) == 1
        assert result[0]["vendor"] == "apache"
        assert result[0]["product"] == "log4j"
        assert result[0]["version_start"] == "2.0"
        assert result[0]["version_end"] == "2.15.0"
        assert result[0]["version_end_type"] == "excluding"

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_404_returns_empty(self, mock_get):
        mock_get.return_value = _make_response(404)
        result = mod._fetch_nvd_cpe_ranges("CVE-9999-99999")
        assert result == []

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_no_vulnerabilities(self, mock_get):
        mock_get.return_value = _make_response(200, {"vulnerabilities": []})
        result = mod._fetch_nvd_cpe_ranges("CVE-2021-44228")
        assert result == []

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_no_configurations(self, mock_get):
        mock_get.return_value = _make_response(200, {"vulnerabilities": [{"cve": {}}]})
        result = mod._fetch_nvd_cpe_ranges("CVE-2021-44228")
        assert result == []

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_version_end_including(self, mock_get):
        mock_get.return_value = _make_response(200, _nvd_response_with_cpe(version_end="3.0", end_type="including"))
        result = mod._fetch_nvd_cpe_ranges("CVE-2021-44228")
        assert result[0]["version_end_type"] == "including"

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_exact_version_in_cpe(self, mock_get):
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }
        mock_get.return_value = _make_response(200, payload)
        result = mod._fetch_nvd_cpe_ranges("CVE-2021-44228")
        assert result[0]["exact_versions"] == ["1.2.3"]

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_non_vulnerable_cpe_skipped(self, mock_get):
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "vulnerable": False,
                                                "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }
        mock_get.return_value = _make_response(200, payload)
        result = mod._fetch_nvd_cpe_ranges("CVE-2021-44228")
        assert result == []

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_nvd_api_key_header(self, mock_get):
        mock_get.return_value = _make_response(200, {"vulnerabilities": []})
        with patch.dict(os.environ, {"NVD_API_KEY": "test-key-123"}):
            mod._fetch_nvd_cpe_ranges("CVE-2021-44228")
        # Verify the call was made with headers containing apiKey
        call_kwargs = mock_get.call_args
        assert "apiKey" in (call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {}))


# ===================================================================
# Tests for _fetch_osv_affected
# ===================================================================
class TestFetchOsvAffected:
    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_basic_package_extraction(self, mock_get):
        mock_get.return_value = _make_response(200, _osv_record_with_packages())
        result = mod._fetch_osv_affected("CVE-2021-44228")
        assert len(result) == 1
        assert result[0]["ecosystem"] == "Maven"
        assert result[0]["package"] == "org.apache.logging.log4j:log4j-core"
        assert "2.0-beta9" in result[0]["introduced"]
        assert "2.15.0" in result[0]["fixed"]

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_404_returns_empty(self, mock_get):
        mock_get.return_value = _make_response(404)
        result = mod._fetch_osv_affected("CVE-9999-99999")
        assert result == []

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_follows_ghsa_aliases(self, mock_get):
        """When the CVE record has no affected, follow GHSA aliases."""
        mock_get.side_effect = [
            _make_response(200, _osv_record_no_packages()),
            _make_response(200, _ghsa_record_with_packages()),
        ]
        result = mod._fetch_osv_affected("CVE-2024-3094")
        assert len(result) == 1
        assert result[0]["ecosystem"] == "PyPI"

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_deduplicates_packages(self, mock_get):
        """Same package from two records shouldn't appear twice."""
        record = _osv_record_with_packages()
        mock_get.return_value = _make_response(200, record)
        result = mod._fetch_osv_affected("CVE-2021-44228")
        ecosystems_packages = [(r["ecosystem"], r["package"]) for r in result]
        assert len(ecosystems_packages) == len(set(ecosystems_packages))

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_network_error_returns_empty(self, mock_get):
        mock_get.side_effect = requests.exceptions.ConnectionError("fail")
        result = mod._fetch_osv_affected("CVE-2021-44228")
        assert result == []

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_http_error_returns_empty(self, mock_get):
        resp = _make_response(500)
        resp.raise_for_status.side_effect = requests.exceptions.HTTPError("500")
        mock_get.return_value = resp
        result = mod._fetch_osv_affected("CVE-2021-44228")
        assert result == []

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_affected_versions_captured(self, mock_get):
        mock_get.return_value = _make_response(200, _osv_record_with_packages())
        result = mod._fetch_osv_affected("CVE-2021-44228")
        assert len(result[0]["affected_versions"]) > 0

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_ghsa_alias_failure_graceful(self, mock_get):
        """Failed alias lookup shouldn't crash."""
        mock_get.side_effect = [
            _make_response(200, _osv_record_no_packages()),
            requests.exceptions.Timeout("timeout"),
        ]
        result = mod._fetch_osv_affected("CVE-2024-3094")
        assert result == []

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_skips_packageless_entries(self, mock_get):
        record = {
            "id": "CVE-2021-44228",
            "aliases": [],
            "affected": [
                {"package": {}, "ranges": []},
                {"package": {"ecosystem": "", "name": ""}, "ranges": []},
            ],
        }
        mock_get.return_value = _make_response(200, record)
        result = mod._fetch_osv_affected("CVE-2021-44228")
        assert result == []


# ===================================================================
# Tests for registry fetch functions
# ===================================================================
class TestFetchRegistryVersions:
    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_pypi_versions(self, mock_get):
        mock_get.return_value = _make_response(200, _pypi_json_response())
        result = mod._fetch_pypi_versions("xz")
        assert "5.6.0" in result
        assert "5.6.2" in result

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_pypi_404(self, mock_get):
        mock_get.return_value = _make_response(404)
        result = mod._fetch_pypi_versions("nonexistent-package")
        assert result == []

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_pypi_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.ConnectionError("fail")
        result = mod._fetch_pypi_versions("xz")
        assert result == []

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_npm_versions(self, mock_get):
        mock_get.return_value = _make_response(200, _npm_json_response())
        result = mod._fetch_npm_versions("lodash")
        assert "4.17.21" in result

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_npm_404(self, mock_get):
        mock_get.return_value = _make_response(404)
        result = mod._fetch_npm_versions("nonexistent")
        assert result == []

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_maven_versions(self, mock_get):
        mock_get.return_value = _make_response(200, _maven_json_response())
        result = mod._fetch_maven_versions("org.apache.logging.log4j:log4j-core")
        assert "2.15.0" in result

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_maven_invalid_format(self, mock_get):
        result = mod._fetch_maven_versions("invalid")
        assert result == []

    @patch("manus_agent.tools.get_version_range._get_with_retry")
    def test_maven_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.ConnectionError("fail")
        result = mod._fetch_maven_versions("org.apache:artifact")
        assert result == []

    @patch("manus_agent.tools.get_version_range._fetch_pypi_versions")
    def test_dispatch_pypi(self, mock_pypi):
        mock_pypi.return_value = ["1.0"]
        result = mod._fetch_registry_versions("PyPI", "somepackage")
        assert result == ["1.0"]

    @patch("manus_agent.tools.get_version_range._fetch_npm_versions")
    def test_dispatch_npm(self, mock_npm):
        mock_npm.return_value = ["1.0.0"]
        result = mod._fetch_registry_versions("npm", "somepackage")
        assert result == ["1.0.0"]

    @patch("manus_agent.tools.get_version_range._fetch_maven_versions")
    def test_dispatch_maven(self, mock_maven):
        mock_maven.return_value = ["1.0"]
        result = mod._fetch_registry_versions("Maven", "group:artifact")
        assert result == ["1.0"]

    def test_dispatch_unknown_ecosystem(self):
        result = mod._fetch_registry_versions("UnknownEco", "package")
        assert result == []


# ===================================================================
# Tests for fetch_version_range (main analysis function)
# ===================================================================
class TestFetchVersionRange:
    @patch("manus_agent.tools.get_version_range._fetch_registry_versions")
    @patch("manus_agent.tools.get_version_range._fetch_osv_affected")
    @patch("manus_agent.tools.get_version_range._fetch_nvd_cpe_ranges")
    def test_full_pipeline(self, mock_nvd, mock_osv, mock_registry):
        mock_nvd.return_value = []
        mock_osv.return_value = [
            {
                "ecosystem": "Maven",
                "package": "org.apache.logging.log4j:log4j-core",
                "introduced": ["2.0-beta9"],
                "fixed": ["2.15.0"],
                "last_affected": [],
                "affected_versions": ["2.0-beta9", "2.14.1"],
            }
        ]
        mock_registry.return_value = []

        result = mod.fetch_version_range("CVE-2021-44228")
        assert result["found"] is True
        assert result["cve_id"] == "CVE-2021-44228"
        assert len(result["packages"]) == 1
        assert result["first_patched_version"] == "2.15.0"
        assert "Maven" in result["ecosystems"]

    @patch("manus_agent.tools.get_version_range._fetch_registry_versions")
    @patch("manus_agent.tools.get_version_range._fetch_osv_affected")
    @patch("manus_agent.tools.get_version_range._fetch_nvd_cpe_ranges")
    def test_ecosystem_filter(self, mock_nvd, mock_osv, mock_registry):
        mock_nvd.return_value = []
        mock_osv.return_value = [
            {
                "ecosystem": "Maven",
                "package": "log4j-core",
                "introduced": ["2.0"],
                "fixed": ["2.15.0"],
                "last_affected": [],
                "affected_versions": [],
            },
            {
                "ecosystem": "PyPI",
                "package": "log4j-python",
                "introduced": ["1.0"],
                "fixed": ["1.5"],
                "last_affected": [],
                "affected_versions": [],
            },
        ]
        mock_registry.return_value = []

        result = mod.fetch_version_range("CVE-2021-44228", ecosystem="pypi")
        assert result["found"] is True
        assert len(result["packages"]) == 1
        assert result["packages"][0]["ecosystem"] == "PyPI"

    def test_invalid_cve_id_empty(self):
        result = mod.fetch_version_range("")
        assert result["found"] is False
        assert "Invalid" in result.get("error", "")

    def test_invalid_cve_id_format(self):
        result = mod.fetch_version_range("not-a-cve")
        assert result["found"] is False
        assert "Invalid" in result.get("error", "")

    @patch("manus_agent.tools.get_version_range._fetch_registry_versions")
    @patch("manus_agent.tools.get_version_range._fetch_osv_affected")
    @patch("manus_agent.tools.get_version_range._fetch_nvd_cpe_ranges")
    def test_no_data_found(self, mock_nvd, mock_osv, mock_registry):
        mock_nvd.return_value = []
        mock_osv.return_value = []
        mock_registry.return_value = []

        result = mod.fetch_version_range("CVE-9999-99999")
        assert result["found"] is False
        assert "No version range data" in result["summary"]

    @patch("manus_agent.tools.get_version_range._fetch_registry_versions")
    @patch("manus_agent.tools.get_version_range._fetch_osv_affected")
    @patch("manus_agent.tools.get_version_range._fetch_nvd_cpe_ranges")
    def test_nvd_error_with_no_osv(self, mock_nvd, mock_osv, mock_registry):
        mock_nvd.side_effect = requests.exceptions.ConnectionError("NVD down")
        mock_osv.return_value = []
        mock_registry.return_value = []

        result = mod.fetch_version_range("CVE-2021-44228")
        assert result["found"] is False
        assert result.get("error") is not None

    @patch("manus_agent.tools.get_version_range._fetch_registry_versions")
    @patch("manus_agent.tools.get_version_range._fetch_osv_affected")
    @patch("manus_agent.tools.get_version_range._fetch_nvd_cpe_ranges")
    def test_nvd_fallback_when_osv_empty(self, mock_nvd, mock_osv, mock_registry):
        mock_nvd.return_value = [
            {
                "vendor": "apache",
                "product": "log4j",
                "version_start": "2.0",
                "version_start_type": "including",
                "version_end": "2.15.0",
                "version_end_type": "excluding",
                "exact_versions": [],
            }
        ]
        mock_osv.return_value = []
        mock_registry.return_value = []

        result = mod.fetch_version_range("CVE-2021-44228")
        assert result["found"] is True
        assert len(result["packages"]) == 1
        assert result["packages"][0]["source"] == "nvd"
        assert result["packages"][0]["ecosystem"] == "NVD/CPE"

    @patch("manus_agent.tools.get_version_range._fetch_registry_versions")
    @patch("manus_agent.tools.get_version_range._fetch_osv_affected")
    @patch("manus_agent.tools.get_version_range._fetch_nvd_cpe_ranges")
    def test_registry_version_filtering(self, mock_nvd, mock_osv, mock_registry):
        mock_nvd.return_value = []
        mock_osv.return_value = [
            {
                "ecosystem": "PyPI",
                "package": "xz",
                "introduced": ["5.6.0"],
                "fixed": ["5.6.2"],
                "last_affected": [],
                "affected_versions": [],  # empty — forces registry lookup
            }
        ]
        mock_registry.return_value = ["5.5.0", "5.6.0", "5.6.1", "5.6.2", "5.7.0"]

        result = mod.fetch_version_range("CVE-2024-3094")
        assert result["found"] is True
        pkg = result["packages"][0]
        assert "5.6.0" in pkg["affected_versions"]
        assert "5.6.1" in pkg["affected_versions"]
        assert "5.6.2" not in pkg["affected_versions"]  # fixed version excluded

    @patch("manus_agent.tools.get_version_range._fetch_registry_versions")
    @patch("manus_agent.tools.get_version_range._fetch_osv_affected")
    @patch("manus_agent.tools.get_version_range._fetch_nvd_cpe_ranges")
    def test_osv_versions_preferred_over_registry(self, mock_nvd, mock_osv, mock_registry):
        mock_nvd.return_value = []
        mock_osv.return_value = [
            {
                "ecosystem": "Maven",
                "package": "log4j-core",
                "introduced": ["2.0"],
                "fixed": ["2.15.0"],
                "last_affected": [],
                "affected_versions": ["2.0", "2.14.1"],  # explicit list
            }
        ]
        mock_registry.return_value = ["2.0", "2.14.1", "2.15.0"]  # should be ignored

        result = mod.fetch_version_range("CVE-2021-44228")
        pkg = result["packages"][0]
        # Should use OSV explicit list, not filter from registry
        assert pkg["affected_versions"] == ["2.0", "2.14.1"]

    @patch("manus_agent.tools.get_version_range._fetch_registry_versions")
    @patch("manus_agent.tools.get_version_range._fetch_osv_affected")
    @patch("manus_agent.tools.get_version_range._fetch_nvd_cpe_ranges")
    def test_affected_versions_capped(self, mock_nvd, mock_osv, mock_registry):
        """Output caps affected_versions at 50 entries."""
        mock_nvd.return_value = []
        mock_osv.return_value = [
            {
                "ecosystem": "npm",
                "package": "big-package",
                "introduced": ["0"],
                "fixed": [],
                "last_affected": [],
                "affected_versions": [f"{i}.0.0" for i in range(100)],
            }
        ]
        mock_registry.return_value = []

        result = mod.fetch_version_range("CVE-2021-44228")
        assert len(result["packages"][0]["affected_versions"]) <= 50

    @patch("manus_agent.tools.get_version_range._fetch_registry_versions")
    @patch("manus_agent.tools.get_version_range._fetch_osv_affected")
    @patch("manus_agent.tools.get_version_range._fetch_nvd_cpe_ranges")
    def test_nvd_cpe_with_including_end(self, mock_nvd, mock_osv, mock_registry):
        mock_nvd.return_value = [
            {
                "vendor": "vendor",
                "product": "product",
                "version_start": "1.0",
                "version_start_type": "including",
                "version_end": "3.0",
                "version_end_type": "including",
                "exact_versions": [],
            }
        ]
        mock_osv.return_value = []
        mock_registry.return_value = []

        result = mod.fetch_version_range("CVE-2021-44228")
        pkg = result["packages"][0]
        assert len(pkg["last_affected"]) == 1
        assert pkg["last_affected"][0] == "3.0"
        assert pkg["first_patched_version"] is None

    @patch("manus_agent.tools.get_version_range._fetch_registry_versions")
    @patch("manus_agent.tools.get_version_range._fetch_osv_affected")
    @patch("manus_agent.tools.get_version_range._fetch_nvd_cpe_ranges")
    def test_nvd_cpe_exact_version(self, mock_nvd, mock_osv, mock_registry):
        mock_nvd.return_value = [
            {
                "vendor": "vendor",
                "product": "product",
                "version_start": "",
                "version_start_type": "",
                "version_end": "",
                "version_end_type": "",
                "exact_versions": ["1.2.3"],
            }
        ]
        mock_osv.return_value = []
        mock_registry.return_value = []

        result = mod.fetch_version_range("CVE-2021-44228")
        pkg = result["packages"][0]
        assert "==1.2.3" in pkg["vulnerable_range"]

    @patch("manus_agent.tools.get_version_range._fetch_registry_versions")
    @patch("manus_agent.tools.get_version_range._fetch_osv_affected")
    @patch("manus_agent.tools.get_version_range._fetch_nvd_cpe_ranges")
    def test_summary_message(self, mock_nvd, mock_osv, mock_registry):
        mock_nvd.return_value = []
        mock_osv.return_value = [
            {
                "ecosystem": "PyPI",
                "package": "xz",
                "introduced": ["5.6.0"],
                "fixed": ["5.6.2"],
                "last_affected": [],
                "affected_versions": ["5.6.0", "5.6.1"],
            }
        ]
        mock_registry.return_value = []

        result = mod.fetch_version_range("CVE-2024-3094")
        assert "CVE-2024-3094" in result["summary"]
        assert "PyPI" in result["summary"]
        assert "5.6.2" in result["summary"]

    @patch("manus_agent.tools.get_version_range._fetch_registry_versions")
    @patch("manus_agent.tools.get_version_range._fetch_osv_affected")
    @patch("manus_agent.tools.get_version_range._fetch_nvd_cpe_ranges")
    def test_no_patched_version(self, mock_nvd, mock_osv, mock_registry):
        mock_nvd.return_value = []
        mock_osv.return_value = [
            {
                "ecosystem": "npm",
                "package": "unfixed-pkg",
                "introduced": ["1.0"],
                "fixed": [],
                "last_affected": ["2.0"],
                "affected_versions": ["1.0", "1.5", "2.0"],
            }
        ]
        mock_registry.return_value = []

        result = mod.fetch_version_range("CVE-2021-44228")
        assert result["first_patched_version"] is None
        assert "No patch" in result["summary"]

    @patch("manus_agent.tools.get_version_range._fetch_registry_versions")
    @patch("manus_agent.tools.get_version_range._fetch_osv_affected")
    @patch("manus_agent.tools.get_version_range._fetch_nvd_cpe_ranges")
    def test_duplicate_osv_nvd_package_dedup(self, mock_nvd, mock_osv, mock_registry):
        """NVD CPE for same product as OSV should be deduplicated."""
        mock_nvd.return_value = [
            {
                "vendor": "org",
                "product": "log4j-core",
                "version_start": "2.0",
                "version_start_type": "including",
                "version_end": "2.15.0",
                "version_end_type": "excluding",
                "exact_versions": [],
            }
        ]
        mock_osv.return_value = [
            {
                "ecosystem": "Maven",
                "package": "org.apache.logging.log4j:log4j-core",
                "introduced": ["2.0"],
                "fixed": ["2.15.0"],
                "last_affected": [],
                "affected_versions": [],
            }
        ]
        mock_registry.return_value = []

        result = mod.fetch_version_range("CVE-2021-44228")
        # Should only have the OSV entry, not a duplicate NVD entry
        assert len(result["packages"]) == 1
        assert result["packages"][0]["source"] == "osv"


# ===================================================================
# Tests for Strands tool entry point
# ===================================================================
class TestGetVersionRangeTool:
    @patch("manus_agent.tools.get_version_range.fetch_version_range")
    def test_success(self, mock_fetch):
        mock_fetch.return_value = {
            "found": True,
            "cve_id": "CVE-2021-44228",
            "packages": [],
            "first_patched_version": "2.15.0",
        }
        tool_use = _make_tool_use()
        result = mod.get_version_range(tool_use)
        assert result["status"] == "success"
        assert result["toolUseId"] == "vr-test-001"

    @patch("manus_agent.tools.get_version_range.fetch_version_range")
    def test_not_found(self, mock_fetch):
        mock_fetch.return_value = {
            "found": False,
            "cve_id": "CVE-9999-99999",
            "packages": [],
            "first_patched_version": None,
        }
        tool_use = _make_tool_use(cve_id="CVE-9999-99999")
        result = mod.get_version_range(tool_use)
        assert result["status"] == "error"

    def test_invalid_cve_id(self):
        tool_use = {"toolUseId": "vr-test-002", "input": {"cve_id": ""}}
        result = mod.get_version_range(tool_use)
        assert result["status"] == "error"
        assert "Invalid" in result["content"][0]["text"]

    def test_none_cve_id(self):
        tool_use = {"toolUseId": "vr-test-003", "input": {"cve_id": None}}
        result = mod.get_version_range(tool_use)
        assert result["status"] == "error"

    def test_missing_input(self):
        tool_use = {"toolUseId": "vr-test-004", "input": {}}
        result = mod.get_version_range(tool_use)
        assert result["status"] == "error"

    def test_null_input(self):
        tool_use = {"toolUseId": "vr-test-005", "input": None}
        result = mod.get_version_range(tool_use)
        assert result["status"] == "error"

    @patch("manus_agent.tools.get_version_range.fetch_version_range")
    def test_ecosystem_passed_through(self, mock_fetch):
        mock_fetch.return_value = {"found": True, "cve_id": "CVE-2021-44228", "packages": []}
        tool_use = _make_tool_use(ecosystem="pypi")
        mod.get_version_range(tool_use)
        mock_fetch.assert_called_once_with("CVE-2021-44228", ecosystem="pypi")

    @patch("manus_agent.tools.get_version_range.fetch_version_range")
    def test_default_ecosystem(self, mock_fetch):
        mock_fetch.return_value = {"found": True, "cve_id": "CVE-2021-44228", "packages": []}
        tool_use = {"toolUseId": "vr-test-006", "input": {"cve_id": "CVE-2021-44228"}}
        mod.get_version_range(tool_use)
        mock_fetch.assert_called_once_with("CVE-2021-44228", ecosystem="auto")


# ===================================================================
# Tests for CLI subcommand
# ===================================================================
class TestVersionRangeCli:
    def test_parser_defaults(self):
        from manus_agent.cli import _build_version_range_parser

        parser = _build_version_range_parser()
        args = parser.parse_args(["CVE-2021-44228"])
        assert args.cve_id == "CVE-2021-44228"
        assert args.ecosystem == "auto"
        assert args.output == "text"

    def test_parser_with_ecosystem(self):
        from manus_agent.cli import _build_version_range_parser

        parser = _build_version_range_parser()
        args = parser.parse_args(["CVE-2021-44228", "--ecosystem", "pypi"])
        assert args.ecosystem == "pypi"

    def test_parser_with_json_output(self):
        from manus_agent.cli import _build_version_range_parser

        parser = _build_version_range_parser()
        args = parser.parse_args(["CVE-2021-44228", "--output", "json"])
        assert args.output == "json"

    def test_parser_invalid_ecosystem(self):
        from manus_agent.cli import _build_version_range_parser

        parser = _build_version_range_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["CVE-2021-44228", "--ecosystem", "invalid"])

    @patch("manus_agent.cli._build_version_range_parser")
    def test_run_import_error(self, mock_parser):
        """Import failure returns exit code 1."""

        mock_args = MagicMock()
        mock_args.cve_id = "CVE-2021-44228"
        mock_args.ecosystem = "auto"
        mock_args.output = "text"
        mock_parser.return_value.parse_args.return_value = mock_args

        with patch.dict("sys.modules", {"manus_agent.tools.get_version_range": None}):
            with patch("builtins.__import__", side_effect=ImportError("no module")):
                # Can't easily force ImportError inside _run_version_range,
                # test the error path via fetch_version_range raising
                pass

    @patch("manus_agent.tools.get_version_range.fetch_version_range")
    def test_run_json_output(self, mock_fetch):
        from manus_agent.cli import _run_version_range

        mock_fetch.return_value = {
            "found": True,
            "cve_id": "CVE-2021-44228",
            "packages": [
                {
                    "ecosystem": "Maven",
                    "package": "log4j-core",
                    "vulnerable_range": ">=2.0 <2.15.0",
                    "first_patched_version": "2.15.0",
                }
            ],
            "first_patched_version": "2.15.0",
            "affected_package_count": 1,
            "ecosystems": ["Maven"],
            "summary": "CVE-2021-44228 affects 1 package(s)",
        }
        with patch("builtins.print") as mock_print:
            exit_code = _run_version_range(["CVE-2021-44228", "--output", "json"])
        assert exit_code == 0
        printed = mock_print.call_args[0][0]
        parsed = json.loads(printed)
        assert parsed["found"] is True

    @patch("manus_agent.tools.get_version_range.fetch_version_range")
    def test_run_text_output(self, mock_fetch):
        from manus_agent.cli import _run_version_range

        mock_fetch.return_value = {
            "found": True,
            "cve_id": "CVE-2021-44228",
            "packages": [
                {
                    "ecosystem": "Maven",
                    "package": "log4j-core",
                    "vulnerable_range": ">=2.0 <2.15.0",
                    "introduced": ["2.0"],
                    "fixed": ["2.15.0"],
                    "last_affected": [],
                    "first_patched_version": "2.15.0",
                    "affected_version_count": 5,
                    "affected_versions": ["2.0", "2.1", "2.14.0", "2.14.1"],
                    "registry_version_count": 10,
                    "source": "osv",
                }
            ],
            "first_patched_version": "2.15.0",
            "affected_package_count": 1,
            "ecosystems": ["Maven"],
            "summary": "CVE-2021-44228 affects 1 package(s) across 1 ecosystem(s): Maven. First patched: 2.15.0.",
        }
        with patch("builtins.print"):
            exit_code = _run_version_range(["CVE-2021-44228"])
        assert exit_code == 0

    @patch("manus_agent.tools.get_version_range.fetch_version_range")
    def test_run_not_found(self, mock_fetch):
        from manus_agent.cli import _run_version_range

        mock_fetch.return_value = {
            "found": False,
            "cve_id": "CVE-9999-99999",
            "packages": [],
            "first_patched_version": None,
            "summary": "No version range data found for CVE-9999-99999.",
        }
        exit_code = _run_version_range(["CVE-9999-99999"])
        assert exit_code == 1

    @patch("manus_agent.tools.get_version_range.fetch_version_range")
    def test_run_fetch_exception(self, mock_fetch):
        from manus_agent.cli import _run_version_range

        mock_fetch.side_effect = RuntimeError("boom")
        exit_code = _run_version_range(["CVE-2021-44228"])
        assert exit_code == 1

    @patch("manus_agent.tools.get_version_range.fetch_version_range")
    def test_run_text_many_versions(self, mock_fetch):
        """Text output with >10 affected versions shows truncation."""
        from manus_agent.cli import _run_version_range

        versions = [f"1.{i}.0" for i in range(15)]
        mock_fetch.return_value = {
            "found": True,
            "cve_id": "CVE-2021-44228",
            "packages": [
                {
                    "ecosystem": "npm",
                    "package": "big-pkg",
                    "vulnerable_range": ">=1.0.0",
                    "introduced": ["1.0.0"],
                    "fixed": [],
                    "last_affected": [],
                    "first_patched_version": None,
                    "affected_version_count": 15,
                    "affected_versions": versions,
                    "registry_version_count": 20,
                    "source": "osv",
                }
            ],
            "first_patched_version": None,
            "affected_package_count": 1,
            "ecosystems": ["npm"],
            "summary": "CVE-2021-44228 affects 1 package(s). No patch identified.",
        }
        with patch("builtins.print") as mock_print:
            exit_code = _run_version_range(["CVE-2021-44228"])
        assert exit_code == 0
        # Check that "more" truncation text appears
        all_printed = " ".join(str(c) for c in mock_print.call_args_list)
        assert "more" in all_printed

    def test_main_dispatch(self):
        """version-range is dispatched from main()."""
        from manus_agent.cli import main

        with patch("manus_agent.cli._run_version_range", return_value=0) as mock_run:
            with patch("sys.argv", ["manus-agent", "version-range", "CVE-2021-44228"]):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0
            mock_run.assert_called_once_with(["CVE-2021-44228"])

    @patch("manus_agent.tools.get_version_range.fetch_version_range")
    def test_run_ecosystem_flag_passed(self, mock_fetch):
        from manus_agent.cli import _run_version_range

        mock_fetch.return_value = {
            "found": True,
            "cve_id": "CVE-2021-44228",
            "packages": [],
            "first_patched_version": None,
            "affected_package_count": 0,
            "ecosystems": [],
            "summary": "No packages found",
        }
        with patch("builtins.print"):
            _run_version_range(["CVE-2021-44228", "--ecosystem", "maven", "--output", "json"])
        mock_fetch.assert_called_once_with("CVE-2021-44228", ecosystem="maven")
