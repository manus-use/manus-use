"""
Tests for get_patch_status tool.

All HTTP calls are mocked; no real network requests.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CVE_LOG4SHELL = "CVE-2021-44228"

# Realistic NVD response fragment for Log4Shell
_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": CVE_LOG4SHELL,
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2024-01-15T00:00:00.000",
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
            }
        }
    ]
}

# Realistic GHSA response for Log4Shell (GitHub Advisory API)
_GHSA_RESPONSE = [
    {
        "ghsa_id": "GHSA-jfh8-c2jp-5v3q",
        "published_at": "2021-12-10T00:40:56Z",
        "vulnerabilities": [
            {
                "package": {"ecosystem": "maven", "name": "org.apache.logging.log4j:log4j-core"},
                "vulnerable_version_range": ">= 2.13.0, < 2.15.0",
                "first_patched_version": "2.15.0",
            }
        ],
    }
]

# OSV response (alias for the same CVE)
_OSV_QUERY_RESPONSE = {"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q"}]}

_OSV_VULN_FULL = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "published": "2021-12-10T00:40:56Z",
    "aliases": [CVE_LOG4SHELL],
    "affected": [
        {
            "package": {
                "name": "org.apache.logging.log4j:log4j-core",
                "ecosystem": "Maven",
            },
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "2.13.0"},
                        {"fixed": "2.15.0"},
                    ],
                }
            ],
        }
    ],
}

# Maven Central search response
_MAVEN_SEARCH_RESPONSE = {
    "response": {
        "docs": [
            {
                "id": "org.apache.logging.log4j:log4j-core:2.15.0",
                "timestamp": 1639167600000,  # ~2021-12-10T21:00:00Z
            }
        ]
    }
}

# PyPI JSON response (requests package)
_PYPI_REQUESTS_RESPONSE = {
    "info": {"name": "requests", "version": "2.32.4"},
    "releases": {
        "2.32.4": [
            {
                "upload_time": "2024-06-09T16:43:05",
                "filename": "requests-2.32.4-py3-none-any.whl",
            }
        ]
    },
}

# npm registry response (lodash)
_NPM_LODASH_RESPONSE = {
    "name": "lodash",
    "time": {
        "4.17.21": "2021-02-20T15:42:16.891Z",
    },
}


# ---------------------------------------------------------------------------
# Unit tests: helpers
# ---------------------------------------------------------------------------


class TestPatchLagLabel:
    """Tests for _patch_lag_label helper."""

    def test_fast_zero(self) -> None:
        from manus_agent.tools.get_patch_status import _patch_lag_label

        assert _patch_lag_label(0) == "FAST"

    def test_fast_boundary(self) -> None:
        from manus_agent.tools.get_patch_status import _patch_lag_label

        assert _patch_lag_label(7) == "FAST"

    def test_normal_eight_days(self) -> None:
        from manus_agent.tools.get_patch_status import _patch_lag_label

        assert _patch_lag_label(8) == "NORMAL"

    def test_normal_thirty_days(self) -> None:
        from manus_agent.tools.get_patch_status import _patch_lag_label

        assert _patch_lag_label(30) == "NORMAL"

    def test_slow(self) -> None:
        from manus_agent.tools.get_patch_status import _patch_lag_label

        assert _patch_lag_label(31) == "SLOW"

    def test_very_slow(self) -> None:
        from manus_agent.tools.get_patch_status import _patch_lag_label

        assert _patch_lag_label(365) == "SLOW"

    def test_none_returns_missing(self) -> None:
        from manus_agent.tools.get_patch_status import _patch_lag_label

        assert _patch_lag_label(None) == "MISSING"

    def test_negative_coordinated_disclosure(self) -> None:
        # Patch released before public disclosure
        from manus_agent.tools.get_patch_status import _patch_lag_label

        assert _patch_lag_label(-3) == "FAST"


class TestParseIso:
    """Tests for _parse_iso helper."""

    def test_with_milliseconds(self) -> None:
        from manus_agent.tools.get_patch_status import _parse_iso

        dt = _parse_iso("2021-12-10T10:15:09.143")
        assert dt is not None
        assert dt.year == 2021
        assert dt.month == 12
        assert dt.day == 10
        assert dt.tzinfo == timezone.utc

    def test_with_z_suffix(self) -> None:
        from manus_agent.tools.get_patch_status import _parse_iso

        dt = _parse_iso("2021-12-10T00:40:56Z")
        assert dt is not None
        assert dt.year == 2021

    def test_without_seconds(self) -> None:
        from manus_agent.tools.get_patch_status import _parse_iso

        dt = _parse_iso("2021-12-10T10:15")
        assert dt is not None

    def test_none_input(self) -> None:
        from manus_agent.tools.get_patch_status import _parse_iso

        assert _parse_iso(None) is None

    def test_empty_string(self) -> None:
        from manus_agent.tools.get_patch_status import _parse_iso

        assert _parse_iso("") is None


# ---------------------------------------------------------------------------
# Unit tests: NVD fetch
# ---------------------------------------------------------------------------


class TestFetchNvdCve:
    """Tests for _fetch_nvd_cve."""

    @patch("manus_agent.tools.get_patch_status._get")
    def test_returns_cve_record(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _NVD_RESPONSE
        from manus_agent.tools.get_patch_status import _fetch_nvd_cve

        result = _fetch_nvd_cve(CVE_LOG4SHELL)
        assert result["id"] == CVE_LOG4SHELL
        assert result["published"] == "2021-12-10T10:15:09.143"

    @patch("manus_agent.tools.get_patch_status._get")
    def test_empty_vulnerabilities(self, mock_get: MagicMock) -> None:
        mock_get.return_value = {"vulnerabilities": []}
        from manus_agent.tools.get_patch_status import _fetch_nvd_cve

        result = _fetch_nvd_cve(CVE_LOG4SHELL)
        assert result == {}

    @patch("manus_agent.tools.get_patch_status._get")
    def test_network_error_returns_empty(self, mock_get: MagicMock) -> None:
        mock_get.side_effect = Exception("network error")
        from manus_agent.tools.get_patch_status import _fetch_nvd_cve

        result = _fetch_nvd_cve(CVE_LOG4SHELL)
        assert result == {}


# ---------------------------------------------------------------------------
# Unit tests: GHSA fetch
# ---------------------------------------------------------------------------


class TestFetchGhsaVulns:
    """Tests for _fetch_ghsa_vulns."""

    @patch("manus_agent.tools.get_patch_status._get")
    def test_returns_vuln_records(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _GHSA_RESPONSE
        from manus_agent.tools.get_patch_status import _fetch_ghsa_vulns

        vulns = _fetch_ghsa_vulns(CVE_LOG4SHELL)
        assert len(vulns) == 1
        assert vulns[0]["name"] == "org.apache.logging.log4j:log4j-core"
        assert vulns[0]["patched_version"] == "2.15.0"
        assert vulns[0]["ecosystem"] == "maven"
        assert vulns[0]["advisory_id"] == "GHSA-jfh8-c2jp-5v3q"

    @patch("manus_agent.tools.get_patch_status._get")
    def test_multiple_packages(self, mock_get: MagicMock) -> None:
        mock_get.return_value = [
            {
                "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "requests"},
                        "vulnerable_version_range": "< 2.32.0",
                        "first_patched_version": "2.32.0",
                    },
                    {
                        "package": {"ecosystem": "npm", "name": "axios"},
                        "vulnerable_version_range": "< 1.7.0",
                        "first_patched_version": "1.7.0",
                    },
                ],
            }
        ]
        from manus_agent.tools.get_patch_status import _fetch_ghsa_vulns

        vulns = _fetch_ghsa_vulns("CVE-2024-12345")
        assert len(vulns) == 2
        names = {v["name"] for v in vulns}
        assert "requests" in names
        assert "axios" in names

    @patch("manus_agent.tools.get_patch_status._get")
    def test_no_patched_version(self, mock_get: MagicMock) -> None:
        mock_get.return_value = [
            {
                "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "example-pkg"},
                        "vulnerable_version_range": ">= 1.0.0",
                        "first_patched_version": None,
                    }
                ],
            }
        ]
        from manus_agent.tools.get_patch_status import _fetch_ghsa_vulns

        vulns = _fetch_ghsa_vulns("CVE-2024-99999")
        assert len(vulns) == 1
        assert vulns[0]["patched_version"] is None

    @patch("manus_agent.tools.get_patch_status._get")
    def test_non_list_response_returns_empty(self, mock_get: MagicMock) -> None:
        mock_get.return_value = {"message": "Not found"}
        from manus_agent.tools.get_patch_status import _fetch_ghsa_vulns

        vulns = _fetch_ghsa_vulns("CVE-2024-00001")
        assert vulns == []

    @patch("manus_agent.tools.get_patch_status._get")
    def test_network_error_returns_empty(self, mock_get: MagicMock) -> None:
        mock_get.side_effect = Exception("timeout")
        from manus_agent.tools.get_patch_status import _fetch_ghsa_vulns

        vulns = _fetch_ghsa_vulns(CVE_LOG4SHELL)
        assert vulns == []


# ---------------------------------------------------------------------------
# Unit tests: OSV fetch
# ---------------------------------------------------------------------------


class TestFetchOsvVulns:
    """Tests for _fetch_osv_vulns."""

    @patch("manus_agent.tools.get_patch_status._get")
    @patch("manus_agent.tools.get_patch_status._post")
    def test_returns_fixed_version(self, mock_post: MagicMock, mock_get: MagicMock) -> None:
        mock_post.return_value = _OSV_QUERY_RESPONSE
        mock_get.return_value = _OSV_VULN_FULL
        from manus_agent.tools.get_patch_status import _fetch_osv_vulns

        vulns = _fetch_osv_vulns(CVE_LOG4SHELL)
        assert len(vulns) == 1
        assert vulns[0]["patched_version"] == "2.15.0"
        assert vulns[0]["ecosystem"] == "maven"

    @patch("manus_agent.tools.get_patch_status._post")
    def test_no_vulns_returns_empty(self, mock_post: MagicMock) -> None:
        mock_post.return_value = {"vulns": []}
        from manus_agent.tools.get_patch_status import _fetch_osv_vulns

        vulns = _fetch_osv_vulns("CVE-2099-99999")
        assert vulns == []

    @patch("manus_agent.tools.get_patch_status._get")
    @patch("manus_agent.tools.get_patch_status._post")
    def test_missing_fixed_event(self, mock_post: MagicMock, mock_get: MagicMock) -> None:
        mock_post.return_value = {"vulns": [{"id": "OSV-2021-1"}]}
        mock_get.return_value = {
            "id": "OSV-2021-1",
            "affected": [
                {
                    "package": {"name": "some-pkg", "ecosystem": "PyPI"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}]}],
                }
            ],
        }
        from manus_agent.tools.get_patch_status import _fetch_osv_vulns

        vulns = _fetch_osv_vulns("CVE-2021-99999")
        assert len(vulns) == 1
        assert vulns[0]["patched_version"] is None

    @patch("manus_agent.tools.get_patch_status._post")
    def test_network_error_returns_empty(self, mock_post: MagicMock) -> None:
        mock_post.side_effect = Exception("connection refused")
        from manus_agent.tools.get_patch_status import _fetch_osv_vulns

        vulns = _fetch_osv_vulns(CVE_LOG4SHELL)
        assert vulns == []


# ---------------------------------------------------------------------------
# Unit tests: registry date lookups
# ---------------------------------------------------------------------------


class TestPypiReleaseDate:
    @patch("manus_agent.tools.get_patch_status._get")
    def test_known_version(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _PYPI_REQUESTS_RESPONSE
        from manus_agent.tools.get_patch_status import _pypi_release_date

        dt = _pypi_release_date("requests", "2.32.4")
        assert dt is not None
        assert dt.year == 2024
        assert dt.month == 6

    @patch("manus_agent.tools.get_patch_status._get")
    def test_unknown_version_returns_none(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _PYPI_REQUESTS_RESPONSE
        from manus_agent.tools.get_patch_status import _pypi_release_date

        dt = _pypi_release_date("requests", "99.99.99")
        assert dt is None

    @patch("manus_agent.tools.get_patch_status._get")
    def test_network_error_returns_none(self, mock_get: MagicMock) -> None:
        mock_get.side_effect = Exception("404")
        from manus_agent.tools.get_patch_status import _pypi_release_date

        dt = _pypi_release_date("nonexistent-pkg", "1.0.0")
        assert dt is None


class TestNpmReleaseDate:
    @patch("manus_agent.tools.get_patch_status._get")
    def test_known_version(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _NPM_LODASH_RESPONSE
        from manus_agent.tools.get_patch_status import _npm_release_date

        dt = _npm_release_date("lodash", "4.17.21")
        assert dt is not None
        assert dt.year == 2021
        assert dt.month == 2

    @patch("manus_agent.tools.get_patch_status._get")
    def test_unknown_version_returns_none(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _NPM_LODASH_RESPONSE
        from manus_agent.tools.get_patch_status import _npm_release_date

        dt = _npm_release_date("lodash", "99.99.99")
        assert dt is None

    @patch("manus_agent.tools.get_patch_status._get")
    def test_network_error_returns_none(self, mock_get: MagicMock) -> None:
        mock_get.side_effect = Exception("timeout")
        from manus_agent.tools.get_patch_status import _npm_release_date

        dt = _npm_release_date("nonexistent", "1.0.0")
        assert dt is None


class TestMavenReleaseDate:
    @patch("manus_agent.tools.get_patch_status._get")
    def test_known_artifact(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _MAVEN_SEARCH_RESPONSE
        from manus_agent.tools.get_patch_status import _maven_release_date

        dt = _maven_release_date("org.apache.logging.log4j:log4j-core", "2.15.0")
        assert dt is not None
        # Timestamp 1639167600000 ms ≈ 2021-12-10
        assert dt.year == 2021

    @patch("manus_agent.tools.get_patch_status._get")
    def test_no_docs_returns_none(self, mock_get: MagicMock) -> None:
        mock_get.return_value = {"response": {"docs": []}}
        from manus_agent.tools.get_patch_status import _maven_release_date

        dt = _maven_release_date("org.example:some-lib", "1.0.0")
        assert dt is None

    @patch("manus_agent.tools.get_patch_status._get")
    def test_network_error_returns_none(self, mock_get: MagicMock) -> None:
        mock_get.side_effect = Exception("503")
        from manus_agent.tools.get_patch_status import _maven_release_date

        dt = _maven_release_date("org.example:lib", "1.0.0")
        assert dt is None

    @patch("manus_agent.tools.get_patch_status._get")
    def test_artifact_without_group(self, mock_get: MagicMock) -> None:
        mock_get.return_value = _MAVEN_SEARCH_RESPONSE
        from manus_agent.tools.get_patch_status import _maven_release_date

        # No ":" in name — should still call through without crashing
        dt = _maven_release_date("log4j-core", "2.15.0")
        assert dt is not None


class TestRegistryReleaseDate:
    """Tests for the dispatcher _registry_release_date."""

    @patch("manus_agent.tools.get_patch_status._pypi_release_date")
    def test_pypi_dispatch(self, mock_pypi: MagicMock) -> None:
        mock_pypi.return_value = datetime(2024, 6, 9, tzinfo=timezone.utc)
        from manus_agent.tools.get_patch_status import _registry_release_date

        dt = _registry_release_date("requests", "pypi", "2.32.4")
        mock_pypi.assert_called_once_with("requests", "2.32.4")
        assert dt is not None

    @patch("manus_agent.tools.get_patch_status._npm_release_date")
    def test_npm_dispatch(self, mock_npm: MagicMock) -> None:
        mock_npm.return_value = datetime(2021, 2, 20, tzinfo=timezone.utc)
        from manus_agent.tools.get_patch_status import _registry_release_date

        dt = _registry_release_date("lodash", "npm", "4.17.21")
        mock_npm.assert_called_once_with("lodash", "4.17.21")
        assert dt is not None

    @patch("manus_agent.tools.get_patch_status._npm_release_date")
    def test_nodejs_alias_dispatch(self, mock_npm: MagicMock) -> None:
        mock_npm.return_value = None
        from manus_agent.tools.get_patch_status import _registry_release_date

        _registry_release_date("express", "node", "4.18.0")
        mock_npm.assert_called_once()

    @patch("manus_agent.tools.get_patch_status._maven_release_date")
    def test_maven_dispatch(self, mock_maven: MagicMock) -> None:
        mock_maven.return_value = datetime(2021, 12, 10, tzinfo=timezone.utc)
        from manus_agent.tools.get_patch_status import _registry_release_date

        dt = _registry_release_date("org.example:lib", "maven", "2.15.0")
        mock_maven.assert_called_once_with("org.example:lib", "2.15.0")
        assert dt is not None

    def test_unknown_ecosystem_returns_none(self) -> None:
        from manus_agent.tools.get_patch_status import _registry_release_date

        dt = _registry_release_date("some-crate", "crates.io", "1.0.0")
        assert dt is None

    def test_go_ecosystem_returns_none(self) -> None:
        from manus_agent.tools.get_patch_status import _registry_release_date

        dt = _registry_release_date("github.com/some/pkg", "go", "v1.2.3")
        assert dt is None


# ---------------------------------------------------------------------------
# Unit tests: merge_vulns
# ---------------------------------------------------------------------------


class TestMergeVulns:
    def test_deduplication(self) -> None:
        from manus_agent.tools.get_patch_status import _merge_vulns

        ghsa = [{"name": "log4j-core", "ecosystem": "maven", "patched_version": "2.15.0", "advisory_id": "GHSA-1"}]
        osv = [{"name": "log4j-core", "ecosystem": "maven", "patched_version": "2.15.0", "advisory_id": "OSV-1"}]
        merged = _merge_vulns(ghsa, osv)
        assert len(merged) == 1
        assert merged[0]["advisory_id"] == "GHSA-1"  # GHSA wins (first)

    def test_osv_fills_missing_patched_version(self) -> None:
        from manus_agent.tools.get_patch_status import _merge_vulns

        ghsa = [{"name": "log4j-core", "ecosystem": "maven", "patched_version": None, "advisory_id": "GHSA-1"}]
        osv = [{"name": "log4j-core", "ecosystem": "maven", "patched_version": "2.15.0", "advisory_id": "OSV-1"}]
        merged = _merge_vulns(ghsa, osv)
        assert len(merged) == 1
        # OSV version should be used because GHSA had None
        assert merged[0]["patched_version"] == "2.15.0"

    def test_different_packages_both_kept(self) -> None:
        from manus_agent.tools.get_patch_status import _merge_vulns

        ghsa = [{"name": "requests", "ecosystem": "pypi", "patched_version": "2.32.0", "advisory_id": "GHSA-1"}]
        osv = [{"name": "axios", "ecosystem": "npm", "patched_version": "1.7.0", "advisory_id": "OSV-1"}]
        merged = _merge_vulns(ghsa, osv)
        assert len(merged) == 2


# ---------------------------------------------------------------------------
# Integration-style tests: _run_patch_status
# ---------------------------------------------------------------------------


class TestRunPatchStatus:
    """Tests for the core _run_patch_status function."""

    def _mock_maven_date_response(self) -> MagicMock:
        m = MagicMock()
        m.return_value = _MAVEN_SEARCH_RESPONSE
        return m

    @patch("manus_agent.tools.get_patch_status._registry_release_date")
    @patch("manus_agent.tools.get_patch_status._fetch_osv_vulns")
    @patch("manus_agent.tools.get_patch_status._fetch_ghsa_vulns")
    @patch("manus_agent.tools.get_patch_status._fetch_nvd_cve")
    def test_log4shell_full_flow(
        self,
        mock_nvd: MagicMock,
        mock_ghsa: MagicMock,
        mock_osv: MagicMock,
        mock_reg: MagicMock,
    ) -> None:
        mock_nvd.return_value = _NVD_RESPONSE["vulnerabilities"][0]["cve"]
        mock_ghsa.return_value = [
            {
                "advisory_id": "GHSA-jfh8-c2jp-5v3q",
                "name": "org.apache.logging.log4j:log4j-core",
                "ecosystem": "maven",
                "patched_version": "2.15.0",
                "vulnerable_range": ">= 2.13.0, < 2.15.0",
            }
        ]
        mock_osv.return_value = []
        # Patch release: Dec 10 2021 → 0 days lag (same day as CVE disclosure)
        mock_reg.return_value = datetime(2021, 12, 10, 21, 0, 0, tzinfo=timezone.utc)

        from manus_agent.tools.get_patch_status import _run_patch_status

        result = _run_patch_status(CVE_LOG4SHELL)

        assert result["cve_id"] == CVE_LOG4SHELL
        assert result["severity"] == "CRITICAL"
        assert len(result["packages"]) == 1

        pkg = result["packages"][0]
        assert pkg["patched_version"] == "2.15.0"
        assert pkg["patch_release_date"] == "2021-12-10"
        assert pkg["patch_lag_label"] == "FAST"

    @patch("manus_agent.tools.get_patch_status._registry_release_date")
    @patch("manus_agent.tools.get_patch_status._fetch_osv_vulns")
    @patch("manus_agent.tools.get_patch_status._fetch_ghsa_vulns")
    @patch("manus_agent.tools.get_patch_status._fetch_nvd_cve")
    def test_slow_patch_lag(
        self,
        mock_nvd: MagicMock,
        mock_ghsa: MagicMock,
        mock_osv: MagicMock,
        mock_reg: MagicMock,
    ) -> None:
        mock_nvd.return_value = {
            "id": "CVE-2023-00001",
            "published": "2023-01-01T00:00:00.000",
            "metrics": {},
        }
        mock_ghsa.return_value = [
            {
                "advisory_id": "GHSA-slow-slow-slow",
                "name": "slowpkg",
                "ecosystem": "pypi",
                "patched_version": "2.0.0",
                "vulnerable_range": "< 2.0.0",
            }
        ]
        mock_osv.return_value = []
        # 45 days after disclosure
        mock_reg.return_value = datetime(2023, 2, 15, tzinfo=timezone.utc)

        from manus_agent.tools.get_patch_status import _run_patch_status

        result = _run_patch_status("CVE-2023-00001")
        pkg = result["packages"][0]
        assert pkg["patch_lag_days"] == 45
        assert pkg["patch_lag_label"] == "SLOW"

    @patch("manus_agent.tools.get_patch_status._registry_release_date")
    @patch("manus_agent.tools.get_patch_status._fetch_osv_vulns")
    @patch("manus_agent.tools.get_patch_status._fetch_ghsa_vulns")
    @patch("manus_agent.tools.get_patch_status._fetch_nvd_cve")
    def test_missing_patch(
        self,
        mock_nvd: MagicMock,
        mock_ghsa: MagicMock,
        mock_osv: MagicMock,
        mock_reg: MagicMock,
    ) -> None:
        mock_nvd.return_value = {
            "id": "CVE-2024-00001",
            "published": "2024-01-01T00:00:00.000",
            "metrics": {},
        }
        mock_ghsa.return_value = [
            {
                "advisory_id": "GHSA-no-fix-here",
                "name": "unpatched-pkg",
                "ecosystem": "pypi",
                "patched_version": None,
                "vulnerable_range": ">= 1.0.0",
            }
        ]
        mock_osv.return_value = []
        mock_reg.return_value = None

        from manus_agent.tools.get_patch_status import _run_patch_status

        result = _run_patch_status("CVE-2024-00001")
        pkg = result["packages"][0]
        assert pkg["patched_version"] == "unknown"
        assert pkg["patch_lag_label"] == "MISSING"
        assert "MISSING" in result["summary"] or "unpatched" in result["summary"].lower()

    @patch("manus_agent.tools.get_patch_status._registry_release_date")
    @patch("manus_agent.tools.get_patch_status._fetch_osv_vulns")
    @patch("manus_agent.tools.get_patch_status._fetch_ghsa_vulns")
    @patch("manus_agent.tools.get_patch_status._fetch_nvd_cve")
    def test_no_packages_found(
        self,
        mock_nvd: MagicMock,
        mock_ghsa: MagicMock,
        mock_osv: MagicMock,
        mock_reg: MagicMock,
    ) -> None:
        mock_nvd.return_value = {
            "id": "CVE-2024-00002",
            "published": "2024-01-01T00:00:00.000",
            "metrics": {},
        }
        mock_ghsa.return_value = []
        mock_osv.return_value = []
        mock_reg.return_value = None

        from manus_agent.tools.get_patch_status import _run_patch_status

        result = _run_patch_status("CVE-2024-00002")
        assert result["packages"] == []
        assert "No affected package records" in result["summary"]

    def test_invalid_cve_id(self) -> None:
        from manus_agent.tools.get_patch_status import _run_patch_status

        result = _run_patch_status("NOT-A-CVE")
        assert "error" in result
        assert "Invalid CVE ID" in result["error"]

    def test_invalid_cve_id_whitespace_stripped(self) -> None:
        from manus_agent.tools.get_patch_status import _run_patch_status

        result = _run_patch_status("   NOT-A-CVE   ")
        assert "error" in result

    @patch("manus_agent.tools.get_patch_status._registry_release_date")
    @patch("manus_agent.tools.get_patch_status._fetch_osv_vulns")
    @patch("manus_agent.tools.get_patch_status._fetch_ghsa_vulns")
    @patch("manus_agent.tools.get_patch_status._fetch_nvd_cve")
    def test_registry_returns_none_lag_is_none(
        self,
        mock_nvd: MagicMock,
        mock_ghsa: MagicMock,
        mock_osv: MagicMock,
        mock_reg: MagicMock,
    ) -> None:
        mock_nvd.return_value = {
            "id": "CVE-2023-11111",
            "published": "2023-06-01T00:00:00.000",
            "metrics": {},
        }
        mock_ghsa.return_value = [
            {
                "advisory_id": "GHSA-rust-rust-rust",
                "name": "some-crate",
                "ecosystem": "crates.io",
                "patched_version": "2.0.0",
                "vulnerable_range": "< 2.0.0",
            }
        ]
        mock_osv.return_value = []
        mock_reg.return_value = None  # crates.io not supported → no date

        from manus_agent.tools.get_patch_status import _run_patch_status

        result = _run_patch_status("CVE-2023-11111")
        pkg = result["packages"][0]
        assert pkg["patch_release_date"] == "unknown"
        assert pkg["patch_lag_days"] is None
        assert pkg["patch_lag_label"] == "MISSING"

    @patch("manus_agent.tools.get_patch_status._registry_release_date")
    @patch("manus_agent.tools.get_patch_status._fetch_osv_vulns")
    @patch("manus_agent.tools.get_patch_status._fetch_ghsa_vulns")
    @patch("manus_agent.tools.get_patch_status._fetch_nvd_cve")
    def test_normal_patch_lag(
        self,
        mock_nvd: MagicMock,
        mock_ghsa: MagicMock,
        mock_osv: MagicMock,
        mock_reg: MagicMock,
    ) -> None:
        mock_nvd.return_value = {
            "id": "CVE-2022-00001",
            "published": "2022-03-01T00:00:00.000",
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
        }
        mock_ghsa.return_value = [
            {
                "advisory_id": "GHSA-norm-norm-norm",
                "name": "my-lib",
                "ecosystem": "pypi",
                "patched_version": "3.1.0",
                "vulnerable_range": "< 3.1.0",
            }
        ]
        mock_osv.return_value = []
        # 15 days → NORMAL
        mock_reg.return_value = datetime(2022, 3, 16, tzinfo=timezone.utc)

        from manus_agent.tools.get_patch_status import _run_patch_status

        result = _run_patch_status("CVE-2022-00001")
        pkg = result["packages"][0]
        assert pkg["patch_lag_days"] == 15
        assert pkg["patch_lag_label"] == "NORMAL"
        assert result["severity"] == "HIGH"

    @patch("manus_agent.tools.get_patch_status._registry_release_date")
    @patch("manus_agent.tools.get_patch_status._fetch_osv_vulns")
    @patch("manus_agent.tools.get_patch_status._fetch_ghsa_vulns")
    @patch("manus_agent.tools.get_patch_status._fetch_nvd_cve")
    def test_case_insensitive_cve_id(
        self,
        mock_nvd: MagicMock,
        mock_ghsa: MagicMock,
        mock_osv: MagicMock,
        mock_reg: MagicMock,
    ) -> None:
        """Lower-case or mixed-case CVE IDs should be accepted."""
        mock_nvd.return_value = {
            "id": "CVE-2021-44228",
            "published": "2021-12-10T10:15:09.143",
            "metrics": {},
        }
        mock_ghsa.return_value = []
        mock_osv.return_value = []
        mock_reg.return_value = None

        from manus_agent.tools.get_patch_status import _run_patch_status

        result = _run_patch_status("cve-2021-44228")
        assert result["cve_id"] == "CVE-2021-44228"


# ---------------------------------------------------------------------------
# Unit tests: Strands tool wrapper
# ---------------------------------------------------------------------------


class TestGetPatchStatusTool:
    """Tests for the @tool-decorated get_patch_status function."""

    def _make_tool_use(self, cve_id: str) -> dict:
        return {"toolUseId": "test-tool-use-id-001", "input": {"cve_id": cve_id}}

    @patch("manus_agent.tools.get_patch_status._run_patch_status")
    def test_success_path(self, mock_core: MagicMock) -> None:
        mock_core.return_value = {
            "cve_id": CVE_LOG4SHELL,
            "cve_published": "2021-12-10T10:15:09.143",
            "severity": "CRITICAL",
            "packages": [
                {
                    "name": "org.apache.logging.log4j:log4j-core",
                    "ecosystem": "maven",
                    "patched_version": "2.15.0",
                    "patch_release_date": "2021-12-10",
                    "patch_lag_days": 0,
                    "patch_lag_label": "FAST",
                    "advisory_id": "GHSA-jfh8-c2jp-5v3q",
                }
            ],
            "summary": "CVE-2021-44228 affects 1 package(s). 1 patched. Overall patch lag: FAST.",
        }

        from manus_agent.tools.get_patch_status import get_patch_status

        result = get_patch_status(self._make_tool_use(CVE_LOG4SHELL))
        assert result["status"] == "success"
        assert result["toolUseId"] == "test-tool-use-id-001"
        text = result["content"][0]["text"]
        assert "CVE-2021-44228" in text
        assert "CRITICAL" in text
        assert "FAST" in text
        assert "2.15.0" in text

    @patch("manus_agent.tools.get_patch_status._run_patch_status")
    def test_error_path(self, mock_core: MagicMock) -> None:
        mock_core.return_value = {"error": "Invalid CVE ID: 'BAD-ID'."}
        from manus_agent.tools.get_patch_status import get_patch_status

        result = get_patch_status(self._make_tool_use("BAD-ID"))
        assert result["status"] == "error"
        assert "Invalid CVE ID" in result["content"][0]["text"]

    def test_missing_cve_id(self) -> None:
        from manus_agent.tools.get_patch_status import get_patch_status

        tool_use = {"toolUseId": "test-002", "input": {}}
        result = get_patch_status(tool_use)
        assert result["status"] == "error"
        assert "cve_id is required" in result["content"][0]["text"]

    @patch("manus_agent.tools.get_patch_status._run_patch_status")
    def test_package_with_no_lag_date(self, mock_core: MagicMock) -> None:
        """Verify text output handles None patch_lag_days gracefully."""
        mock_core.return_value = {
            "cve_id": CVE_LOG4SHELL,
            "cve_published": "2021-12-10T10:15:09.143",
            "severity": "CRITICAL",
            "packages": [
                {
                    "name": "some-crate",
                    "ecosystem": "crates.io",
                    "patched_version": "2.0.0",
                    "patch_release_date": "unknown",
                    "patch_lag_days": None,
                    "patch_lag_label": "MISSING",
                    "advisory_id": "GHSA-xxxx-yyyy-zzzz",
                }
            ],
            "summary": "CVE-2021-44228 affects 1 package(s). 1 patched. Overall patch lag: MISSING.",
        }
        from manus_agent.tools.get_patch_status import get_patch_status

        result = get_patch_status(self._make_tool_use(CVE_LOG4SHELL))
        assert result["status"] == "success"
        text = result["content"][0]["text"]
        assert "N/A" in text  # lag_str fallback
        assert "MISSING" in text


# ---------------------------------------------------------------------------
# CLI subcommand tests
# ---------------------------------------------------------------------------


class TestPatchStatusCli:
    """Tests for _build_patch_status_parser and _run_patch_status (CLI)."""

    def test_parser_defaults(self) -> None:
        from manus_agent.cli import _build_patch_status_parser

        p = _build_patch_status_parser()
        args = p.parse_args([CVE_LOG4SHELL])
        assert args.cve_id == CVE_LOG4SHELL
        assert args.output == "text"

    def test_parser_json_output(self) -> None:
        from manus_agent.cli import _build_patch_status_parser

        p = _build_patch_status_parser()
        args = p.parse_args([CVE_LOG4SHELL, "--output", "json"])
        assert args.output == "json"

    @patch("manus_agent.cli._run_patch_status")
    def test_dispatch_in_main(self, mock_run: MagicMock) -> None:
        """Verify 'patch-status' is recognised in main() dispatch."""

        mock_run.return_value = None  # _run_patch_status (CLI fn) returns int
        from manus_agent.cli import _SUBCOMMANDS

        assert "patch-status" in _SUBCOMMANDS

    @patch("manus_agent.tools.get_patch_status._run_patch_status")
    def test_text_output_exit_zero(self, mock_core: MagicMock, capsys: pytest.CaptureFixture) -> None:
        mock_core.return_value = {
            "cve_id": CVE_LOG4SHELL,
            "cve_published": "2021-12-10T10:15:09.143",
            "severity": "CRITICAL",
            "packages": [
                {
                    "name": "org.apache.logging.log4j:log4j-core",
                    "ecosystem": "maven",
                    "patched_version": "2.15.0",
                    "patch_release_date": "2021-12-10",
                    "patch_lag_days": 0,
                    "patch_lag_label": "FAST",
                    "advisory_id": "GHSA-jfh8-c2jp-5v3q",
                }
            ],
            "summary": "CVE-2021-44228 affects 1 package(s). 1 patched. Overall patch lag: FAST.",
        }

        from manus_agent.cli import _run_patch_status as _cli_run

        exit_code = _cli_run([CVE_LOG4SHELL])
        captured = capsys.readouterr()
        assert exit_code == 0
        assert "CVE-2021-44228" in captured.out
        assert "FAST" in captured.out
        assert "2.15.0" in captured.out

    @patch("manus_agent.tools.get_patch_status._run_patch_status")
    def test_json_output(self, mock_core: MagicMock, capsys: pytest.CaptureFixture) -> None:
        mock_core.return_value = {
            "cve_id": CVE_LOG4SHELL,
            "cve_published": "2021-12-10T10:15:09.143",
            "severity": "CRITICAL",
            "packages": [],
            "summary": "No packages.",
        }

        from manus_agent.cli import _run_patch_status as _cli_run

        exit_code = _cli_run([CVE_LOG4SHELL, "--output", "json"])
        captured = capsys.readouterr()
        assert exit_code == 0
        parsed = json.loads(captured.out)
        assert parsed["cve_id"] == CVE_LOG4SHELL

    @patch("manus_agent.tools.get_patch_status._run_patch_status")
    def test_missing_patch_exits_two(self, mock_core: MagicMock, capsys: pytest.CaptureFixture) -> None:
        """Exit code 2 when any package has MISSING patch_lag_label."""
        mock_core.return_value = {
            "cve_id": "CVE-2024-00001",
            "cve_published": "2024-01-01T00:00:00.000",
            "severity": "HIGH",
            "packages": [
                {
                    "name": "unpatched-pkg",
                    "ecosystem": "pypi",
                    "patched_version": "unknown",
                    "patch_release_date": "unknown",
                    "patch_lag_days": None,
                    "patch_lag_label": "MISSING",
                    "advisory_id": "GHSA-no-fix",
                }
            ],
            "summary": "CVE-2024-00001 affects 1 package(s). 1 unpatched.",
        }

        from manus_agent.cli import _run_patch_status as _cli_run

        exit_code = _cli_run(["CVE-2024-00001"])
        assert exit_code == 2

    @patch("manus_agent.tools.get_patch_status._run_patch_status")
    def test_error_result_exits_one(self, mock_core: MagicMock, capsys: pytest.CaptureFixture) -> None:
        mock_core.return_value = {"error": "Invalid CVE ID: 'BAD'."}

        from manus_agent.cli import _run_patch_status as _cli_run

        exit_code = _cli_run(["BAD"])
        assert exit_code == 1

    @patch("manus_agent.tools.get_patch_status._run_patch_status")
    def test_no_packages_exits_zero(self, mock_core: MagicMock, capsys: pytest.CaptureFixture) -> None:
        mock_core.return_value = {
            "cve_id": "CVE-2024-00002",
            "cve_published": "2024-01-01T00:00:00.000",
            "severity": "UNKNOWN",
            "packages": [],
            "summary": "No affected package records found.",
        }

        from manus_agent.cli import _run_patch_status as _cli_run

        exit_code = _cli_run(["CVE-2024-00002"])
        assert exit_code == 0

    def test_advisory_id_omitted_when_empty(self, capsys: pytest.CaptureFixture) -> None:
        """Advisory line should not appear when advisory_id is empty string."""
        with patch("manus_agent.tools.get_patch_status._run_patch_status") as mock_core:
            mock_core.return_value = {
                "cve_id": CVE_LOG4SHELL,
                "cve_published": "2021-12-10T10:15:09.143",
                "severity": "CRITICAL",
                "packages": [
                    {
                        "name": "log4j-core",
                        "ecosystem": "maven",
                        "patched_version": "2.15.0",
                        "patch_release_date": "2021-12-10",
                        "patch_lag_days": 0,
                        "patch_lag_label": "FAST",
                        "advisory_id": "",  # empty
                    }
                ],
                "summary": "1 package, FAST.",
            }

            from manus_agent.cli import _run_patch_status as _cli_run

            _cli_run([CVE_LOG4SHELL])
            out = capsys.readouterr().out
            assert "Advisory" not in out
