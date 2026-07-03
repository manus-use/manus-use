"""
Tests for get_version_range tool.

All HTTP calls are mocked — no real network access.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from manus_agent.tools.get_version_range import (
    _earliest_version,
    _extract_pkg_from_cpe,
    _fetch_ghsa,
    _fetch_nvd,
    _fetch_osv,
    _merge_results,
    _parse_version_tuple,
    get_version_range,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_LOG4J_CVE = "CVE-2021-44228"

# Minimal OSV query response (list of vulns referencing the full record)
_OSV_QUERY_RESP = {"vulns": [{"id": "GHSA-jfh8-c2jp-hdp8"}]}

# Full OSV vuln record for Log4Shell
_OSV_FULL_RESP: dict[str, Any] = {
    "id": "GHSA-jfh8-c2jp-hdp8",
    "affected": [
        {
            "package": {"name": "log4j-core", "ecosystem": "Maven"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "2.0-beta9"},
                        {"fixed": "2.15.0"},
                    ],
                }
            ],
            "versions": ["2.14.1", "2.14.0", "2.13.3", "2.12.2", "2.11.0"],
        }
    ],
}

# NVD response for Log4Shell
_NVD_RESP: dict[str, Any] = {
    "vulnerabilities": [
        {
            "cve": {
                "id": _LOG4J_CVE,
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "2.0",
                                        "versionEndExcluding": "2.15.0",
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        }
    ]
}

# GHSA advisory response
_GHSA_RESP: list[dict[str, Any]] = [
    {
        "ghsa_id": "GHSA-jfh8-c2jp-hdp8",
        "vulnerabilities": [
            {
                "package": {"name": "log4j-core", "ecosystem": "maven"},
                "vulnerable_version_range": ">=2.0-beta9, <2.15.0",
                "patched_versions": ">=2.15.0",
            }
        ],
    }
]


def _make_response(data: Any, status: int = 200) -> MagicMock:
    """Create a mock requests.Response-like object."""
    mock = MagicMock()
    mock.status_code = status
    mock.json.return_value = data
    mock.raise_for_status = MagicMock()
    return mock


# ---------------------------------------------------------------------------
# _parse_version_tuple
# ---------------------------------------------------------------------------


class TestParseVersionTuple:
    def test_simple_semver(self):
        assert _parse_version_tuple("2.15.0") == (2, 15, 0)

    def test_major_only(self):
        assert _parse_version_tuple("3") == (3,)

    def test_prerelease_stripped(self):
        assert _parse_version_tuple("2.0-beta9") == (2, 0)

    def test_build_meta_stripped(self):
        assert _parse_version_tuple("1.2.3+build.1") == (1, 2, 3)

    def test_non_numeric_component(self):
        result = _parse_version_tuple("1.0.rc1")
        # rc1 can't be int; treated as 0
        assert result[0] == 1

    def test_empty_string(self):
        # empty string splits to [""] which becomes [0], so result is (0,)
        assert _parse_version_tuple("") == (0,)


# ---------------------------------------------------------------------------
# _earliest_version
# ---------------------------------------------------------------------------


class TestEarliestVersion:
    def test_picks_lowest(self):
        assert _earliest_version(["2.15.0", "2.3.1", "1.0.0"]) == "1.0.0"

    def test_single_element(self):
        assert _earliest_version(["3.0.0"]) == "3.0.0"

    def test_empty_list(self):
        assert _earliest_version([]) is None

    def test_deduplication(self):
        assert _earliest_version(["1.0.0", "1.0.0", "2.0.0"]) == "1.0.0"

    def test_ignores_empty_strings(self):
        assert _earliest_version(["", "2.0.0", ""]) == "2.0.0"

    def test_all_empty(self):
        assert _earliest_version(["", ""]) is None

    def test_prerelease(self):
        # 2.0-beta9 → (2, 0) < (2, 15, 0)
        assert _earliest_version(["2.15.0", "2.0-beta9"]) == "2.0-beta9"


# ---------------------------------------------------------------------------
# _extract_pkg_from_cpe
# ---------------------------------------------------------------------------


class TestExtractPkgFromCpe:
    def test_apache_log4j(self):
        cpe = "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"
        assert _extract_pkg_from_cpe(cpe) == "log4j"

    def test_short_cpe_returns_empty(self):
        assert _extract_pkg_from_cpe("cpe:2.3") == ""

    def test_empty_string(self):
        assert _extract_pkg_from_cpe("") == ""

    def test_vendor_and_product(self):
        cpe = "cpe:2.3:a:redhat:openssl:1.0:*:*:*:*:*:*:*"
        assert _extract_pkg_from_cpe(cpe) == "openssl"


# ---------------------------------------------------------------------------
# _fetch_osv
# ---------------------------------------------------------------------------


class TestFetchOSV:
    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_returns_ranges_for_log4shell(self, mock_post, mock_get):
        # _post(_OSV_QUERY_URL, {id: cve_id}) → list of vuln IDs
        mock_post.return_value = _make_response(_OSV_QUERY_RESP)
        # _get(_OSV_VULN_URL.format(vuln_id)) → full record
        mock_get.return_value = _make_response(_OSV_FULL_RESP)

        result = _fetch_osv(_LOG4J_CVE)

        assert result["package_name"] == "log4j-core"
        assert result["ecosystem"] == "Maven"
        assert result["first_patched_version"] == "2.15.0"
        assert len(result["ranges"]) >= 1
        rng = result["ranges"][0]
        assert rng["fixed"] == "2.15.0"
        assert rng["introduced"] == "2.0-beta9"
        assert rng["source"] == "osv"

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_affected_versions_populated(self, mock_post, mock_get):
        mock_post.return_value = _make_response(_OSV_QUERY_RESP)
        mock_get.return_value = _make_response(_OSV_FULL_RESP)

        result = _fetch_osv(_LOG4J_CVE)
        assert "2.14.1" in result["affected_versions"]
        assert len(result["affected_versions"]) <= 20

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_ecosystem_filter_excludes_non_matching(self, mock_post, mock_get):
        mock_post.return_value = _make_response(_OSV_QUERY_RESP)
        mock_get.return_value = _make_response(_OSV_FULL_RESP)

        # Filter for pypi — Maven entry should be excluded
        result = _fetch_osv(_LOG4J_CVE, ecosystem_filter="pypi")
        assert result["ecosystem"] == "unknown"
        assert result["ranges"] == []

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_ecosystem_filter_includes_matching(self, mock_post, mock_get):
        mock_post.return_value = _make_response(_OSV_QUERY_RESP)
        mock_get.return_value = _make_response(_OSV_FULL_RESP)

        # Filter for maven — Maven entry should be included
        result = _fetch_osv(_LOG4J_CVE, ecosystem_filter="maven")
        assert result["ecosystem"] == "Maven"
        assert len(result["ranges"]) >= 1

    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_empty_vulns_returns_default(self, mock_post):
        mock_post.return_value = _make_response({"vulns": []})

        result = _fetch_osv("CVE-2099-9999")
        assert result["ranges"] == []
        assert result["first_patched_version"] is None

    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_network_error_raises(self, mock_post):
        """_fetch_osv raises on initial query failure; caller records the error."""
        mock_post.side_effect = Exception("connection refused")

        with pytest.raises(Exception, match="connection refused"):
            _fetch_osv("CVE-2099-9999")

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_range_without_introduced(self, mock_post, mock_get):
        vuln = {
            "affected": [
                {
                    "package": {"name": "requests", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"fixed": "2.31.0"}],
                        }
                    ],
                    "versions": [],
                }
            ]
        }
        mock_post.return_value = _make_response({"vulns": [{"id": "GHSA-test"}]})
        mock_get.return_value = _make_response(vuln)

        result = _fetch_osv("CVE-2023-9999")
        assert result["ranges"][0]["introduced"] is None
        assert result["ranges"][0]["fixed"] == "2.31.0"

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_range_with_zero_introduced_excluded(self, mock_post, mock_get):
        """OSV uses 'introduced: 0' as 'beginning of time'; should not become introduced value."""
        vuln = {
            "affected": [
                {
                    "package": {"name": "flask", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                        }
                    ],
                    "versions": [],
                }
            ]
        }
        mock_post.return_value = _make_response({"vulns": [{"id": "GHSA-test"}]})
        mock_get.return_value = _make_response(vuln)

        result = _fetch_osv("CVE-2021-9999")
        assert result["ranges"][0]["introduced"] is None

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_multiple_affected_packages(self, mock_post, mock_get):
        """Multiple packages in one OSV record — picks the first as primary."""
        vuln = {
            "affected": [
                {
                    "package": {"name": "pkg-a", "ecosystem": "PyPI"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0"}, {"fixed": "1.5"}]}],
                    "versions": ["1.0", "1.1"],
                },
                {
                    "package": {"name": "pkg-b", "ecosystem": "npm"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "2.0"}, {"fixed": "2.1"}]}],
                    "versions": ["2.0"],
                },
            ]
        }
        mock_post.return_value = _make_response({"vulns": [{"id": "GHSA-multi"}]})
        mock_get.return_value = _make_response(vuln)

        result = _fetch_osv("CVE-2022-1234")
        assert result["package_name"] == "pkg-a"
        assert len(result["ranges"]) == 2

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_get_failure_skips_vuln(self, mock_post, mock_get):
        """If the full vuln GET fails, it is silently skipped."""
        mock_post.return_value = _make_response({"vulns": [{"id": "GHSA-bad"}]})
        mock_get.side_effect = Exception("timeout")

        result = _fetch_osv("CVE-2024-1111")
        assert result["ranges"] == []

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_affected_versions_capped_at_20(self, mock_post, mock_get):
        """Affected versions list should never exceed 20 entries."""
        versions = [f"1.{i}.0" for i in range(50)]
        vuln = {
            "affected": [
                {
                    "package": {"name": "bigpkg", "ecosystem": "PyPI"},
                    "ranges": [],
                    "versions": versions,
                }
            ]
        }
        mock_post.return_value = _make_response({"vulns": [{"id": "GHSA-big"}]})
        mock_get.return_value = _make_response(vuln)

        result = _fetch_osv("CVE-2023-8888")
        assert len(result["affected_versions"]) <= 20


# ---------------------------------------------------------------------------
# _fetch_nvd
# ---------------------------------------------------------------------------


class TestFetchNVD:
    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_extracts_version_range(self, mock_get):
        mock_get.return_value = _make_response(_NVD_RESP)

        result = _fetch_nvd(_LOG4J_CVE)

        assert len(result["ranges"]) >= 1
        rng = result["ranges"][0]
        assert rng["source"] == "nvd"
        assert rng["introduced"] == "2.0"
        assert rng["fixed"] == "2.15.0"
        assert rng["range_type"] == "VERSION"
        assert result["first_patched_version"] == "2.15.0"

    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_no_vulnerabilities_returns_empty(self, mock_get):
        mock_get.return_value = _make_response({"vulnerabilities": []})

        result = _fetch_nvd("CVE-2099-1")
        assert result["ranges"] == []
        assert result["first_patched_version"] is None

    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_network_error_raises(self, mock_get):
        """_fetch_nvd raises on network failure; caller records the error."""
        mock_get.side_effect = Exception("timeout")

        with pytest.raises(Exception, match="timeout"):
            _fetch_nvd("CVE-2099-2")

    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_cpe_without_version_start(self, mock_get):
        nvd = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1111",
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                                "versionEndExcluding": "3.0.0",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                }
            ]
        }
        mock_get.return_value = _make_response(nvd)

        result = _fetch_nvd("CVE-2024-1111")
        assert result["ranges"][0]["introduced"] is None
        assert result["ranges"][0]["fixed"] == "3.0.0"

    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_non_vulnerable_cpe_excluded(self, mock_get):
        nvd = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-2222",
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "vulnerable": False,
                                                "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                                                "versionEndExcluding": "2.0.0",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                }
            ]
        }
        mock_get.return_value = _make_response(nvd)

        result = _fetch_nvd("CVE-2024-2222")
        # Non-vulnerable entries should be skipped
        assert result["ranges"] == []

    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_version_end_including_produces_no_fixed(self, mock_get):
        """versionEndIncluding cannot infer the first patched version."""
        nvd = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-3333",
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:a:b:*:*:*:*:*:*:*:*",
                                                "versionStartIncluding": "1.0",
                                                "versionEndIncluding": "1.9",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                }
            ]
        }
        mock_get.return_value = _make_response(nvd)

        result = _fetch_nvd("CVE-2024-3333")
        assert result["ranges"][0]["fixed"] is None
        assert result["first_patched_version"] is None

    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_package_name_extracted_from_cpe(self, mock_get):
        mock_get.return_value = _make_response(_NVD_RESP)

        result = _fetch_nvd(_LOG4J_CVE)
        assert result["ranges"][0]["package"] == "log4j"

    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_multiple_cpe_entries(self, mock_get):
        nvd = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-4444",
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                                "versionStartIncluding": "1.0",
                                                "versionEndExcluding": "1.5",
                                            },
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                                "versionStartIncluding": "2.0",
                                                "versionEndExcluding": "2.3",
                                            },
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                }
            ]
        }
        mock_get.return_value = _make_response(nvd)

        result = _fetch_nvd("CVE-2024-4444")
        assert len(result["ranges"]) == 2
        assert result["first_patched_version"] == "1.5"  # earliest of 1.5 and 2.3


# ---------------------------------------------------------------------------
# _fetch_ghsa
# ---------------------------------------------------------------------------


class TestFetchGHSA:
    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_extracts_patched_version(self, mock_get):
        mock_get.return_value = _make_response(_GHSA_RESP)

        result = _fetch_ghsa(_LOG4J_CVE)

        assert result["package_name"] == "log4j-core"
        assert result["first_patched_version"] == "2.15.0"
        assert len(result["ranges"]) >= 1

    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_empty_advisories(self, mock_get):
        mock_get.return_value = _make_response([])

        result = _fetch_ghsa("CVE-2099-99")
        assert result["ranges"] == []
        assert result["first_patched_version"] is None

    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_network_error_raises(self, mock_get):
        """_fetch_ghsa raises on network failure; caller records the error."""
        mock_get.side_effect = Exception("connection error")

        with pytest.raises(Exception, match="connection error"):
            _fetch_ghsa("CVE-2099-99")

    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_ghsa_range_parsing(self, mock_get):
        advisory = [
            {
                "ghsa_id": "GHSA-test",
                "vulnerabilities": [
                    {
                        "package": {"name": "mypkg", "ecosystem": "npm"},
                        "vulnerable_version_range": ">=1.0.0, <3.0.0",
                        "patched_versions": ">=3.0.0",
                    }
                ],
            }
        ]
        mock_get.return_value = _make_response(advisory)

        result = _fetch_ghsa("CVE-2023-5555")
        assert result["package_name"] == "mypkg"
        assert result["ecosystem"] == "npm"
        rng = result["ranges"][0]
        assert rng["introduced"] == "1.0.0"
        assert rng["fixed"] == "3.0.0"
        assert result["first_patched_version"] == "3.0.0"

    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_patched_versions_without_range(self, mock_get):
        """patched_versions alone (no vulnerable_version_range) still populates first_patched."""
        advisory = [
            {
                "ghsa_id": "GHSA-norange",
                "vulnerabilities": [
                    {
                        "package": {"name": "mypkg", "ecosystem": "pypi"},
                        "vulnerable_version_range": "",
                        "patched_versions": ">=1.2.3",
                    }
                ],
            }
        ]
        mock_get.return_value = _make_response(advisory)

        result = _fetch_ghsa("CVE-2023-6666")
        assert result["first_patched_version"] == "1.2.3"

    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_multiple_advisories_picks_earliest_patched(self, mock_get):
        advisories = [
            {
                "ghsa_id": "GHSA-a",
                "vulnerabilities": [
                    {
                        "package": {"name": "pkg", "ecosystem": "npm"},
                        "vulnerable_version_range": ">=1.0.0, <3.0.0",
                        "patched_versions": ">=3.0.0",
                    }
                ],
            },
            {
                "ghsa_id": "GHSA-b",
                "vulnerabilities": [
                    {
                        "package": {"name": "pkg", "ecosystem": "npm"},
                        "vulnerable_version_range": ">=0.5.0, <2.1.0",
                        "patched_versions": ">=2.1.0",
                    }
                ],
            },
        ]
        mock_get.return_value = _make_response(advisories)

        result = _fetch_ghsa("CVE-2024-7777")
        assert result["first_patched_version"] == "2.1.0"

    @patch("manus_agent.tools.get_version_range.requests.get")
    def test_ecosystem_normalised(self, mock_get):
        advisory = [
            {
                "ghsa_id": "GHSA-eco",
                "vulnerabilities": [
                    {
                        "package": {"name": "pkg", "ecosystem": "PyPI"},
                        "vulnerable_version_range": ">=1.0, <2.0",
                        "patched_versions": ">=2.0",
                    }
                ],
            }
        ]
        mock_get.return_value = _make_response(advisory)

        result = _fetch_ghsa("CVE-2024-8888")
        assert result["ecosystem"] == "PyPI"  # lowercase normalised


# ---------------------------------------------------------------------------
# _merge_results
# ---------------------------------------------------------------------------


class TestMergeResults:
    def _empty(self) -> dict:
        return {
            "ranges": [],
            "first_patched_version": None,
            "affected_versions": [],
            "package_name": "",
            "ecosystem": "unknown",
        }

    def test_combines_ranges(self):
        osv = {
            **self._empty(),
            "ranges": [
                {
                    "introduced": "1.0",
                    "fixed": "1.5",
                    "range_type": "SEMVER",
                    "source": "osv",
                    "package": "pkg",
                    "ecosystem": "PyPI",
                }
            ],
        }
        nvd = {
            **self._empty(),
            "ranges": [
                {
                    "introduced": "1.0",
                    "fixed": "1.5",
                    "range_type": "VERSION",
                    "source": "nvd",
                    "package": "pkg",
                    "ecosystem": "unknown",
                }
            ],
        }
        ghsa = self._empty()

        merged = _merge_results(osv, nvd, ghsa)
        assert len(merged["ranges"]) == 2

    def test_deduplicates_identical_ranges(self):
        rng = {
            "introduced": "1.0",
            "fixed": "1.5",
            "range_type": "SEMVER",
            "source": "osv",
            "package": "pkg",
            "ecosystem": "PyPI",
        }
        osv = {**self._empty(), "ranges": [rng, rng]}
        merged = _merge_results(osv, self._empty(), self._empty())
        assert len(merged["ranges"]) == 1

    def test_picks_earliest_first_patched(self):
        osv = {**self._empty(), "first_patched_version": "2.15.0"}
        nvd = {**self._empty(), "first_patched_version": "2.14.99"}
        ghsa = {**self._empty(), "first_patched_version": "3.0.0"}

        merged = _merge_results(osv, nvd, ghsa)
        assert merged["first_patched_version"] == "2.14.99"

    def test_all_sources_empty_gives_none_patched(self):
        merged = _merge_results(self._empty(), self._empty(), self._empty())
        assert merged["first_patched_version"] is None

    def test_package_name_preference_osv_over_ghsa(self):
        osv = {**self._empty(), "package_name": "osv-pkg"}
        ghsa = {**self._empty(), "package_name": "ghsa-pkg"}
        merged = _merge_results(osv, self._empty(), ghsa)
        assert merged["package_name"] == "osv-pkg"

    def test_package_name_falls_back_to_ghsa(self):
        ghsa = {**self._empty(), "package_name": "ghsa-only"}
        merged = _merge_results(self._empty(), self._empty(), ghsa)
        assert merged["package_name"] == "ghsa-only"

    def test_ecosystem_preference_osv(self):
        osv = {**self._empty(), "ecosystem": "PyPI"}
        ghsa = {**self._empty(), "ecosystem": "npm"}
        merged = _merge_results(osv, self._empty(), ghsa)
        assert merged["ecosystem"] == "PyPI"

    def test_ecosystem_falls_back_to_ghsa(self):
        ghsa = {**self._empty(), "ecosystem": "npm"}
        merged = _merge_results(self._empty(), self._empty(), ghsa)
        assert merged["ecosystem"] == "npm"

    def test_all_sources_populated_correctly(self):
        osv = {
            **self._empty(),
            "ranges": [
                {
                    "introduced": "1.0",
                    "fixed": "2.0",
                    "range_type": "SEMVER",
                    "source": "osv",
                    "package": "x",
                    "ecosystem": "PyPI",
                }
            ],
        }
        nvd = {
            **self._empty(),
            "ranges": [
                {
                    "introduced": "1.0",
                    "fixed": "2.0",
                    "range_type": "VERSION",
                    "source": "nvd",
                    "package": "x",
                    "ecosystem": "unknown",
                }
            ],
        }
        ghsa = {
            **self._empty(),
            "ranges": [
                {
                    "introduced": "1.0",
                    "fixed": "2.0",
                    "range_type": "SEMVER",
                    "source": "ghsa",
                    "package": "x",
                    "ecosystem": "PyPI",
                }
            ],
        }

        merged = _merge_results(osv, nvd, ghsa)
        assert "osv" in merged["all_sources"]
        assert "nvd" in merged["all_sources"]
        assert "ghsa" in merged["all_sources"]

    def test_no_sources_returns_empty_all_sources(self):
        merged = _merge_results(self._empty(), self._empty(), self._empty())
        assert merged["all_sources"] == []

    def test_affected_versions_combined(self):
        osv = {**self._empty(), "affected_versions": ["1.0", "1.1", "1.2"]}
        merged = _merge_results(osv, self._empty(), self._empty())
        assert set(merged["affected_versions"]) >= {"1.0", "1.1", "1.2"}


# ---------------------------------------------------------------------------
# get_version_range (integration-level, all HTTP mocked)
# ---------------------------------------------------------------------------


class TestGetVersionRange:
    def _patch_all(self, osv_query=None, osv_full=None, nvd=None, ghsa=None):
        """Return a stack of patches for a full run."""
        osv_query = osv_query or _OSV_QUERY_RESP
        osv_full = osv_full or _OSV_FULL_RESP
        nvd = nvd or _NVD_RESP
        ghsa = ghsa or _GHSA_RESP

        post_mock = MagicMock(side_effect=lambda url, **kw: _make_response(osv_query))
        get_mock = MagicMock(
            side_effect=lambda url, **kw: _make_response(
                osv_full if "osv.dev" in url else (nvd if "nvd.nist.gov" in url else ghsa)
            )
        )
        return post_mock, get_mock

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_full_log4shell_run(self, mock_post, mock_get):
        mock_post.return_value = _make_response(_OSV_QUERY_RESP)
        mock_get.side_effect = lambda url, **kw: _make_response(
            _OSV_FULL_RESP if "osv.dev" in url else (_NVD_RESP if "nvd.nist.gov" in url else _GHSA_RESP)
        )

        result = get_version_range(cve_id=_LOG4J_CVE)

        assert result["cve_id"] == _LOG4J_CVE
        assert result["first_patched_version"] == "2.15.0"
        assert result["ecosystem"] == "Maven"
        assert result["package_name"] == "log4j-core"
        assert isinstance(result["vulnerable_ranges"], list)
        assert len(result["vulnerable_ranges"]) >= 1
        assert isinstance(result["errors"], list)

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_cve_id_normalised_to_upper(self, mock_post, mock_get):
        mock_post.return_value = _make_response({"vulns": []})
        mock_get.return_value = _make_response({"vulnerabilities": []})

        result = get_version_range(cve_id="cve-2021-44228")
        assert result["cve_id"] == "CVE-2021-44228"

    def test_invalid_cve_id_returns_error(self):
        result = get_version_range(cve_id="NOT-A-CVE")
        assert "error" in result

    def test_empty_cve_id_returns_error(self):
        result = get_version_range(cve_id="")
        assert "error" in result

    def test_non_string_cve_id_returns_error(self):
        result = get_version_range(cve_id=None)  # type: ignore[arg-type]
        assert "error" in result

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_ecosystem_auto_default(self, mock_post, mock_get):
        mock_post.return_value = _make_response({"vulns": []})
        mock_get.return_value = _make_response({"vulnerabilities": []})

        result = get_version_range(cve_id=_LOG4J_CVE)
        assert "error" not in result  # no error key
        assert result.get("cve_id") == _LOG4J_CVE

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_ecosystem_filter_passed_through(self, mock_post, mock_get):
        mock_post.return_value = _make_response({"vulns": []})
        mock_get.return_value = _make_response({"vulnerabilities": []})

        result = get_version_range(cve_id=_LOG4J_CVE, ecosystem="pypi")
        assert result["cve_id"] == _LOG4J_CVE

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_all_sources_fail_gracefully(self, mock_post, mock_get):
        mock_post.side_effect = Exception("all down")
        mock_get.side_effect = Exception("all down")

        result = get_version_range(cve_id=_LOG4J_CVE)
        assert result["cve_id"] == _LOG4J_CVE
        assert result["first_patched_version"] is None
        assert result["vulnerable_ranges"] == []
        assert len(result["errors"]) > 0  # errors logged

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_public_range_keys(self, mock_post, mock_get):
        mock_post.return_value = _make_response(_OSV_QUERY_RESP)
        mock_get.side_effect = lambda url, **kw: _make_response(
            _OSV_FULL_RESP if "osv.dev" in url else (_NVD_RESP if "nvd.nist.gov" in url else _GHSA_RESP)
        )

        result = get_version_range(cve_id=_LOG4J_CVE)
        for rng in result["vulnerable_ranges"]:
            # Internal keys (package, ecosystem on range) must NOT be in public output
            assert "introduced" in rng
            assert "fixed" in rng
            assert "range_type" in rng
            assert "source" in rng

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_output_keys_complete(self, mock_post, mock_get):
        mock_post.return_value = _make_response({"vulns": []})
        mock_get.return_value = _make_response({"vulnerabilities": []})

        result = get_version_range(cve_id=_LOG4J_CVE)
        required_keys = {
            "cve_id",
            "ecosystem",
            "package_name",
            "vulnerable_ranges",
            "first_patched_version",
            "affected_versions",
            "all_sources",
            "errors",
        }
        assert required_keys <= set(result.keys())

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_json_serializable(self, mock_post, mock_get):
        """Result must be fully JSON-serialisable (no sets, custom objects, etc.)."""
        mock_post.return_value = _make_response(_OSV_QUERY_RESP)
        mock_get.side_effect = lambda url, **kw: _make_response(
            _OSV_FULL_RESP if "osv.dev" in url else (_NVD_RESP if "nvd.nist.gov" in url else _GHSA_RESP)
        )

        result = get_version_range(cve_id=_LOG4J_CVE)
        serialised = json.dumps(result)  # should not raise
        assert serialised

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_unknown_cve_returns_empty_ranges(self, mock_post, mock_get):
        mock_post.return_value = _make_response({"vulns": []})
        mock_get.return_value = _make_response({"vulnerabilities": []})

        result = get_version_range(cve_id="CVE-2099-99999")
        assert result["vulnerable_ranges"] == []
        assert result["first_patched_version"] is None
        assert result["ecosystem"] == "unknown"

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_osv_only_source_works(self, mock_post, mock_get):
        """When NVD and GHSA both fail, OSV data still populates the result."""
        mock_post.return_value = _make_response(_OSV_QUERY_RESP)

        def selective_get(url, **kw):
            if "osv.dev" in url:
                return _make_response(_OSV_FULL_RESP)
            raise Exception("simulated failure")

        mock_get.side_effect = selective_get

        result = get_version_range(cve_id=_LOG4J_CVE)
        assert result["first_patched_version"] == "2.15.0"
        assert len(result["errors"]) >= 2  # NVD + GHSA errors recorded

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_nvd_only_source_works(self, mock_post, mock_get):
        """When OSV and GHSA both fail, NVD data still populates the result."""
        mock_post.side_effect = Exception("osv down")

        def selective_get(url, **kw):
            if "nvd.nist.gov" in url:
                return _make_response(_NVD_RESP)
            raise Exception("simulated failure")

        mock_get.side_effect = selective_get

        result = get_version_range(cve_id=_LOG4J_CVE)
        assert result["first_patched_version"] == "2.15.0"

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_affected_versions_in_output(self, mock_post, mock_get):
        mock_post.return_value = _make_response(_OSV_QUERY_RESP)
        mock_get.side_effect = lambda url, **kw: _make_response(
            _OSV_FULL_RESP if "osv.dev" in url else (_NVD_RESP if "nvd.nist.gov" in url else _GHSA_RESP)
        )

        result = get_version_range(cve_id=_LOG4J_CVE)
        assert isinstance(result["affected_versions"], list)
        assert len(result["affected_versions"]) > 0

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_all_sources_list_in_output(self, mock_post, mock_get):
        mock_post.return_value = _make_response(_OSV_QUERY_RESP)
        mock_get.side_effect = lambda url, **kw: _make_response(
            _OSV_FULL_RESP if "osv.dev" in url else (_NVD_RESP if "nvd.nist.gov" in url else _GHSA_RESP)
        )

        result = get_version_range(cve_id=_LOG4J_CVE)
        assert "osv" in result["all_sources"]


# ---------------------------------------------------------------------------
# CLI tests (import and dispatch)
# ---------------------------------------------------------------------------


class TestCLIVersionRange:
    """Smoke-test the CLI integration without full subprocess overhead."""

    def test_cli_module_importable(self):
        from manus_agent import cli  # noqa: F401

    def test_build_version_range_parser_exists(self):
        from manus_agent.cli import _build_version_range_parser

        p = _build_version_range_parser()
        assert p is not None

    def test_parser_accepts_cve_id(self):
        from manus_agent.cli import _build_version_range_parser

        p = _build_version_range_parser()
        args = p.parse_args(["CVE-2021-44228"])
        assert args.cve_id == "CVE-2021-44228"

    def test_parser_accepts_ecosystem_flag(self):
        from manus_agent.cli import _build_version_range_parser

        p = _build_version_range_parser()
        args = p.parse_args(["CVE-2021-44228", "--ecosystem", "pypi"])
        assert args.ecosystem == "pypi"

    def test_parser_accepts_output_flag(self):
        from manus_agent.cli import _build_version_range_parser

        p = _build_version_range_parser()
        args = p.parse_args(["CVE-2021-44228", "--output", "json"])
        assert args.output == "json"

    def test_parser_defaults(self):
        from manus_agent.cli import _build_version_range_parser

        p = _build_version_range_parser()
        args = p.parse_args(["CVE-2021-44228"])
        assert args.ecosystem == "auto"
        assert args.output == "text"

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_run_version_range_json_exit_0(self, mock_post, mock_get, capsys):
        from manus_agent.cli import _run_version_range

        mock_post.return_value = _make_response({"vulns": []})
        mock_get.return_value = _make_response({"vulnerabilities": []})

        rc = _run_version_range(["CVE-2021-44228", "--output", "json"])
        assert rc == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["cve_id"] == "CVE-2021-44228"

    @patch("manus_agent.tools.get_version_range.requests.get")
    @patch("manus_agent.tools.get_version_range.requests.post")
    def test_run_version_range_text_exit_0(self, mock_post, mock_get, capsys):
        from manus_agent.cli import _run_version_range

        mock_post.return_value = _make_response({"vulns": []})
        mock_get.return_value = _make_response({"vulnerabilities": []})

        rc = _run_version_range(["CVE-2021-44228"])
        assert rc == 0

    def test_run_version_range_empty_cve_id(self, capsys):
        from manus_agent.cli import _run_version_range

        rc = _run_version_range([""])
        assert rc == 1

    def test_run_version_range_invalid_cve_format(self, capsys):
        from manus_agent.cli import _run_version_range

        rc = _run_version_range(["NOT-A-CVE"])
        assert rc == 1

    def test_version_range_in_subcommands_set(self):
        from manus_agent.cli import _SUBCOMMANDS

        assert "version-range" in _SUBCOMMANDS

    @patch("manus_agent.cli._run_version_range")
    def test_main_dispatches_version_range(self, mock_run):
        import sys
        from unittest.mock import patch as upatch

        mock_run.return_value = 0

        with upatch.object(sys, "argv", ["manus-agent", "version-range", "CVE-2021-44228"]):
            try:
                from manus_agent.cli import main

                main()
            except SystemExit as e:
                assert e.code == 0
        mock_run.assert_called_once_with(["CVE-2021-44228"])
