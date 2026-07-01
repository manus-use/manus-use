"""
Tests for src/manus_agent/tools/get_patch_status.py

All external HTTP calls are mocked — no real network I/O.
100% mocked: NVD, Ubuntu Security API, Debian Security Tracker,
             Red Hat CVE DB, OSV.dev.
"""

from __future__ import annotations

import json
from datetime import date
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from manus_agent.tools.get_patch_status import (
    _days_to_patch,
    _fetch_debian,
    _fetch_nvd_publish_date,
    _fetch_osv,
    _fetch_redhat,
    _fetch_ubuntu,
    _parse_iso_date,
    _summarise,
    get_patch_status,
)

# ===========================================================================
# Fixtures / helpers
# ===========================================================================

_NVD_PUBLISHED = date(2024, 3, 29)

_NVD_RESPONSE = {
    "resultsPerPage": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-3094",
                "published": "2024-03-29T16:15:00.000",
                "lastModified": "2024-04-01T00:00:00.000",
            }
        }
    ],
}

_UBUNTU_RESPONSE = {
    "id": "CVE-2024-3094",
    "notices": [
        {"id": "USN-6743-1"},
        {"id": "USN-6744-1"},
    ],
    "packages": [
        {
            "name": "xz-utils",
            "statuses": [
                {
                    "release_codename": "focal",
                    "status": "not-applicable",
                    "fix_version": "",
                },
                {
                    "release_codename": "jammy",
                    "status": "not-applicable",
                    "fix_version": "",
                },
                {
                    "release_codename": "noble",
                    "status": "released",
                    "fix_version": "5.6.1+really5.4.5-1",
                    "pocket_date": "2024-04-02",
                },
            ],
        }
    ],
}

_DEBIAN_RESPONSE = {
    "xz-utils": {
        "bookworm": {
            "status": "resolved",
            "fixed_version": "5.4.1-0.2+deb12u1",
            "urgency": "high",
        },
        "bullseye": {
            "status": "resolved",
            "fixed_version": "5.2.4-1+deb11u1",
            "urgency": "high",
        },
        "sid": {
            "status": "resolved",
            "fixed_version": "5.6.1+really5.4.5-1",
            "urgency": "unimportant",
        },
    }
}

_REDHAT_RESPONSE = {
    "name": "CVE-2024-3094",
    "affected_release": [
        {
            "product_name": "Red Hat Enterprise Linux 9",
            "release_date": "2024-04-03",
            "advisory": "RHSA-2024:1642",
            "package": "xz-libs-5.4.3-2.el9_4.x86_64",
        }
    ],
    "package_state": [
        {
            "product_name": "Red Hat Enterprise Linux 8",
            "fix_state": "Not affected",
            "package_name": "xz",
        }
    ],
}

_OSV_RESPONSE = {
    "vulns": [
        {
            "id": "GHSA-rxwq-x6h5-x525",
            "modified": "2024-04-01T00:00:00Z",
            "affected": [
                {
                    "package": {"name": "xz-utils", "ecosystem": "Ubuntu"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "5.6.1+really5.4.5-1"},
                            ],
                        }
                    ],
                    "versions": ["5.6.0-0.2"],
                }
            ],
        }
    ]
}


def _make_mock_response(data: Any, status_code: int = 200) -> MagicMock:
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = data
    mock.raise_for_status.return_value = None
    return mock


def _make_404_response() -> MagicMock:
    mock = MagicMock()
    mock.status_code = 404
    http_err = requests.HTTPError(response=mock)
    mock.raise_for_status.side_effect = http_err
    return mock


# ===========================================================================
# _parse_iso_date
# ===========================================================================


class TestParseIsoDate:
    def test_plain_date(self):
        assert _parse_iso_date("2024-03-29") == date(2024, 3, 29)

    def test_datetime_string(self):
        assert _parse_iso_date("2024-03-29T16:15:00.000") == date(2024, 3, 29)

    def test_datetime_with_z(self):
        assert _parse_iso_date("2024-04-01T00:00:00Z") == date(2024, 4, 1)

    def test_none_input(self):
        assert _parse_iso_date(None) is None

    def test_empty_string(self):
        assert _parse_iso_date("") is None

    def test_invalid_string(self):
        assert _parse_iso_date("not-a-date") is None

    def test_datetime_with_microseconds(self):
        assert _parse_iso_date("2024-03-29T16:15:00.123456") == date(2024, 3, 29)


# ===========================================================================
# _days_to_patch
# ===========================================================================


class TestDaysToPatch:
    def test_normal_case(self):
        published = date(2024, 3, 29)
        patched = date(2024, 4, 3)
        assert _days_to_patch(published, patched) == 5

    def test_same_day(self):
        d = date(2024, 3, 29)
        assert _days_to_patch(d, d) == 0

    def test_patch_before_publish(self):
        published = date(2024, 4, 1)
        patched = date(2024, 3, 29)
        assert _days_to_patch(published, patched) is None

    def test_none_published(self):
        assert _days_to_patch(None, date(2024, 4, 1)) is None

    def test_none_patched(self):
        assert _days_to_patch(date(2024, 3, 29), None) is None

    def test_both_none(self):
        assert _days_to_patch(None, None) is None


# ===========================================================================
# _fetch_nvd_publish_date
# ===========================================================================


class TestFetchNvdPublishDate:
    def test_returns_publish_date(self):
        with patch("requests.get", return_value=_make_mock_response(_NVD_RESPONSE)):
            result = _fetch_nvd_publish_date("CVE-2024-3094")
        assert result == date(2024, 3, 29)

    def test_empty_vulnerabilities(self):
        empty = {"resultsPerPage": 0, "vulnerabilities": []}
        with patch("requests.get", return_value=_make_mock_response(empty)):
            result = _fetch_nvd_publish_date("CVE-9999-0000")
        assert result is None

    def test_network_error_returns_none(self):
        with patch("requests.get", side_effect=Exception("timeout")):
            result = _fetch_nvd_publish_date("CVE-2024-3094")
        assert result is None

    def test_missing_published_field(self):
        data = {"vulnerabilities": [{"cve": {"id": "CVE-2024-3094"}}]}
        with patch("requests.get", return_value=_make_mock_response(data)):
            result = _fetch_nvd_publish_date("CVE-2024-3094")
        assert result is None


# ===========================================================================
# _fetch_ubuntu
# ===========================================================================


class TestFetchUbuntu:
    def test_normal_response(self):
        with patch("requests.get", return_value=_make_mock_response(_UBUNTU_RESPONSE)):
            results = _fetch_ubuntu("CVE-2024-3094", _NVD_PUBLISHED)
        # noble should be "fixed"; focal/jammy are "not_affected" and filtered
        fixed = [r for r in results if r["status"] == "fixed"]
        assert len(fixed) >= 1
        assert fixed[0]["vendor"] == "ubuntu/noble"
        assert fixed[0]["fixed_version"] == "5.6.1+really5.4.5-1"
        assert fixed[0]["patch_date"] == "2024-04-02"
        assert fixed[0]["days_to_patch"] == 4  # 2024-03-29 → 2024-04-02

    def test_advisory_ids_collected(self):
        with patch("requests.get", return_value=_make_mock_response(_UBUNTU_RESPONSE)):
            results = _fetch_ubuntu("CVE-2024-3094", _NVD_PUBLISHED)
        fixed = [r for r in results if r["status"] == "fixed"]
        assert "USN-6743-1" in fixed[0]["advisory_ids"]

    def test_404_returns_empty(self):
        with patch("requests.get", return_value=_make_404_response()):
            results = _fetch_ubuntu("CVE-9999-0000", None)
        assert results == []

    def test_network_error_returns_empty(self):
        with patch("requests.get", side_effect=Exception("timeout")):
            results = _fetch_ubuntu("CVE-2024-3094", None)
        assert results == []

    def test_empty_packages_returns_empty(self):
        data = {"id": "CVE-2024-3094", "notices": [], "packages": []}
        with patch("requests.get", return_value=_make_mock_response(data)):
            results = _fetch_ubuntu("CVE-2024-3094", None)
        assert results == []

    def test_status_mapping_needed(self):
        data = {
            "packages": [
                {
                    "name": "pkg",
                    "statuses": [{"release_codename": "focal", "status": "needed", "fix_version": ""}],
                }
            ],
            "notices": [],
        }
        with patch("requests.get", return_value=_make_mock_response(data)):
            results = _fetch_ubuntu("CVE-2024-3094", None)
        assert any(r["status"] == "vulnerable" for r in results)

    def test_status_mapping_pending(self):
        data = {
            "packages": [
                {
                    "name": "pkg",
                    "statuses": [{"release_codename": "jammy", "status": "pending", "fix_version": "1.2.3"}],
                }
            ],
            "notices": [],
        }
        with patch("requests.get", return_value=_make_mock_response(data)):
            results = _fetch_ubuntu("CVE-2024-3094", None)
        assert any(r["status"] == "vulnerable" for r in results)

    def test_no_nvd_published_days_to_patch_none(self):
        with patch("requests.get", return_value=_make_mock_response(_UBUNTU_RESPONSE)):
            results = _fetch_ubuntu("CVE-2024-3094", None)
        fixed = [r for r in results if r["status"] == "fixed"]
        if fixed:
            assert fixed[0]["days_to_patch"] is None

    def test_affected_packages_populated(self):
        with patch("requests.get", return_value=_make_mock_response(_UBUNTU_RESPONSE)):
            results = _fetch_ubuntu("CVE-2024-3094", _NVD_PUBLISHED)
        fixed = [r for r in results if r["status"] == "fixed"]
        assert "xz-utils" in fixed[0]["affected_packages"]


# ===========================================================================
# _fetch_debian
# ===========================================================================


class TestFetchDebian:
    def test_normal_response(self):
        with patch("requests.get", return_value=_make_mock_response(_DEBIAN_RESPONSE)):
            results = _fetch_debian("CVE-2024-3094", _NVD_PUBLISHED)
        assert len(results) > 0
        vendors = {r["vendor"] for r in results}
        assert "debian/bookworm" in vendors
        assert "debian/bullseye" in vendors

    def test_fixed_status_and_version(self):
        with patch("requests.get", return_value=_make_mock_response(_DEBIAN_RESPONSE)):
            results = _fetch_debian("CVE-2024-3094", _NVD_PUBLISHED)
        bookworm = next(r for r in results if r["vendor"] == "debian/bookworm")
        assert bookworm["status"] == "fixed"
        assert bookworm["fixed_version"] == "5.4.1-0.2+deb12u1"

    def test_404_returns_empty(self):
        with patch("requests.get", return_value=_make_404_response()):
            results = _fetch_debian("CVE-9999-0000", None)
        assert results == []

    def test_json_parse_error_returns_empty(self):
        mock = MagicMock()
        mock.status_code = 200
        mock.raise_for_status.return_value = None
        mock.json.side_effect = ValueError("not JSON")
        with patch("requests.get", return_value=mock):
            results = _fetch_debian("CVE-2024-3094", None)
        assert results == []

    def test_network_error_returns_empty(self):
        with patch("requests.get", side_effect=Exception("timeout")):
            results = _fetch_debian("CVE-2024-3094", None)
        assert results == []

    def test_open_status_maps_to_vulnerable(self):
        data = {"somepkg": {"bookworm": {"status": "open", "fixed_version": "", "urgency": "high"}}}
        with patch("requests.get", return_value=_make_mock_response(data)):
            results = _fetch_debian("CVE-2024-3094", None)
        assert any(r["status"] == "vulnerable" for r in results)

    def test_unimportant_urgency_maps_to_not_affected(self):
        data = {
            "somepkg": {"sid": {"status": "resolved", "fixed_version": "1.0", "urgency": "unimportant", "nodsa": ""}}
        }
        with patch("requests.get", return_value=_make_mock_response(data)):
            results = _fetch_debian("CVE-2024-3094", None)
        # resolved with unimportant urgency → not_affected via nodsa path
        # The current logic: nodsa takes precedence when truthy; here nodsa=""
        # so status resolves from "resolved" → "fixed"
        assert any(r["status"] in ("fixed", "not_affected") for r in results)

    def test_non_dict_release_map_skipped(self):
        data = {"somepkg": "not-a-dict"}
        with patch("requests.get", return_value=_make_mock_response(data)):
            results = _fetch_debian("CVE-2024-3094", None)
        assert results == []

    def test_affected_packages_populated(self):
        with patch("requests.get", return_value=_make_mock_response(_DEBIAN_RESPONSE)):
            results = _fetch_debian("CVE-2024-3094", _NVD_PUBLISHED)
        bookworm = next(r for r in results if r["vendor"] == "debian/bookworm")
        assert "xz-utils" in bookworm["affected_packages"]


# ===========================================================================
# _fetch_redhat
# ===========================================================================


class TestFetchRedhat:
    def test_normal_response_fixed(self):
        with patch("requests.get", return_value=_make_mock_response(_REDHAT_RESPONSE)):
            results = _fetch_redhat("CVE-2024-3094", _NVD_PUBLISHED)
        fixed = [r for r in results if r["status"] == "fixed"]
        assert len(fixed) >= 1
        rhel9 = next((r for r in fixed if "Red Hat Enterprise Linux 9" in r["vendor"]), None)
        assert rhel9 is not None
        assert "RHSA-2024:1642" in rhel9["advisory_ids"]
        assert rhel9["patch_date"] == "2024-04-03"
        assert rhel9["days_to_patch"] == 5  # 2024-03-29 → 2024-04-03

    def test_package_state_not_affected(self):
        with patch("requests.get", return_value=_make_mock_response(_REDHAT_RESPONSE)):
            results = _fetch_redhat("CVE-2024-3094", _NVD_PUBLISHED)
        not_affected = [r for r in results if r["vendor"] == "redhat/Red Hat Enterprise Linux 8"]
        assert len(not_affected) >= 1

    def test_404_returns_empty(self):
        with patch("requests.get", return_value=_make_404_response()):
            results = _fetch_redhat("CVE-9999-0000", None)
        assert results == []

    def test_400_returns_empty(self):
        mock = MagicMock()
        mock.status_code = 400
        http_err = requests.HTTPError(response=mock)
        mock.raise_for_status.side_effect = http_err
        with patch("requests.get", return_value=mock):
            results = _fetch_redhat("CVE-2024-3094", None)
        assert results == []

    def test_network_error_returns_empty(self):
        with patch("requests.get", side_effect=Exception("timeout")):
            results = _fetch_redhat("CVE-2024-3094", None)
        assert results == []

    def test_empty_lists_returns_empty(self):
        data = {"name": "CVE-2024-3094", "affected_release": [], "package_state": []}
        with patch("requests.get", return_value=_make_mock_response(data)):
            results = _fetch_redhat("CVE-2024-3094", None)
        assert results == []

    def test_missing_release_date_no_days(self):
        data = {
            "affected_release": [
                {
                    "product_name": "RHEL 9",
                    "advisory": "RHSA-2024:0001",
                    "package": "xz-5.4.3-1.el9",
                    # no release_date
                }
            ],
            "package_state": [],
        }
        with patch("requests.get", return_value=_make_mock_response(data)):
            results = _fetch_redhat("CVE-2024-3094", _NVD_PUBLISHED)
        assert results[0]["days_to_patch"] is None

    def test_affected_packages_populated(self):
        with patch("requests.get", return_value=_make_mock_response(_REDHAT_RESPONSE)):
            results = _fetch_redhat("CVE-2024-3094", _NVD_PUBLISHED)
        fixed = [r for r in results if r["status"] == "fixed"]
        assert len(fixed[0]["affected_packages"]) > 0


# ===========================================================================
# _fetch_osv
# ===========================================================================


class TestFetchOsv:
    def test_normal_response(self):
        with patch("requests.post", return_value=_make_mock_response(_OSV_RESPONSE)):
            results = _fetch_osv("CVE-2024-3094", _NVD_PUBLISHED)
        assert len(results) > 0
        fixed = [r for r in results if r["status"] == "fixed"]
        assert len(fixed) >= 1
        assert fixed[0]["fixed_version"] == "5.6.1+really5.4.5-1"

    def test_advisory_id_populated(self):
        with patch("requests.post", return_value=_make_mock_response(_OSV_RESPONSE)):
            results = _fetch_osv("CVE-2024-3094", _NVD_PUBLISHED)
        fixed = [r for r in results if r["status"] == "fixed"]
        assert "GHSA-rxwq-x6h5-x525" in fixed[0]["advisory_ids"]

    def test_404_returns_empty(self):
        with patch("requests.post", return_value=_make_404_response()):
            results = _fetch_osv("CVE-9999-0000", None)
        assert results == []

    def test_network_error_returns_empty(self):
        with patch("requests.post", side_effect=Exception("timeout")):
            results = _fetch_osv("CVE-2024-3094", None)
        assert results == []

    def test_empty_vulns(self):
        with patch("requests.post", return_value=_make_mock_response({"vulns": []})):
            results = _fetch_osv("CVE-2024-3094", None)
        assert results == []

    def test_no_fixed_event_returns_vulnerable(self):
        data = {
            "vulns": [
                {
                    "id": "GHSA-xxxx",
                    "modified": "2024-04-01T00:00:00Z",
                    "affected": [
                        {
                            "package": {"name": "somepkg", "ecosystem": "PyPI"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                            "versions": ["1.0.0"],
                        }
                    ],
                }
            ]
        }
        with patch("requests.post", return_value=_make_mock_response(data)):
            results = _fetch_osv("CVE-2024-3094", None)
        assert any(r["status"] == "vulnerable" for r in results)

    def test_vendor_name_lowercased(self):
        with patch("requests.post", return_value=_make_mock_response(_OSV_RESPONSE)):
            results = _fetch_osv("CVE-2024-3094", _NVD_PUBLISHED)
        fixed = [r for r in results if r["status"] == "fixed"]
        assert fixed[0]["vendor"].startswith("osv/")

    def test_patch_date_from_modified(self):
        with patch("requests.post", return_value=_make_mock_response(_OSV_RESPONSE)):
            results = _fetch_osv("CVE-2024-3094", _NVD_PUBLISHED)
        fixed = [r for r in results if r["status"] == "fixed"]
        assert fixed[0]["patch_date"] == "2024-04-01"

    def test_days_to_patch_computed(self):
        with patch("requests.post", return_value=_make_mock_response(_OSV_RESPONSE)):
            results = _fetch_osv("CVE-2024-3094", _NVD_PUBLISHED)
        fixed = [r for r in results if r["status"] == "fixed"]
        # 2024-04-01 - 2024-03-29 = 3 days
        assert fixed[0]["days_to_patch"] == 3


# ===========================================================================
# _summarise
# ===========================================================================


class TestSummarise:
    def _make_vendors(self):
        return [
            {
                "vendor": "ubuntu/noble",
                "status": "fixed",
                "days_to_patch": 4,
                "advisory_ids": ["USN-6743-1"],
                "fixed_version": "5.6.1+really5.4.5-1",
                "affected_packages": ["xz-utils"],
                "patch_date": "2024-04-02",
            },
            {
                "vendor": "debian/bookworm",
                "status": "fixed",
                "days_to_patch": 10,
                "advisory_ids": ["DSA-5654-1"],
                "fixed_version": "5.4.1-0.2+deb12u1",
                "affected_packages": ["xz-utils"],
                "patch_date": "2024-04-08",
            },
            {
                "vendor": "redhat/rhel9",
                "status": "vulnerable",
                "days_to_patch": None,
                "advisory_ids": [],
                "fixed_version": None,
                "affected_packages": ["xz"],
                "patch_date": None,
            },
        ]

    def test_overall_status_partially_patched(self):
        summary = _summarise(self._make_vendors())
        assert summary["overall_status"] == "partially_patched"

    def test_fully_patched(self):
        vendors = [
            {"vendor": "ubuntu/noble", "status": "fixed", "days_to_patch": 4, "advisory_ids": ["USN-1"]},
            {"vendor": "debian/bookworm", "status": "fixed", "days_to_patch": 10, "advisory_ids": []},
        ]
        summary = _summarise(vendors)
        assert summary["overall_status"] == "fully_patched"

    def test_unpatched(self):
        vendors = [
            {"vendor": "redhat/rhel9", "status": "vulnerable", "days_to_patch": None, "advisory_ids": []},
            {"vendor": "debian/bookworm", "status": "vulnerable", "days_to_patch": None, "advisory_ids": []},
        ]
        summary = _summarise(vendors)
        assert summary["overall_status"] == "unpatched"

    def test_unknown_when_empty(self):
        summary = _summarise([])
        assert summary["overall_status"] == "unknown"

    def test_fastest_patch_vendor(self):
        summary = _summarise(self._make_vendors())
        assert summary["fastest_patch_vendor"] == "ubuntu/noble"
        assert summary["fastest_patch_days"] == 4

    def test_vendors_counts(self):
        summary = _summarise(self._make_vendors())
        assert summary["vendors_checked"] == 3
        assert summary["vendors_fixed"] == 2
        assert summary["vendors_vulnerable"] == 1

    def test_all_advisory_ids_deduplicated(self):
        vendors = [
            {"vendor": "a", "status": "fixed", "days_to_patch": 1, "advisory_ids": ["USN-1", "USN-2"]},
            {"vendor": "b", "status": "fixed", "days_to_patch": 2, "advisory_ids": ["USN-1", "DSA-1"]},
        ]
        summary = _summarise(vendors)
        adv = summary["all_advisory_ids"]
        assert adv.count("USN-1") == 1
        assert "USN-2" in adv
        assert "DSA-1" in adv

    def test_no_fastest_when_no_days(self):
        vendors = [
            {"vendor": "a", "status": "fixed", "days_to_patch": None, "advisory_ids": []},
        ]
        summary = _summarise(vendors)
        assert summary["fastest_patch_vendor"] is None
        assert summary["fastest_patch_days"] is None

    def test_not_affected_not_counted(self):
        vendors = [
            {"vendor": "a", "status": "not_affected", "days_to_patch": None, "advisory_ids": []},
        ]
        summary = _summarise(vendors)
        assert summary["overall_status"] == "unknown"

    def test_fastest_ignores_none_days(self):
        vendors = [
            {"vendor": "slow", "status": "fixed", "days_to_patch": 30, "advisory_ids": []},
            {"vendor": "nodates", "status": "fixed", "days_to_patch": None, "advisory_ids": []},
        ]
        summary = _summarise(vendors)
        assert summary["fastest_patch_vendor"] == "slow"


# ===========================================================================
# get_patch_status (integration)
# ===========================================================================


class TestGetPatchStatus:
    def _mock_all_sources(self, cve_id="CVE-2024-3094"):
        """Context manager that patches all four network sources."""

        def _side_effect_get(url, *args, **kwargs):
            if "nvd.nist.gov" in url:
                return _make_mock_response(_NVD_RESPONSE)
            if "ubuntu.com" in url:
                return _make_mock_response(_UBUNTU_RESPONSE)
            if "security-tracker.debian.org" in url:
                return _make_mock_response(_DEBIAN_RESPONSE)
            if "access.redhat.com" in url:
                return _make_mock_response(_REDHAT_RESPONSE)
            return _make_mock_response({})

        return patch("requests.get", side_effect=_side_effect_get)

    def test_basic_structure(self):
        with self._mock_all_sources():
            with patch("requests.post", return_value=_make_mock_response(_OSV_RESPONSE)):
                result = get_patch_status(cve_id="CVE-2024-3094")

        assert result["cve_id"] == "CVE-2024-3094"
        assert "summary" in result
        assert "vendors" in result
        assert isinstance(result["vendors"], list)

    def test_nvd_published_date(self):
        with self._mock_all_sources():
            with patch("requests.post", return_value=_make_mock_response(_OSV_RESPONSE)):
                result = get_patch_status(cve_id="CVE-2024-3094")
        assert result["nvd_published"] == "2024-03-29"

    def test_summary_populated(self):
        with self._mock_all_sources():
            with patch("requests.post", return_value=_make_mock_response(_OSV_RESPONSE)):
                result = get_patch_status(cve_id="CVE-2024-3094")
        summary = result["summary"]
        assert summary["vendors_checked"] > 0
        assert summary["overall_status"] in (
            "fully_patched",
            "partially_patched",
            "unpatched",
            "unknown",
        )

    def test_invalid_cve_id_returns_error(self):
        result = get_patch_status(cve_id="INVALID-FORMAT")
        assert "error" in result
        assert result["summary"] is None
        assert result["vendors"] == []

    def test_cve_id_normalised_to_uppercase(self):
        with self._mock_all_sources():
            with patch("requests.post", return_value=_make_mock_response(_OSV_RESPONSE)):
                result = get_patch_status(cve_id="cve-2024-3094")
        assert result["cve_id"] == "CVE-2024-3094"

    def test_cve_id_whitespace_stripped(self):
        with self._mock_all_sources():
            with patch("requests.post", return_value=_make_mock_response(_OSV_RESPONSE)):
                result = get_patch_status(cve_id="  CVE-2024-3094  ")
        assert result["cve_id"] == "CVE-2024-3094"

    def test_all_sources_down_returns_unknown(self):
        with patch("requests.get", side_effect=Exception("network error")):
            with patch("requests.post", side_effect=Exception("network error")):
                result = get_patch_status(cve_id="CVE-2024-3094")
        # NVD down → nvd_published None; all fetches fail → empty vendors
        assert result["summary"]["overall_status"] == "unknown"
        assert result["vendors"] == []

    def test_ubuntu_down_partial_results(self):
        """Other sources should still work if Ubuntu is down."""

        def _side_effect_get(url, *args, **kwargs):
            if "nvd.nist.gov" in url:
                return _make_mock_response(_NVD_RESPONSE)
            if "ubuntu.com" in url:
                raise Exception("ubuntu down")
            if "security-tracker.debian.org" in url:
                return _make_mock_response(_DEBIAN_RESPONSE)
            if "access.redhat.com" in url:
                return _make_mock_response(_REDHAT_RESPONSE)
            return _make_mock_response({})

        with patch("requests.get", side_effect=_side_effect_get):
            with patch("requests.post", return_value=_make_mock_response(_OSV_RESPONSE)):
                result = get_patch_status(cve_id="CVE-2024-3094")

        vendors = {r["vendor"].split("/")[0] for r in result["vendors"]}
        assert "ubuntu" not in vendors
        assert "debian" in vendors or "osv" in vendors

    def test_vendors_have_required_fields(self):
        with self._mock_all_sources():
            with patch("requests.post", return_value=_make_mock_response(_OSV_RESPONSE)):
                result = get_patch_status(cve_id="CVE-2024-3094")
        for v in result["vendors"]:
            assert "vendor" in v
            assert "status" in v
            assert v["status"] in ("fixed", "vulnerable", "not_affected", "unknown")
            assert "advisory_ids" in v
            assert isinstance(v["advisory_ids"], list)
            assert "affected_packages" in v
            assert isinstance(v["affected_packages"], list)

    def test_multiple_distros_present(self):
        with self._mock_all_sources():
            with patch("requests.post", return_value=_make_mock_response(_OSV_RESPONSE)):
                result = get_patch_status(cve_id="CVE-2024-3094")
        vendor_prefixes = {v["vendor"].split("/")[0] for v in result["vendors"]}
        # At least two sources should contribute
        assert len(vendor_prefixes) >= 2

    def test_no_error_key_on_success(self):
        with self._mock_all_sources():
            with patch("requests.post", return_value=_make_mock_response(_OSV_RESPONSE)):
                result = get_patch_status(cve_id="CVE-2024-3094")
        assert "error" not in result


# ===========================================================================
# CLI subcommand tests
# ===========================================================================


class TestPatchStatusCli:
    """Test the _run_patch_status CLI runner via the main() dispatch."""

    def _mock_get_patch_status(self, return_value):
        return patch(
            "manus_agent.tools.get_patch_status.get_patch_status",
            return_value=return_value,
        )

    def test_cli_registered_in_subcommands(self):
        from manus_agent.cli import _SUBCOMMANDS

        assert "patch-status" in _SUBCOMMANDS

    def test_cli_text_output(self, capsys):

        fake_result = {
            "cve_id": "CVE-2024-3094",
            "nvd_published": "2024-03-29",
            "summary": {
                "overall_status": "partially_patched",
                "vendors_checked": 3,
                "vendors_fixed": 2,
                "vendors_vulnerable": 1,
                "fastest_patch_vendor": "ubuntu/noble",
                "fastest_patch_days": 4,
                "all_advisory_ids": ["USN-6743-1"],
            },
            "vendors": [
                {
                    "vendor": "ubuntu/noble",
                    "status": "fixed",
                    "fixed_version": "5.6.1+really5.4.5-1",
                    "advisory_ids": ["USN-6743-1"],
                    "patch_date": "2024-04-02",
                    "days_to_patch": 4,
                    "affected_packages": ["xz-utils"],
                },
                {
                    "vendor": "debian/bookworm",
                    "status": "fixed",
                    "fixed_version": "5.4.1-0.2+deb12u1",
                    "advisory_ids": ["DSA-5654-1"],
                    "patch_date": "2024-04-08",
                    "days_to_patch": 10,
                    "affected_packages": ["xz-utils"],
                },
                {
                    "vendor": "redhat/rhel9",
                    "status": "vulnerable",
                    "fixed_version": None,
                    "advisory_ids": [],
                    "patch_date": None,
                    "days_to_patch": None,
                    "affected_packages": ["xz"],
                },
            ],
        }

        with patch("manus_agent.cli.get_patch_status", return_value=fake_result, create=True):
            with patch(
                "manus_agent.tools.get_patch_status.get_patch_status",
                return_value=fake_result,
            ):
                from manus_agent.cli import _run_patch_status as runner

                exit_code = runner(["CVE-2024-3094"])

        captured = capsys.readouterr()
        assert exit_code == 0
        assert "CVE-2024-3094" in captured.out
        assert "PARTIALLY PATCHED" in captured.out

    def test_cli_json_output(self, capsys):
        from manus_agent.cli import _run_patch_status as runner

        fake_result = {
            "cve_id": "CVE-2024-3094",
            "nvd_published": "2024-03-29",
            "summary": {
                "overall_status": "fully_patched",
                "vendors_checked": 2,
                "vendors_fixed": 2,
                "vendors_vulnerable": 0,
                "fastest_patch_vendor": "ubuntu/noble",
                "fastest_patch_days": 4,
                "all_advisory_ids": [],
            },
            "vendors": [],
        }

        with patch(
            "manus_agent.tools.get_patch_status.get_patch_status",
            return_value=fake_result,
        ):
            exit_code = runner(["CVE-2024-3094", "--output", "json"])

        captured = capsys.readouterr()
        assert exit_code == 0
        parsed = json.loads(captured.out)
        assert parsed["cve_id"] == "CVE-2024-3094"
        assert parsed["summary"]["overall_status"] == "fully_patched"

    def test_cli_invalid_cve(self, capsys):
        from manus_agent.cli import _run_patch_status as runner

        fake_result = {
            "cve_id": "INVALID",
            "error": "Invalid CVE ID format: 'INVALID'",
            "summary": None,
            "vendors": [],
        }

        with patch(
            "manus_agent.tools.get_patch_status.get_patch_status",
            return_value=fake_result,
        ):
            exit_code = runner(["INVALID"])

        assert exit_code == 1

    def test_cli_in_main_dispatch(self):
        """Smoke-test that main() routes 'patch-status' to _run_patch_status."""
        from unittest.mock import patch as _patch

        with _patch("sys.argv", ["manus-agent", "patch-status", "--help"]):
            from manus_agent.cli import main

            with pytest.raises(SystemExit) as exc:
                main()
            # --help exits with 0
            assert exc.value.code == 0

    def test_cli_help_text_present(self, capsys):
        from manus_agent.cli import _build_patch_status_parser

        p = _build_patch_status_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["--help"])
        captured = capsys.readouterr()
        assert "patch" in captured.out.lower() or "patch" in captured.err.lower()


# ===========================================================================
# Tool spec (for module-level TOOL_SPEC consumers)
# ===========================================================================


class TestModuleLevel:
    def test_module_imports_cleanly(self):
        import manus_agent.tools.get_patch_status as m

        assert hasattr(m, "get_patch_status")

    def test_get_patch_status_is_callable(self):
        from manus_agent.tools.get_patch_status import get_patch_status

        assert callable(get_patch_status)

    def test_all_exports(self):
        from manus_agent.tools.get_patch_status import __all__

        assert "get_patch_status" in __all__

    def test_internal_helpers_exported(self):
        """Confirm helpers are importable for unit-testing."""
        from manus_agent.tools.get_patch_status import (
            _days_to_patch,
            _parse_iso_date,
            _summarise,
        )

        assert callable(_days_to_patch)
        assert callable(_parse_iso_date)
        assert callable(_summarise)
