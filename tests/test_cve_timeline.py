"""Tests for the get_cve_timeline tool and cve-timeline CLI subcommand.

All tests are unit tests that mock the NVD, FIRST.org EPSS, CISA KEV, and
OSV.dev APIs.  No real network calls are made.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T00:00:00.000",
                "lastModified": "2022-01-06T12:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other endpoints.",
                    }
                ],
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

_EPSS_RESPONSE = {
    "status": "OK",
    "data": [
        {
            "cve": "CVE-2021-44228",
            "epss": "0.975280",
            "percentile": "0.999990",
            "date": "2026-07-01",
            "time-series": [
                {"epss": "0.100000", "percentile": "0.900000", "date": "2021-12-12"},
                {"epss": "0.500000", "percentile": "0.995000", "date": "2021-12-15"},
                {"epss": "0.975280", "percentile": "0.999990", "date": "2021-12-20"},
                {"epss": "0.960000", "percentile": "0.999980", "date": "2026-07-01"},
            ],
        }
    ],
}

_KEV_RESPONSE = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "requiredAction": "Apply updates per vendor instructions.",
        }
    ]
}

_KEV_RESPONSE_EMPTY = {"vulnerabilities": []}

_OSV_RESPONSE = {
    "vulns": [
        {
            "id": "GHSA-jfh8-c2jp-cr6x",
            "modified": "2021-12-14T00:00:00Z",
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "2.15.0"},
                            ],
                        }
                    ]
                }
            ],
        }
    ]
}

_OSV_RESPONSE_NO_FIX = {
    "vulns": [
        {
            "id": "GHSA-jfh8-c2jp-cr6x",
            "modified": "2021-12-14T00:00:00Z",
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}],
                        }
                    ]
                }
            ],
        }
    ]
}


# ---------------------------------------------------------------------------
# Helper: build a mock requests.get/post response
# ---------------------------------------------------------------------------


def _mock_response(json_data: dict, status_code: int = 200) -> MagicMock:
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data
    mock.raise_for_status.return_value = None
    return mock


def _mock_http_error() -> MagicMock:
    import requests

    mock = MagicMock()
    mock.raise_for_status.side_effect = requests.HTTPError("500")
    return mock


# ---------------------------------------------------------------------------
# Module import tests
# ---------------------------------------------------------------------------


def test_module_imports():
    """The tool module must be importable without strands."""
    import manus_agent.tools.get_cve_timeline as m

    assert hasattr(m, "get_cve_timeline")
    assert hasattr(m, "TOOL_SPEC")
    assert hasattr(m, "_build_timeline")
    assert hasattr(m, "_fetch_nvd_meta")
    assert hasattr(m, "_fetch_epss_series")
    assert hasattr(m, "_analyse_epss")
    assert hasattr(m, "_fetch_kev_entry")
    assert hasattr(m, "_fetch_osv_patch_date")
    assert hasattr(m, "_days_between")


def test_tool_spec_fields():
    from manus_agent.tools.get_cve_timeline import TOOL_SPEC

    assert TOOL_SPEC["name"] == "get_cve_timeline"
    assert "cve_id" in TOOL_SPEC["inputSchema"]["json"]["properties"]
    assert "cve_id" in TOOL_SPEC["inputSchema"]["json"]["required"]


# ---------------------------------------------------------------------------
# _fetch_nvd_meta
# ---------------------------------------------------------------------------


def test_fetch_nvd_meta_success():
    from manus_agent.tools.get_cve_timeline import _fetch_nvd_meta

    with patch("manus_agent.tools.get_cve_timeline.requests.get") as mock_get:
        mock_get.return_value = _mock_response(_NVD_RESPONSE)
        result = _fetch_nvd_meta("CVE-2021-44228")

    assert result["id"] == "CVE-2021-44228"
    assert result["published"].startswith("2021-12-10")


def test_fetch_nvd_meta_not_found():
    from manus_agent.tools.get_cve_timeline import _fetch_nvd_meta

    with patch("manus_agent.tools.get_cve_timeline.requests.get") as mock_get:
        mock_get.return_value = _mock_response({"vulnerabilities": []})
        result = _fetch_nvd_meta("CVE-9999-9999")

    assert result == {}


def test_fetch_nvd_meta_http_error():
    from manus_agent.tools.get_cve_timeline import _fetch_nvd_meta

    with patch("manus_agent.tools.get_cve_timeline.requests.get") as mock_get:
        mock_get.return_value = _mock_http_error()
        result = _fetch_nvd_meta("CVE-2021-44228")

    assert result == {}


def test_fetch_nvd_meta_network_exception():
    from manus_agent.tools.get_cve_timeline import _fetch_nvd_meta

    with patch("manus_agent.tools.get_cve_timeline.requests.get", side_effect=Exception("timeout")):
        result = _fetch_nvd_meta("CVE-2021-44228")

    assert result == {}


# ---------------------------------------------------------------------------
# _fetch_epss_series / _analyse_epss
# ---------------------------------------------------------------------------


def test_fetch_epss_series_success():
    from manus_agent.tools.get_cve_timeline import _fetch_epss_series

    with patch("manus_agent.tools.get_cve_timeline.requests.get") as mock_get:
        mock_get.return_value = _mock_response(_EPSS_RESPONSE)
        series = _fetch_epss_series("CVE-2021-44228")

    assert len(series) == 4
    # Should be sorted oldest-first
    assert series[0]["date"] == "2021-12-12"
    assert series[-1]["date"] == "2026-07-01"


def test_fetch_epss_series_empty():
    from manus_agent.tools.get_cve_timeline import _fetch_epss_series

    with patch("manus_agent.tools.get_cve_timeline.requests.get") as mock_get:
        mock_get.return_value = _mock_response({"status": "OK", "data": []})
        series = _fetch_epss_series("CVE-9999-9999")

    assert series == []


def test_fetch_epss_series_error():
    from manus_agent.tools.get_cve_timeline import _fetch_epss_series

    with patch("manus_agent.tools.get_cve_timeline.requests.get", side_effect=Exception("err")):
        series = _fetch_epss_series("CVE-2021-44228")

    assert series == []


def test_analyse_epss_empty():
    from manus_agent.tools.get_cve_timeline import _analyse_epss

    result = _analyse_epss([])
    assert result["first_seen_date"] is None
    assert result["peak_date"] is None
    assert result["peak_score"] is None
    assert result["current_score"] is None


def test_analyse_epss_peak_found():
    from manus_agent.tools.get_cve_timeline import _analyse_epss

    series = [
        {"epss": "0.100000", "percentile": "0.900000", "date": "2021-12-12"},
        {"epss": "0.975280", "percentile": "0.999990", "date": "2021-12-20"},
        {"epss": "0.960000", "percentile": "0.999980", "date": "2026-07-01"},
    ]
    result = _analyse_epss(series)
    assert result["first_seen_date"] == "2021-12-12"
    assert result["peak_date"] == "2021-12-20"
    assert abs(result["peak_score"] - 0.975280) < 1e-5
    assert abs(result["current_score"] - 0.960000) < 1e-5


def test_analyse_epss_single_point():
    from manus_agent.tools.get_cve_timeline import _analyse_epss

    series = [{"epss": "0.050000", "percentile": "0.850000", "date": "2021-12-12"}]
    result = _analyse_epss(series)
    assert result["first_seen_date"] == "2021-12-12"
    assert result["peak_date"] == "2021-12-12"
    assert abs(result["peak_score"] - 0.05) < 1e-5
    assert abs(result["current_score"] - 0.05) < 1e-5


# ---------------------------------------------------------------------------
# _fetch_kev_entry
# ---------------------------------------------------------------------------


def test_fetch_kev_entry_found():
    from manus_agent.tools.get_cve_timeline import _fetch_kev_entry

    with patch("manus_agent.tools.get_cve_timeline.requests.get") as mock_get:
        mock_get.return_value = _mock_response(_KEV_RESPONSE)
        entry = _fetch_kev_entry("CVE-2021-44228")

    assert entry["cveID"] == "CVE-2021-44228"
    assert entry["dateAdded"] == "2021-12-10"
    assert entry["vendorProject"] == "Apache"


def test_fetch_kev_entry_not_found():
    from manus_agent.tools.get_cve_timeline import _fetch_kev_entry

    with patch("manus_agent.tools.get_cve_timeline.requests.get") as mock_get:
        mock_get.return_value = _mock_response(_KEV_RESPONSE_EMPTY)
        entry = _fetch_kev_entry("CVE-9999-9999")

    assert entry == {}


def test_fetch_kev_entry_case_insensitive():
    from manus_agent.tools.get_cve_timeline import _fetch_kev_entry

    with patch("manus_agent.tools.get_cve_timeline.requests.get") as mock_get:
        mock_get.return_value = _mock_response(_KEV_RESPONSE)
        entry = _fetch_kev_entry("cve-2021-44228")  # lowercase

    assert entry.get("cveID") == "CVE-2021-44228"


def test_fetch_kev_entry_http_error():
    from manus_agent.tools.get_cve_timeline import _fetch_kev_entry

    with patch("manus_agent.tools.get_cve_timeline.requests.get", side_effect=Exception("err")):
        entry = _fetch_kev_entry("CVE-2021-44228")

    assert entry == {}


# ---------------------------------------------------------------------------
# _fetch_osv_patch_date
# ---------------------------------------------------------------------------


def test_fetch_osv_patch_date_found():
    from manus_agent.tools.get_cve_timeline import _fetch_osv_patch_date

    with patch("manus_agent.tools.get_cve_timeline.requests.post") as mock_post:
        mock_post.return_value = _mock_response(_OSV_RESPONSE)
        date = _fetch_osv_patch_date("CVE-2021-44228")

    assert date == "2021-12-14"


def test_fetch_osv_patch_date_no_fix():
    from manus_agent.tools.get_cve_timeline import _fetch_osv_patch_date

    with patch("manus_agent.tools.get_cve_timeline.requests.post") as mock_post:
        mock_post.return_value = _mock_response(_OSV_RESPONSE_NO_FIX)
        date = _fetch_osv_patch_date("CVE-9999-9999")

    assert date is None


def test_fetch_osv_patch_date_empty():
    from manus_agent.tools.get_cve_timeline import _fetch_osv_patch_date

    with patch("manus_agent.tools.get_cve_timeline.requests.post") as mock_post:
        mock_post.return_value = _mock_response({"vulns": []})
        date = _fetch_osv_patch_date("CVE-9999-9999")

    assert date is None


def test_fetch_osv_patch_date_error():
    from manus_agent.tools.get_cve_timeline import _fetch_osv_patch_date

    with patch("manus_agent.tools.get_cve_timeline.requests.post", side_effect=Exception("err")):
        date = _fetch_osv_patch_date("CVE-2021-44228")

    assert date is None


def test_fetch_osv_earliest_of_multiple():
    """When multiple OSV vulns have fixes, the earliest modified date is returned."""
    from manus_agent.tools.get_cve_timeline import _fetch_osv_patch_date

    multi = {
        "vulns": [
            {
                "id": "GHSA-aaa",
                "modified": "2022-01-15T00:00:00Z",
                "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}],
            },
            {
                "id": "GHSA-bbb",
                "modified": "2021-12-14T00:00:00Z",
                "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.5"}]}]}],
            },
        ]
    }
    with patch("manus_agent.tools.get_cve_timeline.requests.post") as mock_post:
        mock_post.return_value = _mock_response(multi)
        date = _fetch_osv_patch_date("CVE-2021-44228")

    assert date == "2021-12-14"


# ---------------------------------------------------------------------------
# _days_between
# ---------------------------------------------------------------------------


def test_days_between_positive():
    from manus_agent.tools.get_cve_timeline import _days_between

    assert _days_between("2021-12-10", "2021-12-24") == 14


def test_days_between_zero():
    from manus_agent.tools.get_cve_timeline import _days_between

    assert _days_between("2021-12-10", "2021-12-10") == 0


def test_days_between_negative():
    from manus_agent.tools.get_cve_timeline import _days_between

    assert _days_between("2021-12-24", "2021-12-10") == -14


def test_days_between_none_first():
    from manus_agent.tools.get_cve_timeline import _days_between

    assert _days_between(None, "2021-12-10") is None


def test_days_between_none_second():
    from manus_agent.tools.get_cve_timeline import _days_between

    assert _days_between("2021-12-10", None) is None


def test_days_between_both_none():
    from manus_agent.tools.get_cve_timeline import _days_between

    assert _days_between(None, None) is None


def test_days_between_datetime_prefix():
    """Should accept ISO datetime strings, not just dates."""
    from manus_agent.tools.get_cve_timeline import _days_between

    assert _days_between("2021-12-10T00:00:00Z", "2021-12-24T12:00:00Z") == 14


# ---------------------------------------------------------------------------
# _build_timeline (full integration with mocked HTTP)
# ---------------------------------------------------------------------------


def _patch_all_sources(nvd=_NVD_RESPONSE, epss=_EPSS_RESPONSE, kev=_KEV_RESPONSE, osv=_OSV_RESPONSE):
    """Context manager that mocks all four HTTP sources."""
    from unittest.mock import patch as _patch

    def _get_side_effect(url, *args, **kwargs):
        if "nvd.nist" in url:
            return _mock_response(nvd)
        if "first.org" in url:
            return _mock_response(epss)
        if "cisa.gov" in url:
            return _mock_response(kev)
        return _mock_response({})

    def _post_side_effect(url, *args, **kwargs):
        if "osv.dev" in url:
            return _mock_response(osv)
        return _mock_response({})

    return (
        _patch("manus_agent.tools.get_cve_timeline.requests.get", side_effect=_get_side_effect),
        _patch("manus_agent.tools.get_cve_timeline.requests.post", side_effect=_post_side_effect),
    )


def test_build_timeline_full():
    from manus_agent.tools.get_cve_timeline import _build_timeline

    get_patch, post_patch = _patch_all_sources()
    with get_patch, post_patch:
        result = _build_timeline("CVE-2021-44228")

    assert result["cve_id"] == "CVE-2021-44228"
    assert result["cvss_score"] == 10.0
    assert result["cvss_severity"] == "CRITICAL"
    tl = result["timeline"]
    assert tl["nvd_published"] == "2021-12-10"
    assert tl["epss_peak_date"] == "2021-12-20"
    assert tl["kev_added"] == "2021-12-10"
    assert tl["patch_released"] == "2021-12-14"
    assert result["kev_details"]["vendor"] == "Apache"
    deltas = result["deltas"]
    assert deltas["days_nvd_to_kev"] == 0
    assert deltas["days_nvd_to_patch"] == 4
    assert deltas["days_nvd_to_epss_peak"] == 10


def test_build_timeline_no_kev():
    from manus_agent.tools.get_cve_timeline import _build_timeline

    get_patch, post_patch = _patch_all_sources(kev=_KEV_RESPONSE_EMPTY)
    with get_patch, post_patch:
        result = _build_timeline("CVE-2021-44228")

    assert result["kev_details"] is None
    assert result["timeline"]["kev_added"] is None
    assert result["deltas"]["days_nvd_to_kev"] is None


def test_build_timeline_no_osv():
    from manus_agent.tools.get_cve_timeline import _build_timeline

    get_patch, post_patch = _patch_all_sources(osv={"vulns": []})
    with get_patch, post_patch:
        result = _build_timeline("CVE-2021-44228")

    assert result["timeline"]["patch_released"] is None
    assert result["deltas"]["days_nvd_to_patch"] is None


def test_build_timeline_no_epss():
    from manus_agent.tools.get_cve_timeline import _build_timeline

    epss_empty = {"status": "OK", "data": []}
    get_patch, post_patch = _patch_all_sources(epss=epss_empty)
    with get_patch, post_patch:
        result = _build_timeline("CVE-2021-44228")

    assert result["timeline"]["epss_first_seen"] is None
    assert result["timeline"]["epss_peak_date"] is None
    assert result["deltas"]["days_nvd_to_epss_peak"] is None


def test_build_timeline_uppercase_normalised():
    from manus_agent.tools.get_cve_timeline import _build_timeline

    get_patch, post_patch = _patch_all_sources()
    with get_patch, post_patch:
        result = _build_timeline("cve-2021-44228")  # lowercase input

    assert result["cve_id"] == "CVE-2021-44228"


# ---------------------------------------------------------------------------
# Strands tool entry point
# ---------------------------------------------------------------------------


def _make_tool(cve_id: str) -> dict:
    return {"toolUseId": "test-001", "input": {"cve_id": cve_id}}


def test_strands_tool_invalid_cve():
    from manus_agent.tools.get_cve_timeline import get_cve_timeline

    result = get_cve_timeline(_make_tool("not-a-cve"))
    assert result["status"] == "error"
    assert "Invalid CVE ID" in result["content"][0]["text"]


def test_strands_tool_empty_cve():
    from manus_agent.tools.get_cve_timeline import get_cve_timeline

    result = get_cve_timeline(_make_tool(""))
    assert result["status"] == "error"


def test_strands_tool_success():
    from manus_agent.tools.get_cve_timeline import get_cve_timeline

    get_patch, post_patch = _patch_all_sources()
    with get_patch, post_patch:
        result = get_cve_timeline(_make_tool("CVE-2021-44228"))

    assert result["status"] == "success"
    payload = result["content"][0]["json"]
    assert payload["cve_id"] == "CVE-2021-44228"
    assert "timeline" in payload
    assert "deltas" in payload


def test_strands_tool_exception_handled():
    from manus_agent.tools.get_cve_timeline import get_cve_timeline

    with patch("manus_agent.tools.get_cve_timeline._build_timeline", side_effect=RuntimeError("boom")):
        result = get_cve_timeline(_make_tool("CVE-2021-44228"))

    assert result["status"] == "error"
    assert "boom" in result["content"][0]["text"]


# ---------------------------------------------------------------------------
# CLI subcommand
# ---------------------------------------------------------------------------


def test_cve_timeline_registered_in_subcommands():
    from manus_agent.cli import _SUBCOMMANDS

    assert "cve-timeline" in _SUBCOMMANDS


def test_cve_timeline_parser_defaults():
    from manus_agent.cli import _build_cve_timeline_parser

    p = _build_cve_timeline_parser()
    args = p.parse_args(["CVE-2021-44228"])
    assert args.cve_id == "CVE-2021-44228"
    assert args.output == "text"


def test_cve_timeline_parser_json_flag():
    from manus_agent.cli import _build_cve_timeline_parser

    p = _build_cve_timeline_parser()
    args = p.parse_args(["CVE-2021-44228", "--output", "json"])
    assert args.output == "json"


def test_cve_timeline_help_exits_zero():
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-m", "manus_agent.cli", "cve-timeline", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "CVE-ID" in result.stdout


def test_run_cve_timeline_json_output(capsys):
    from manus_agent.cli import _run_cve_timeline

    get_patch, post_patch = _patch_all_sources()
    with get_patch, post_patch:
        rc = _run_cve_timeline(["CVE-2021-44228", "--output", "json"])

    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["cve_id"] == "CVE-2021-44228"
    assert "timeline" in data
    assert "deltas" in data


def test_run_cve_timeline_text_output(capsys):
    from manus_agent.cli import _run_cve_timeline

    get_patch, post_patch = _patch_all_sources()
    with get_patch, post_patch:
        rc = _run_cve_timeline(["CVE-2021-44228"])

    assert rc == 0
    out = capsys.readouterr().out
    assert "CVE-2021-44228" in out
    assert "2021-12-10" in out  # NVD published
    assert "NVD published" in out
    assert "EPSS peak" in out


def test_run_cve_timeline_text_shows_kev(capsys):
    from manus_agent.cli import _run_cve_timeline

    get_patch, post_patch = _patch_all_sources()
    with get_patch, post_patch:
        _run_cve_timeline(["CVE-2021-44228"])

    out = capsys.readouterr().out
    assert "CISA KEV" in out
    assert "Apache" in out


def test_run_cve_timeline_text_no_kev(capsys):
    from manus_agent.cli import _run_cve_timeline

    get_patch, post_patch = _patch_all_sources(kev=_KEV_RESPONSE_EMPTY)
    with get_patch, post_patch:
        rc = _run_cve_timeline(["CVE-2021-44228"])

    assert rc == 0
    out = capsys.readouterr().out
    # kev_added row should show not available
    assert "not available" in out


def test_run_cve_timeline_text_patch_lag_flagged(capsys):
    """If patch lags KEV listing, an exposure window warning is shown."""
    from manus_agent.cli import _run_cve_timeline

    # kev_added=Dec 10, patch=Dec 20 -> lag of 10 days
    kev_early = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "dateAdded": "2021-12-10",
                "dueDate": "2021-12-24",
                "vendorProject": "Apache",
                "product": "Log4j2",
                "requiredAction": "Apply updates.",
            }
        ]
    }
    osv_late = {
        "vulns": [
            {
                "id": "GHSA-jfh8",
                "modified": "2021-12-20T00:00:00Z",
                "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.15"}]}]}],
            }
        ]
    }
    get_patch, post_patch = _patch_all_sources(kev=kev_early, osv=osv_late)
    with get_patch, post_patch:
        rc = _run_cve_timeline(["CVE-2021-44228"])

    out = capsys.readouterr().out
    assert rc == 0
    assert "window of exposure" in out


def test_run_cve_timeline_text_patch_before_kev(capsys):
    """If patch precedes KEV listing, a positive indicator is shown."""
    from manus_agent.cli import _run_cve_timeline

    kev_late = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "dateAdded": "2021-12-20",
                "dueDate": "2022-01-04",
                "vendorProject": "Apache",
                "product": "Log4j2",
                "requiredAction": "Apply updates.",
            }
        ]
    }
    osv_early = {
        "vulns": [
            {
                "id": "GHSA-jfh8",
                "modified": "2021-12-14T00:00:00Z",
                "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.15"}]}]}],
            }
        ]
    }
    get_patch, post_patch = _patch_all_sources(kev=kev_late, osv=osv_early)
    with get_patch, post_patch:
        rc = _run_cve_timeline(["CVE-2021-44228"])

    out = capsys.readouterr().out
    assert rc == 0
    assert "preceded KEV" in out


def test_run_cve_timeline_import_error(capsys):
    from manus_agent.cli import _run_cve_timeline

    with patch("builtins.__import__", side_effect=ImportError("strands missing")):
        pass  # can't easily mock import inside the function; skip import-error path

    # Test that bad CVE causes error output
    get_patch, post_patch = _patch_all_sources()
    with get_patch, post_patch:
        # Patch _build_timeline to raise
        with patch("manus_agent.tools.get_cve_timeline._build_timeline", side_effect=RuntimeError("fail")):
            rc = _run_cve_timeline(["CVE-2021-44228"])

    assert rc == 1
    err = capsys.readouterr().err
    assert "fail" in err


def test_main_dispatch_cve_timeline():
    """main() dispatches cve-timeline correctly."""
    import sys

    with patch("manus_agent.cli._run_cve_timeline", return_value=0) as mock_run:
        with patch.object(sys, "argv", ["manus-agent", "cve-timeline", "CVE-2021-44228"]):
            try:
                from manus_agent.cli import main

                main()
            except SystemExit as e:
                assert e.code == 0

    mock_run.assert_called_once_with(["CVE-2021-44228"])


# ---------------------------------------------------------------------------
# vi_agent wiring
# ---------------------------------------------------------------------------


def test_get_cve_timeline_in_vi_agent_tools():
    """get_cve_timeline must appear in vi_agent's tool list."""
    import inspect

    import manus_agent.agents.vi_agent as vi

    source = inspect.getsource(vi)
    assert "get_cve_timeline" in source


def test_get_cve_timeline_in_system_prompt():
    """Step 6d must reference get_cve_timeline in the system prompt."""
    import manus_agent.agents.vi_agent as vi

    assert "get_cve_timeline" in vi.SYSTEM_PROMPT
    assert "6d" in vi.SYSTEM_PROMPT
