"""Tests for the EPSS trend tool and epss-trend CLI subcommand.

All tests are unit tests that mock the FIRST.org API; no network calls are made.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAMPLE_TIME_SERIES = [
    {"epss": "0.050000", "percentile": "0.850000", "date": "2026-06-24"},
    {"epss": "0.040000", "percentile": "0.820000", "date": "2026-06-23"},
    {"epss": "0.035000", "percentile": "0.810000", "date": "2026-06-22"},
    {"epss": "0.030000", "percentile": "0.800000", "date": "2026-06-21"},
    {"epss": "0.025000", "percentile": "0.790000", "date": "2026-06-20"},
    {"epss": "0.020000", "percentile": "0.770000", "date": "2026-06-19"},
    {"epss": "0.010000", "percentile": "0.700000", "date": "2026-06-18"},
]

_SPIKE_TIME_SERIES = [
    {"epss": "0.900000", "percentile": "0.998000", "date": "2026-06-24"},
    {"epss": "0.850000", "percentile": "0.997000", "date": "2026-06-23"},
    {"epss": "0.750000", "percentile": "0.995000", "date": "2026-06-22"},
    {"epss": "0.600000", "percentile": "0.990000", "date": "2026-06-21"},
    {"epss": "0.500000", "percentile": "0.985000", "date": "2026-06-20"},
    {"epss": "0.050000", "percentile": "0.850000", "date": "2026-06-19"},
    {"epss": "0.010000", "percentile": "0.700000", "date": "2026-06-18"},
]

_MOCK_API_RESPONSE = {
    "status": "OK",
    "data": [
        {
            "cve": "CVE-2024-3094",
            "epss": "0.050000",
            "percentile": "0.850000",
            "date": "2026-06-25",
            "time-series": _SAMPLE_TIME_SERIES,
        }
    ],
}

_MOCK_SPIKE_RESPONSE = {
    "status": "OK",
    "data": [
        {
            "cve": "CVE-2024-3094",
            "epss": "0.900000",
            "percentile": "0.998000",
            "date": "2026-06-25",
            "time-series": _SPIKE_TIME_SERIES,
        }
    ],
}


# ---------------------------------------------------------------------------
# Tool module imports
# ---------------------------------------------------------------------------


def test_get_epss_trend_module_imports():
    """The module must be importable without strands."""
    import manus_use.tools.get_epss_trend as m

    assert hasattr(m, "get_epss_trend")
    assert hasattr(m, "TOOL_SPEC")
    assert hasattr(m, "_analyse_series")
    assert hasattr(m, "_fetch_epss_time_series")


def test_tool_spec_has_required_fields():
    from manus_use.tools.get_epss_trend import TOOL_SPEC

    assert TOOL_SPEC["name"] == "get_epss_trend"
    assert "cve_id" in TOOL_SPEC["inputSchema"]["json"]["properties"]
    assert "days" in TOOL_SPEC["inputSchema"]["json"]["properties"]
    assert TOOL_SPEC["inputSchema"]["json"]["required"] == ["cve_id"]


# ---------------------------------------------------------------------------
# _analyse_series unit tests
# ---------------------------------------------------------------------------


def test_analyse_series_empty():
    from manus_use.tools.get_epss_trend import _analyse_series

    result = _analyse_series([])
    assert result["spike_detected"] is False
    assert result["max_jump"] == 0.0
    assert result["trend"] == "unknown"


def test_analyse_series_stable():
    from manus_use.tools.get_epss_trend import _analyse_series

    series = [{"date": f"2026-06-{10 + i:02d}", "epss": "0.500000", "percentile": "0.900000"} for i in range(10)]
    result = _analyse_series(series)
    assert result["trend"] == "stable"
    assert result["spike_detected"] is False


def test_analyse_series_rising():
    from manus_use.tools.get_epss_trend import _analyse_series

    series = [
        {"date": f"2026-06-{10 + i:02d}", "epss": f"{0.1 + i * 0.05:.6f}", "percentile": "0.900000"} for i in range(10)
    ]
    result = _analyse_series(series)
    assert result["trend"] == "rising"


def test_analyse_series_falling():
    from manus_use.tools.get_epss_trend import _analyse_series

    series = [
        {"date": f"2026-06-{10 + i:02d}", "epss": f"{0.8 - i * 0.05:.6f}", "percentile": "0.900000"} for i in range(10)
    ]
    result = _analyse_series(series)
    assert result["trend"] == "falling"


def test_analyse_series_spike_detected():
    from manus_use.tools.get_epss_trend import _analyse_series

    result = _analyse_series(_SPIKE_TIME_SERIES)
    assert result["spike_detected"] is True
    assert result["max_7d_jump"] >= 0.10


def test_analyse_series_no_spike():
    from manus_use.tools.get_epss_trend import _analyse_series

    result = _analyse_series(_SAMPLE_TIME_SERIES)
    assert result["spike_detected"] is False


def test_analyse_series_returns_sorted_points():
    from manus_use.tools.get_epss_trend import _analyse_series

    shuffled = list(reversed(_SAMPLE_TIME_SERIES))
    result = _analyse_series(shuffled)
    dates = [p["date"] for p in result["points"]]
    assert dates == sorted(dates), "Points must be sorted oldest-first"


def test_analyse_series_current_and_oldest():
    from manus_use.tools.get_epss_trend import _analyse_series

    result = _analyse_series(_SAMPLE_TIME_SERIES)
    assert result["oldest_date"] == "2026-06-18"
    assert result["latest_date"] == "2026-06-24"
    assert abs(result["current_epss"] - 0.05) < 1e-6
    assert abs(result["oldest_epss"] - 0.01) < 1e-6


def test_analyse_series_single_point():
    from manus_use.tools.get_epss_trend import _analyse_series

    result = _analyse_series([{"date": "2026-06-24", "epss": "0.300000", "percentile": "0.900000"}])
    assert result["spike_detected"] is False
    assert result["max_7d_jump"] == 0.0
    assert len(result["points"]) == 1


# ---------------------------------------------------------------------------
# get_epss_trend tool function
# ---------------------------------------------------------------------------


def _make_tool_use(cve_id: str, days: int = 30) -> dict:
    return {"toolUseId": "test-id-001", "input": {"cve_id": cve_id, "days": days}}


def test_tool_returns_error_for_invalid_cve():
    from manus_use.tools.get_epss_trend import get_epss_trend

    result = get_epss_trend(_make_tool_use("NOTACVE"))
    assert result["status"] == "error"
    assert "Invalid CVE ID" in result["content"][0]["text"]


def test_tool_returns_error_for_empty_cve():
    from manus_use.tools.get_epss_trend import get_epss_trend

    result = get_epss_trend(_make_tool_use(""))
    assert result["status"] == "error"


@patch("manus_use.tools.get_epss_trend._fetch_epss_time_series")
def test_tool_success_returns_text_and_json(mock_fetch):
    from manus_use.tools.get_epss_trend import get_epss_trend

    mock_fetch.return_value = _MOCK_API_RESPONSE

    result = get_epss_trend(_make_tool_use("CVE-2024-3094"))
    assert result["status"] == "success"
    # Should have text summary + json analysis
    content_types = [list(c.keys())[0] for c in result["content"]]
    assert "text" in content_types
    assert "json" in content_types


@patch("manus_use.tools.get_epss_trend._fetch_epss_time_series")
def test_tool_success_json_contains_analysis(mock_fetch):
    from manus_use.tools.get_epss_trend import get_epss_trend

    mock_fetch.return_value = _MOCK_API_RESPONSE

    result = get_epss_trend(_make_tool_use("CVE-2024-3094"))
    json_block = next(c["json"] for c in result["content"] if "json" in c)
    assert json_block["cve_id"] == "CVE-2024-3094"
    assert "analysis" in json_block
    assert "spike_detected" in json_block["analysis"]
    assert "trend" in json_block["analysis"]
    assert "points" in json_block["analysis"]


@patch("manus_use.tools.get_epss_trend._fetch_epss_time_series")
def test_tool_spike_detected_flag(mock_fetch):
    from manus_use.tools.get_epss_trend import get_epss_trend

    mock_fetch.return_value = _MOCK_SPIKE_RESPONSE

    result = get_epss_trend(_make_tool_use("CVE-2024-3094"))
    json_block = next(c["json"] for c in result["content"] if "json" in c)
    assert json_block["analysis"]["spike_detected"] is True


@patch("manus_use.tools.get_epss_trend._fetch_epss_time_series")
def test_tool_no_data_returns_error(mock_fetch):
    from manus_use.tools.get_epss_trend import get_epss_trend

    mock_fetch.return_value = {"status": "OK", "data": []}

    result = get_epss_trend(_make_tool_use("CVE-9999-9999"))
    assert result["status"] == "error"
    assert "No EPSS data" in result["content"][0]["text"]


@patch("manus_use.tools.get_epss_trend._fetch_epss_time_series")
def test_tool_api_failure_returns_error(mock_fetch):
    import requests

    from manus_use.tools.get_epss_trend import get_epss_trend

    mock_fetch.side_effect = requests.exceptions.ConnectionError("network unreachable")

    result = get_epss_trend(_make_tool_use("CVE-2024-3094"))
    assert result["status"] == "error"
    assert "EPSS API request failed" in result["content"][0]["text"]


@patch("manus_use.tools.get_epss_trend._fetch_epss_time_series")
def test_tool_normalises_cve_to_uppercase(mock_fetch):
    from manus_use.tools.get_epss_trend import get_epss_trend

    response_copy = {
        "status": "OK",
        "data": [
            {
                "cve": "CVE-2024-3094",
                "epss": "0.860000",
                "percentile": "0.997000",
                "date": "2026-06-25",
                "time-series": _SAMPLE_TIME_SERIES,
            }
        ],
    }
    mock_fetch.return_value = response_copy

    result = get_epss_trend(_make_tool_use("cve-2024-3094"))
    assert result["status"] == "success"
    json_block = next(c["json"] for c in result["content"] if "json" in c)
    assert json_block["cve_id"] == "CVE-2024-3094"


# ---------------------------------------------------------------------------
# CLI subcommand tests
# ---------------------------------------------------------------------------


def test_epss_trend_subcommand_registered_in_main():
    from manus_use.cli import _SUBCOMMANDS

    assert "epss-trend" in _SUBCOMMANDS


def test_epss_trend_help_exits_zero():
    from manus_use.cli import _build_epss_trend_parser

    parser = _build_epss_trend_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--help"])
    assert exc_info.value.code == 0


def test_epss_trend_missing_cve_is_error():
    from manus_use.cli import _build_epss_trend_parser

    parser = _build_epss_trend_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args([])
    assert exc_info.value.code != 0


def test_epss_trend_parser_defaults():
    from manus_use.cli import _build_epss_trend_parser

    parser = _build_epss_trend_parser()
    args = parser.parse_args(["CVE-2024-3094"])
    assert args.cve_id == "CVE-2024-3094"
    assert args.days == 30
    assert args.output == "text"


def test_epss_trend_parser_custom_days():
    from manus_use.cli import _build_epss_trend_parser

    parser = _build_epss_trend_parser()
    args = parser.parse_args(["CVE-2024-3094", "--days", "90"])
    assert args.days == 90


def test_epss_trend_parser_json_output():
    from manus_use.cli import _build_epss_trend_parser

    parser = _build_epss_trend_parser()
    args = parser.parse_args(["CVE-2024-3094", "--output", "json"])
    assert args.output == "json"


@patch("manus_use.tools.get_epss_trend._fetch_epss_time_series")
def test_run_epss_trend_text_output(mock_fetch, capsys):
    from manus_use.cli import _run_epss_trend

    mock_fetch.return_value = _MOCK_API_RESPONSE
    rc = _run_epss_trend(["CVE-2024-3094"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CVE-2024-3094" in out
    assert "EPSS trend" in out


@patch("manus_use.tools.get_epss_trend._fetch_epss_time_series")
def test_run_epss_trend_json_output(mock_fetch, capsys):
    from manus_use.cli import _run_epss_trend

    mock_fetch.return_value = _MOCK_API_RESPONSE
    rc = _run_epss_trend(["CVE-2024-3094", "--output", "json"])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["cve_id"] == "CVE-2024-3094"
    assert "analysis" in data


@patch("manus_use.tools.get_epss_trend._fetch_epss_time_series")
def test_run_epss_trend_spike_shown_in_text(mock_fetch, capsys):
    from manus_use.cli import _run_epss_trend

    mock_fetch.return_value = _MOCK_SPIKE_RESPONSE
    rc = _run_epss_trend(["CVE-2024-3094"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "SPIKE" in out


@patch("manus_use.tools.get_epss_trend._fetch_epss_time_series")
def test_run_epss_trend_no_data_returns_nonzero(mock_fetch):
    from manus_use.cli import _run_epss_trend

    mock_fetch.return_value = {"status": "OK", "data": []}
    rc = _run_epss_trend(["CVE-9999-9999"])
    assert rc != 0


@patch("manus_use.tools.get_epss_trend._fetch_epss_time_series")
def test_run_epss_trend_api_error_returns_nonzero(mock_fetch):
    import requests

    from manus_use.cli import _run_epss_trend

    mock_fetch.side_effect = requests.exceptions.ConnectionError("down")
    rc = _run_epss_trend(["CVE-2024-3094"])
    assert rc != 0


# ---------------------------------------------------------------------------
# vi_agent integration: get_epss_trend is in the tool list
# ---------------------------------------------------------------------------


def test_vi_agent_imports_get_epss_trend():
    """get_epss_trend module must be importable and have the expected interface."""
    from manus_use.tools.get_epss_trend import TOOL_SPEC, get_epss_trend

    assert callable(get_epss_trend)
    assert TOOL_SPEC["name"] == "get_epss_trend"


# ---------------------------------------------------------------------------
# README coverage
# ---------------------------------------------------------------------------


def test_readme_documents_epss_trend():
    """README must document the epss-trend subcommand."""
    from pathlib import Path

    readme = Path(__file__).resolve().parents[1] / "README.md"
    content = readme.read_text()
    assert "epss-trend" in content, "README must mention the epss-trend subcommand"
    assert "EPSS" in content, "README must mention EPSS"


def test_readme_epss_trend_has_options_table():
    """README epss-trend section must document --days and --output flags."""
    from pathlib import Path

    readme = Path(__file__).resolve().parents[1] / "README.md"
    content = readme.read_text()
    assert "--days" in content
    assert "--output" in content


def test_readme_epss_trend_example_commands():
    """README must include example commands for epss-trend."""
    from pathlib import Path

    readme = Path(__file__).resolve().parents[1] / "README.md"
    content = readme.read_text()
    assert "manus-use epss-trend CVE-" in content
