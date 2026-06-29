"""Tests for the score_epss_decay tool and epss-decay CLI subcommand.

All tests are unit tests that mock the FIRST.org API; no network calls are made.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------

# A "well-behaved decay" series: peaked at 0.85, now at 0.10 (11.8% of peak).
_DECAYED_SERIES = [
    {"date": "2026-01-01", "epss": "0.050000", "percentile": "0.850000"},
    {"date": "2026-01-15", "epss": "0.400000", "percentile": "0.960000"},
    {"date": "2026-02-01", "epss": "0.850000", "percentile": "0.998000"},
    {"date": "2026-02-08", "epss": "0.820000", "percentile": "0.997000"},
    {"date": "2026-03-01", "epss": "0.500000", "percentile": "0.985000"},
    {"date": "2026-04-01", "epss": "0.200000", "percentile": "0.920000"},
    {"date": "2026-05-01", "epss": "0.100000", "percentile": "0.870000"},
    {"date": "2026-06-01", "epss": "0.100000", "percentile": "0.870000"},
]

# A "moderate decay" series: peaked at 0.60, now at 0.30 (50% of peak).
_MODERATE_DECAY_SERIES = [
    {"date": "2026-01-01", "epss": "0.100000", "percentile": "0.800000"},
    {"date": "2026-02-01", "epss": "0.600000", "percentile": "0.990000"},
    {"date": "2026-03-01", "epss": "0.500000", "percentile": "0.985000"},
    {"date": "2026-04-01", "epss": "0.400000", "percentile": "0.970000"},
    {"date": "2026-05-01", "epss": "0.300000", "percentile": "0.945000"},
]

# A "stable" series: peaked at 0.70, currently at 0.65 (92.9% of peak).
_STABLE_SERIES = [
    {"date": "2026-01-01", "epss": "0.500000", "percentile": "0.980000"},
    {"date": "2026-02-01", "epss": "0.700000", "percentile": "0.995000"},
    {"date": "2026-03-01", "epss": "0.680000", "percentile": "0.994000"},
    {"date": "2026-04-01", "epss": "0.670000", "percentile": "0.993000"},
    {"date": "2026-05-01", "epss": "0.650000", "percentile": "0.992000"},
]

# A "never peaked" series: max EPSS 0.08, well below _PEAK_BASELINE.
_NEVER_PEAKED_SERIES = [
    {"date": "2026-01-01", "epss": "0.010000", "percentile": "0.500000"},
    {"date": "2026-02-01", "epss": "0.030000", "percentile": "0.550000"},
    {"date": "2026-03-01", "epss": "0.080000", "percentile": "0.600000"},
    {"date": "2026-04-01", "epss": "0.050000", "percentile": "0.580000"},
    {"date": "2026-05-01", "epss": "0.020000", "percentile": "0.510000"},
]


def _make_api_response(cve_id: str, series: list[dict]) -> dict:
    """Build a FIRST.org-shaped API response from a series list."""
    current = series[-1] if series else {}
    return {
        "status": "OK",
        "data": [
            {
                "cve": cve_id,
                "epss": current.get("epss", "0"),
                "percentile": current.get("percentile", "0"),
                "date": current.get("date", "2026-06-01"),
                "time-series": series,
            }
        ],
    }


def _make_tool_use(cve_id: str, days: int = 365) -> dict:
    return {"toolUseId": "test-id-decay", "input": {"cve_id": cve_id, "days": days}}


# ---------------------------------------------------------------------------
# Module import checks
# ---------------------------------------------------------------------------


def test_module_imports():
    """score_epss_decay is importable without strands."""
    import manus_agent.tools.score_epss_decay as m

    assert hasattr(m, "score_epss_decay")
    assert hasattr(m, "TOOL_SPEC")
    assert hasattr(m, "_analyse_decay")


def test_tool_spec_structure():
    from manus_agent.tools.score_epss_decay import TOOL_SPEC

    assert TOOL_SPEC["name"] == "score_epss_decay"
    props = TOOL_SPEC["inputSchema"]["json"]["properties"]
    assert "cve_id" in props
    assert "days" in props
    assert TOOL_SPEC["inputSchema"]["json"]["required"] == ["cve_id"]


def test_tool_spec_days_default():
    from manus_agent.tools.score_epss_decay import TOOL_SPEC

    assert TOOL_SPEC["inputSchema"]["json"]["properties"]["days"]["default"] == 365


# ---------------------------------------------------------------------------
# _analyse_decay unit tests
# ---------------------------------------------------------------------------


def test_analyse_decay_empty():
    from manus_agent.tools.score_epss_decay import _analyse_decay

    result = _analyse_decay([])
    assert result["class"] == "unknown"
    assert result["peak_epss"] is None
    assert result["current_epss"] is None
    assert "No EPSS data" in result["interpretation"]


def test_analyse_decay_significant():
    from manus_agent.tools.score_epss_decay import _analyse_decay

    result = _analyse_decay(_DECAYED_SERIES)
    assert result["class"] == "significant_decay"
    assert abs(result["peak_epss"] - 0.85) < 1e-5
    assert abs(result["current_epss"] - 0.10) < 1e-5
    assert result["decay_ratio"] < 0.40


def test_analyse_decay_moderate():
    from manus_agent.tools.score_epss_decay import _analyse_decay

    result = _analyse_decay(_MODERATE_DECAY_SERIES)
    assert result["class"] == "moderate_decay"
    assert abs(result["peak_epss"] - 0.60) < 1e-5
    assert abs(result["current_epss"] - 0.30) < 1e-5
    assert 0.40 <= result["decay_ratio"] < 0.70


def test_analyse_decay_stable():
    from manus_agent.tools.score_epss_decay import _analyse_decay

    result = _analyse_decay(_STABLE_SERIES)
    assert result["class"] == "stable"
    assert result["decay_ratio"] >= 0.70


def test_analyse_decay_never_peaked():
    from manus_agent.tools.score_epss_decay import _analyse_decay

    result = _analyse_decay(_NEVER_PEAKED_SERIES)
    assert result["class"] == "never_peaked"
    assert "never" in result["interpretation"].lower() or "baseline" in result["interpretation"].lower()


def test_analyse_decay_peak_date():
    from manus_agent.tools.score_epss_decay import _analyse_decay

    result = _analyse_decay(_DECAYED_SERIES)
    # Peak is on 2026-02-01 (value 0.85)
    assert result["peak_date"] == "2026-02-01"


def test_analyse_decay_current_date():
    from manus_agent.tools.score_epss_decay import _analyse_decay

    result = _analyse_decay(_DECAYED_SERIES)
    # Latest date in the series
    assert result["current_date"] == "2026-06-01"


def test_analyse_decay_days_since_peak():
    from manus_agent.tools.score_epss_decay import _analyse_decay

    result = _analyse_decay(_DECAYED_SERIES)
    # 2026-02-01 → 2026-06-01 = 120 days
    assert result["days_since_peak"] == 120


def test_analyse_decay_decay_ratio_range():
    from manus_agent.tools.score_epss_decay import _analyse_decay

    result = _analyse_decay(_DECAYED_SERIES)
    assert 0.0 <= result["decay_ratio"] <= 1.0


def test_analyse_decay_decay_rate_is_positive_for_decay():
    from manus_agent.tools.score_epss_decay import _analyse_decay

    result = _analyse_decay(_DECAYED_SERIES)
    # Rate should be positive (peak > current → positive weekly drop)
    assert result["decay_rate_per_week"] > 0


def test_analyse_decay_decay_rate_is_none_for_zero_days():
    """If peak is today (days_since_peak==0), rate is undefined → None."""
    from manus_agent.tools.score_epss_decay import _analyse_decay

    series = [{"date": "2026-06-01", "epss": "0.800000", "percentile": "0.990000"}]
    result = _analyse_decay(series)
    # Single point: peak == current, days_since_peak == 0 → rate None
    assert result["decay_rate_per_week"] is None


def test_analyse_decay_single_point_stable():
    from manus_agent.tools.score_epss_decay import _analyse_decay

    series = [{"date": "2026-06-01", "epss": "0.800000", "percentile": "0.990000"}]
    result = _analyse_decay(series)
    # Single high-value point: peak == current, should be stable
    assert result["class"] == "stable"
    assert result["decay_ratio"] == 1.0


def test_analyse_decay_single_low_point_never_peaked():
    from manus_agent.tools.score_epss_decay import _analyse_decay

    series = [{"date": "2026-06-01", "epss": "0.010000", "percentile": "0.500000"}]
    result = _analyse_decay(series)
    assert result["class"] == "never_peaked"


def test_analyse_decay_unsorted_input():
    """_analyse_decay must handle input that is not sorted by date."""
    from manus_agent.tools.score_epss_decay import _analyse_decay

    shuffled = list(reversed(_DECAYED_SERIES))
    result = _analyse_decay(shuffled)
    # Should produce the same result regardless of input order
    assert result["class"] == "significant_decay"
    assert result["current_date"] == "2026-06-01"


def test_analyse_decay_peak_sustained_days_basic():
    from manus_agent.tools.score_epss_decay import _analyse_decay

    result = _analyse_decay(_DECAYED_SERIES)
    # Peak at index 2 (0.85); next day 0.82 is within 10% band; then 0.50 is not
    assert result["peak_sustained_days"] >= 1


def test_analyse_decay_points_sorted_oldest_first():
    from manus_agent.tools.score_epss_decay import _analyse_decay

    result = _analyse_decay(_DECAYED_SERIES)
    dates = [p["date"] for p in result["points"]]
    assert dates == sorted(dates), "points must be sorted oldest-first"


def test_analyse_decay_interpretation_non_empty():
    from manus_agent.tools.score_epss_decay import _analyse_decay

    for series in [_DECAYED_SERIES, _MODERATE_DECAY_SERIES, _STABLE_SERIES, _NEVER_PEAKED_SERIES]:
        result = _analyse_decay(series)
        assert isinstance(result["interpretation"], str)
        assert len(result["interpretation"]) > 10


# ---------------------------------------------------------------------------
# score_epss_decay tool function
# ---------------------------------------------------------------------------


def test_tool_invalid_cve_format():
    from manus_agent.tools.score_epss_decay import score_epss_decay

    result = score_epss_decay(_make_tool_use("NOTACVE"))
    assert result["status"] == "error"
    assert "Invalid CVE ID" in result["content"][0]["text"]


def test_tool_empty_cve():
    from manus_agent.tools.score_epss_decay import score_epss_decay

    result = score_epss_decay(_make_tool_use(""))
    assert result["status"] == "error"


def test_tool_lowercase_cve_normalised():
    """Lowercase CVE IDs must be accepted and normalised to uppercase."""
    from manus_agent.tools.score_epss_decay import score_epss_decay

    with patch(
        "manus_agent.tools.score_epss_decay._fetch_epss_time_series",
        return_value=_make_api_response("CVE-2021-44228", _DECAYED_SERIES),
    ):
        result = score_epss_decay(_make_tool_use("cve-2021-44228"))
    assert result["status"] == "success"
    json_block = next(c["json"] for c in result["content"] if "json" in c)
    assert json_block["cve_id"] == "CVE-2021-44228"


@patch("manus_agent.tools.score_epss_decay._fetch_epss_time_series")
def test_tool_success_significant_decay(mock_fetch):
    from manus_agent.tools.score_epss_decay import score_epss_decay

    mock_fetch.return_value = _make_api_response("CVE-2021-44228", _DECAYED_SERIES)
    result = score_epss_decay(_make_tool_use("CVE-2021-44228"))
    assert result["status"] == "success"


@patch("manus_agent.tools.score_epss_decay._fetch_epss_time_series")
def test_tool_success_returns_text_and_json(mock_fetch):
    from manus_agent.tools.score_epss_decay import score_epss_decay

    mock_fetch.return_value = _make_api_response("CVE-2021-44228", _DECAYED_SERIES)
    result = score_epss_decay(_make_tool_use("CVE-2021-44228"))
    content_types = [list(c.keys())[0] for c in result["content"]]
    assert "text" in content_types
    assert "json" in content_types


@patch("manus_agent.tools.score_epss_decay._fetch_epss_time_series")
def test_tool_json_contains_decay_object(mock_fetch):
    from manus_agent.tools.score_epss_decay import score_epss_decay

    mock_fetch.return_value = _make_api_response("CVE-2021-44228", _DECAYED_SERIES)
    result = score_epss_decay(_make_tool_use("CVE-2021-44228"))
    json_block = next(c["json"] for c in result["content"] if "json" in c)
    assert "decay" in json_block
    assert "class" in json_block["decay"]
    assert "peak_epss" in json_block["decay"]
    assert "current_epss" in json_block["decay"]
    assert "days_since_peak" in json_block["decay"]
    assert "interpretation" in json_block["decay"]


@patch("manus_agent.tools.score_epss_decay._fetch_epss_time_series")
def test_tool_json_does_not_contain_verbose_points(mock_fetch):
    """JSON payload must not include the raw points list (keeps agent context lean)."""
    from manus_agent.tools.score_epss_decay import score_epss_decay

    mock_fetch.return_value = _make_api_response("CVE-2021-44228", _DECAYED_SERIES)
    result = score_epss_decay(_make_tool_use("CVE-2021-44228"))
    json_block = next(c["json"] for c in result["content"] if "json" in c)
    assert "points" not in json_block["decay"], "points list must be excluded from JSON payload"


@patch("manus_agent.tools.score_epss_decay._fetch_epss_time_series")
def test_tool_significant_decay_classification(mock_fetch):
    from manus_agent.tools.score_epss_decay import score_epss_decay

    mock_fetch.return_value = _make_api_response("CVE-2021-44228", _DECAYED_SERIES)
    result = score_epss_decay(_make_tool_use("CVE-2021-44228"))
    json_block = next(c["json"] for c in result["content"] if "json" in c)
    assert json_block["decay"]["class"] == "significant_decay"


@patch("manus_agent.tools.score_epss_decay._fetch_epss_time_series")
def test_tool_never_peaked_classification(mock_fetch):
    from manus_agent.tools.score_epss_decay import score_epss_decay

    mock_fetch.return_value = _make_api_response("CVE-2026-9999", _NEVER_PEAKED_SERIES)
    result = score_epss_decay(_make_tool_use("CVE-2026-9999"))
    json_block = next(c["json"] for c in result["content"] if "json" in c)
    assert json_block["decay"]["class"] == "never_peaked"


@patch("manus_agent.tools.score_epss_decay._fetch_epss_time_series")
def test_tool_data_points_count(mock_fetch):
    from manus_agent.tools.score_epss_decay import score_epss_decay

    mock_fetch.return_value = _make_api_response("CVE-2021-44228", _DECAYED_SERIES)
    result = score_epss_decay(_make_tool_use("CVE-2021-44228"))
    json_block = next(c["json"] for c in result["content"] if "json" in c)
    assert json_block["data_points_available"] == len(_DECAYED_SERIES)


@patch("manus_agent.tools.score_epss_decay._fetch_epss_time_series")
def test_tool_no_data_returns_error(mock_fetch):
    from manus_agent.tools.score_epss_decay import score_epss_decay

    mock_fetch.return_value = {"status": "OK", "data": []}
    result = score_epss_decay(_make_tool_use("CVE-9999-9999"))
    assert result["status"] == "error"
    assert "No EPSS data" in result["content"][0]["text"]


@patch("manus_agent.tools.score_epss_decay._fetch_epss_time_series")
def test_tool_api_failure_returns_error(mock_fetch):
    import requests

    from manus_agent.tools.score_epss_decay import score_epss_decay

    mock_fetch.side_effect = requests.exceptions.ConnectionError("unreachable")
    result = score_epss_decay(_make_tool_use("CVE-2021-44228"))
    assert result["status"] == "error"
    assert "EPSS API request failed" in result["content"][0]["text"]


@patch("manus_agent.tools.score_epss_decay._fetch_epss_time_series")
def test_tool_single_point_fallback(mock_fetch):
    """When API returns no time-series, fall back to the single top-level data point."""
    from manus_agent.tools.score_epss_decay import score_epss_decay

    mock_fetch.return_value = {
        "status": "OK",
        "data": [
            {
                "cve": "CVE-2021-44228",
                "epss": "0.950000",
                "percentile": "0.999000",
                "date": "2026-06-01",
                # no "time-series" key
            }
        ],
    }
    result = score_epss_decay(_make_tool_use("CVE-2021-44228"))
    assert result["status"] == "success"


@patch("manus_agent.tools.score_epss_decay._fetch_epss_time_series")
def test_tool_days_clamped_to_365(mock_fetch):
    """days > 365 must be silently clamped to 365."""
    from manus_agent.tools.score_epss_decay import score_epss_decay

    mock_fetch.return_value = _make_api_response("CVE-2021-44228", _DECAYED_SERIES)
    result = score_epss_decay(_make_tool_use("CVE-2021-44228", days=9999))
    assert result["status"] == "success"
    # Verify the clamp was applied by checking that _fetch was called with ≤ 365
    call_days = mock_fetch.call_args[0][1]
    assert call_days <= 365


@patch("manus_agent.tools.score_epss_decay._fetch_epss_time_series")
def test_tool_text_output_contains_cve_id(mock_fetch, capsys):
    from manus_agent.tools.score_epss_decay import score_epss_decay

    mock_fetch.return_value = _make_api_response("CVE-2021-44228", _DECAYED_SERIES)
    result = score_epss_decay(_make_tool_use("CVE-2021-44228"))
    text_block = next(c["text"] for c in result["content"] if "text" in c)
    assert "CVE-2021-44228" in text_block


@patch("manus_agent.tools.score_epss_decay._fetch_epss_time_series")
def test_tool_text_output_contains_decay_class(mock_fetch):
    from manus_agent.tools.score_epss_decay import score_epss_decay

    mock_fetch.return_value = _make_api_response("CVE-2021-44228", _DECAYED_SERIES)
    result = score_epss_decay(_make_tool_use("CVE-2021-44228"))
    text_block = next(c["text"] for c in result["content"] if "text" in c)
    assert "SIGNIFICANT_DECAY" in text_block


# ---------------------------------------------------------------------------
# CLI subcommand: registration and parser
# ---------------------------------------------------------------------------


def test_epss_decay_subcommand_registered():
    from manus_agent.cli import _SUBCOMMANDS

    assert "epss-decay" in _SUBCOMMANDS


def test_epss_decay_parser_help_exits_zero():
    from manus_agent.cli import _build_epss_decay_parser

    parser = _build_epss_decay_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--help"])
    assert exc_info.value.code == 0


def test_epss_decay_parser_missing_cve_errors():
    from manus_agent.cli import _build_epss_decay_parser

    parser = _build_epss_decay_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args([])
    assert exc_info.value.code != 0


def test_epss_decay_parser_defaults():
    from manus_agent.cli import _build_epss_decay_parser

    parser = _build_epss_decay_parser()
    args = parser.parse_args(["CVE-2021-44228"])
    assert args.cve_id == "CVE-2021-44228"
    assert args.days == 365
    assert args.output == "text"


def test_epss_decay_parser_custom_days():
    from manus_agent.cli import _build_epss_decay_parser

    parser = _build_epss_decay_parser()
    args = parser.parse_args(["CVE-2021-44228", "--days", "90"])
    assert args.days == 90


def test_epss_decay_parser_json_output():
    from manus_agent.cli import _build_epss_decay_parser

    parser = _build_epss_decay_parser()
    args = parser.parse_args(["CVE-2021-44228", "--output", "json"])
    assert args.output == "json"


# ---------------------------------------------------------------------------
# CLI subcommand: _run_epss_decay
# ---------------------------------------------------------------------------


@patch("manus_agent.tools.get_epss_trend._fetch_epss_time_series")
def test_run_epss_decay_text_output_rc_zero(mock_fetch, capsys):
    from manus_agent.cli import _run_epss_decay

    mock_fetch.return_value = _make_api_response("CVE-2021-44228", _DECAYED_SERIES)
    rc = _run_epss_decay(["CVE-2021-44228"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CVE-2021-44228" in out
    assert "EPSS Decay" in out


@patch("manus_agent.tools.get_epss_trend._fetch_epss_time_series")
def test_run_epss_decay_json_output_valid(mock_fetch, capsys):
    from manus_agent.cli import _run_epss_decay

    mock_fetch.return_value = _make_api_response("CVE-2021-44228", _DECAYED_SERIES)
    rc = _run_epss_decay(["CVE-2021-44228", "--output", "json"])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["cve_id"] == "CVE-2021-44228"
    assert "decay" in data
    assert "class" in data["decay"]


@patch("manus_agent.tools.get_epss_trend._fetch_epss_time_series")
def test_run_epss_decay_text_shows_decay_class(mock_fetch, capsys):
    from manus_agent.cli import _run_epss_decay

    mock_fetch.return_value = _make_api_response("CVE-2021-44228", _DECAYED_SERIES)
    _run_epss_decay(["CVE-2021-44228"])
    out = capsys.readouterr().out
    assert "SIGNIFICANT_DECAY" in out


@patch("manus_agent.tools.get_epss_trend._fetch_epss_time_series")
def test_run_epss_decay_never_peaked_text(mock_fetch, capsys):
    from manus_agent.cli import _run_epss_decay

    mock_fetch.return_value = _make_api_response("CVE-2026-9999", _NEVER_PEAKED_SERIES)
    rc = _run_epss_decay(["CVE-2026-9999"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "NEVER_PEAKED" in out


@patch("manus_agent.tools.get_epss_trend._fetch_epss_time_series")
def test_run_epss_decay_no_data_nonzero(mock_fetch):
    from manus_agent.cli import _run_epss_decay

    mock_fetch.return_value = {"status": "OK", "data": []}
    rc = _run_epss_decay(["CVE-9999-9999"])
    assert rc != 0


@patch("manus_agent.tools.get_epss_trend._fetch_epss_time_series")
def test_run_epss_decay_api_error_nonzero(mock_fetch):
    import requests

    from manus_agent.cli import _run_epss_decay

    mock_fetch.side_effect = requests.exceptions.ConnectionError("down")
    rc = _run_epss_decay(["CVE-2021-44228"])
    assert rc != 0


def test_run_epss_decay_invalid_cve_nonzero():
    """Non-CVE positional arg should exit non-zero."""
    from manus_agent.cli import _run_epss_decay

    with pytest.raises(SystemExit) as exc_info:
        _run_epss_decay(["NOTACVE"])
    assert exc_info.value.code != 0


@patch("manus_agent.tools.get_epss_trend._fetch_epss_time_series")
def test_run_epss_decay_json_days_recorded(mock_fetch, capsys):
    from manus_agent.cli import _run_epss_decay

    mock_fetch.return_value = _make_api_response("CVE-2021-44228", _DECAYED_SERIES)
    _run_epss_decay(["CVE-2021-44228", "--days", "180", "--output", "json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["days_requested"] == 180


@patch("manus_agent.tools.get_epss_trend._fetch_epss_time_series")
def test_run_epss_decay_text_shows_peak_date(mock_fetch, capsys):
    from manus_agent.cli import _run_epss_decay

    mock_fetch.return_value = _make_api_response("CVE-2021-44228", _DECAYED_SERIES)
    _run_epss_decay(["CVE-2021-44228"])
    out = capsys.readouterr().out
    assert "2026-02-01" in out  # peak date


@patch("manus_agent.tools.get_epss_trend._fetch_epss_time_series")
def test_run_epss_decay_text_shows_interpretation(mock_fetch, capsys):
    from manus_agent.cli import _run_epss_decay

    mock_fetch.return_value = _make_api_response("CVE-2021-44228", _DECAYED_SERIES)
    _run_epss_decay(["CVE-2021-44228"])
    out = capsys.readouterr().out
    # Interpretation must appear
    assert any(word in out.lower() for word in ["attacker", "interest", "peaked", "waned"])


# ---------------------------------------------------------------------------
# vi_agent integration
# ---------------------------------------------------------------------------


def test_vi_agent_imports_score_epss_decay():
    """score_epss_decay must be importable and have the expected interface."""
    from manus_agent.tools.score_epss_decay import TOOL_SPEC, score_epss_decay

    assert callable(score_epss_decay)
    assert TOOL_SPEC["name"] == "score_epss_decay"


# ---------------------------------------------------------------------------
# README documentation checks
# ---------------------------------------------------------------------------


def test_readme_documents_epss_decay():
    from pathlib import Path

    readme = Path(__file__).resolve().parents[1] / "README.md"
    content = readme.read_text()
    assert "epss-decay" in content, "README must document the epss-decay subcommand"


def test_readme_epss_decay_flags():
    from pathlib import Path

    readme = Path(__file__).resolve().parents[1] / "README.md"
    content = readme.read_text()
    assert "--days" in content
    assert "--output" in content


def test_readme_epss_decay_example_command():
    from pathlib import Path

    readme = Path(__file__).resolve().parents[1] / "README.md"
    content = readme.read_text()
    assert "manus-agent epss-decay CVE-" in content


def test_readme_epss_decay_mentions_decay_classes():
    from pathlib import Path

    readme = Path(__file__).resolve().parents[1] / "README.md"
    content = readme.read_text()
    assert "significant_decay" in content
    assert "never_peaked" in content
