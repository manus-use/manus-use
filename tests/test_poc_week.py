"""Tests for the get_poc_week tool."""

from __future__ import annotations

from datetime import date
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest

from manus_agent.tools.get_poc_week import (
    _last_sunday,
    _parse_poc_week,
    _url_for_date,
    get_poc_week,
)

# ---------------------------------------------------------------------------
# Sample HTML fixture — mirrors real PoC Week structure
# ---------------------------------------------------------------------------

SAMPLE_HTML = """
## CVE-2026-33824

- Severity: 9.8 CRITICAL
- Impacted Products: Microsoft Windows, IKEv2
- Description: A double free vulnerability in IKE Service Extensions allows RCE.
- PoC:

https://github.com/z3r0h3ro/CVE-2026-33824

## CVE-2026-32201 NEW

- Severity: 6.5 MEDIUM
- Impacted Products: Microsoft SharePoint
- Description: Improper input validation allows spoofing.
- PoC:

https://github.com/B1tBit/CVE-2026-32201-exploit

## CVE-2026-40175

- Severity: 10.0 CRITICAL
- Impacted Products: Axios
- PoC:

https://github.com/pjt3591oo/CVE-2026-40175-poc
https://github.com/kengzzzz/CVE-2026-40175
"""

# ---------------------------------------------------------------------------
# _last_sunday
# ---------------------------------------------------------------------------


def test_last_sunday_on_sunday():
    # 2026-06-21 is a Sunday
    d = date(2026, 6, 21)
    assert _last_sunday(d) == d


def test_last_sunday_on_monday():
    d = date(2026, 6, 22)  # Monday
    assert _last_sunday(d) == date(2026, 6, 21)


def test_last_sunday_on_saturday():
    d = date(2026, 6, 27)  # Saturday
    assert _last_sunday(d) == date(2026, 6, 21)


# ---------------------------------------------------------------------------
# _url_for_date
# ---------------------------------------------------------------------------


def test_url_for_date():
    d = date(2026, 4, 27)
    assert _url_for_date(d) == "https://tonyharris.io/poc-week/poc-week-20260427/"


# ---------------------------------------------------------------------------
# _parse_poc_week
# ---------------------------------------------------------------------------


def test_parse_returns_list():
    results = _parse_poc_week(SAMPLE_HTML)
    assert isinstance(results, list)


def test_parse_cve_count():
    results = _parse_poc_week(SAMPLE_HTML)
    assert len(results) == 3


def test_parse_cve_ids():
    results = _parse_poc_week(SAMPLE_HTML)
    ids = [r["cve_id"] for r in results]
    assert "CVE-2026-33824" in ids
    assert "CVE-2026-32201" in ids
    assert "CVE-2026-40175" in ids


def test_parse_mention_rank_ordering():
    results = _parse_poc_week(SAMPLE_HTML)
    ranks = [r["mention_rank"] for r in results]
    assert ranks == sorted(ranks)
    assert ranks[0] == 1


def test_parse_is_new_flag():
    results = _parse_poc_week(SAMPLE_HTML)
    by_id = {r["cve_id"]: r for r in results}
    assert by_id["CVE-2026-32201"]["is_new"] is True
    assert by_id["CVE-2026-33824"]["is_new"] is False


def test_parse_severity():
    results = _parse_poc_week(SAMPLE_HTML)
    by_id = {r["cve_id"]: r for r in results}
    assert by_id["CVE-2026-33824"]["severity"] == "9.8 CRITICAL"
    assert by_id["CVE-2026-32201"]["severity"] == "6.5 MEDIUM"
    assert by_id["CVE-2026-40175"]["severity"] == "10.0 CRITICAL"


def test_parse_poc_urls_present():
    results = _parse_poc_week(SAMPLE_HTML)
    by_id = {r["cve_id"]: r for r in results}
    assert len(by_id["CVE-2026-33824"]["poc_urls"]) >= 1
    assert any("CVE-2026-33824" in u for u in by_id["CVE-2026-33824"]["poc_urls"])


def test_parse_multiple_poc_urls():
    results = _parse_poc_week(SAMPLE_HTML)
    by_id = {r["cve_id"]: r for r in results}
    assert len(by_id["CVE-2026-40175"]["poc_urls"]) >= 2


def test_parse_empty_html():
    assert _parse_poc_week("") == []
    assert _parse_poc_week("<html><body>No CVEs here</body></html>") == []


# ---------------------------------------------------------------------------
# get_poc_week — happy path (mocked HTTP)
# ---------------------------------------------------------------------------


def _make_mock_response(html: str):
    mock_resp = MagicMock()
    mock_resp.read.return_value = html.encode("utf-8")
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


@patch("manus_agent.tools.get_poc_week.urlopen")
def test_get_poc_week_returns_dict(mock_urlopen):
    mock_urlopen.return_value = _make_mock_response(SAMPLE_HTML)
    result = get_poc_week("2026-04-27")
    assert isinstance(result, dict)
    assert "error" not in result


@patch("manus_agent.tools.get_poc_week.urlopen")
def test_get_poc_week_week_date(mock_urlopen):
    mock_urlopen.return_value = _make_mock_response(SAMPLE_HTML)
    result = get_poc_week("2026-04-26")  # 2026-04-26 is a Sunday
    assert result["week_date"] == "2026-04-26"


@patch("manus_agent.tools.get_poc_week.urlopen")
def test_get_poc_week_url_field(mock_urlopen):
    mock_urlopen.return_value = _make_mock_response(SAMPLE_HTML)
    result = get_poc_week("2026-04-26")  # Sunday
    assert "20260426" in result["url"]


@patch("manus_agent.tools.get_poc_week.urlopen")
def test_get_poc_week_total(mock_urlopen):
    mock_urlopen.return_value = _make_mock_response(SAMPLE_HTML)
    result = get_poc_week("2026-04-26")  # Sunday
    assert result["total"] == len(result["cves"])
    assert result["total"] == 3


@patch("manus_agent.tools.get_poc_week.urlopen")
def test_get_poc_week_rounds_to_sunday(mock_urlopen):
    """Mid-week date should round back to the preceding Sunday."""
    mock_urlopen.return_value = _make_mock_response(SAMPLE_HTML)
    result = get_poc_week("2026-04-29")  # Wednesday
    assert result["week_date"] == "2026-04-26"  # prior Sunday


@patch("manus_agent.tools.get_poc_week.urlopen")
def test_get_poc_week_no_date_uses_today(mock_urlopen):
    mock_urlopen.return_value = _make_mock_response(SAMPLE_HTML)
    result = get_poc_week()
    assert "week_date" in result
    assert "error" not in result


# ---------------------------------------------------------------------------
# get_poc_week — error handling
# ---------------------------------------------------------------------------


def test_get_poc_week_invalid_date():
    result = get_poc_week("not-a-date")
    assert "error" in result


@patch("manus_agent.tools.get_poc_week.urlopen")
def test_get_poc_week_404_retries_and_fails(mock_urlopen):
    mock_urlopen.side_effect = HTTPError(url="https://example.com", code=404, msg="Not Found", hdrs=None, fp=None)
    result = get_poc_week("2026-04-27", max_retries=2)
    assert "error" in result
    assert "No PoC Week issue found" in result["error"]


@patch("manus_agent.tools.get_poc_week.urlopen")
def test_get_poc_week_404_then_success(mock_urlopen):
    """First call returns 404; second call (prior week) succeeds."""
    http_err = HTTPError(url="https://example.com", code=404, msg="Not Found", hdrs=None, fp=None)
    mock_urlopen.side_effect = [http_err, _make_mock_response(SAMPLE_HTML)]
    result = get_poc_week("2026-04-26", max_retries=2)  # Sunday
    assert "error" not in result
    assert result["total"] == 3


@patch("manus_agent.tools.get_poc_week.urlopen")
def test_get_poc_week_network_error(mock_urlopen):
    mock_urlopen.side_effect = URLError("Connection refused")
    result = get_poc_week("2026-04-27")
    assert "error" in result
    assert "Network error" in result["error"]


@patch("manus_agent.tools.get_poc_week.urlopen")
def test_get_poc_week_non_404_http_error(mock_urlopen):
    mock_urlopen.side_effect = HTTPError(
        url="https://example.com", code=503, msg="Service Unavailable", hdrs=None, fp=None
    )
    result = get_poc_week("2026-04-27")
    assert "error" in result
    assert "503" in result["error"]


# ---------------------------------------------------------------------------
# Integration smoke test (skipped in CI without network)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not pytest.importorskip("urllib.request", reason="urllib unavailable"),
    reason="requires network",
)
@pytest.mark.integration
def test_get_poc_week_live():
    """Smoke-test against the real site. Skip with: pytest -m 'not integration'."""
    result = get_poc_week()
    # If we get a result (not a network error), validate shape
    if "error" not in result:
        assert "week_date" in result
        assert isinstance(result["cves"], list)
        assert result["total"] == len(result["cves"])
