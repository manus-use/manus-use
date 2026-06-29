"""
Tests for score_temporal_priority.

All HTTP calls are mocked — no real network access.
"""

from __future__ import annotations

from datetime import date, timedelta
from unittest.mock import MagicMock, patch

import pytest

from manus_use.tools.score_temporal_priority import (
    TOOL_SPEC,
    _compute_score,
    _fetch_epss,
    _fetch_kev,
    _fetch_nvd,
    _render_text,
    _spike_decay,
    score_temporal_priority,
)

# ──────────────────────────────────────────────────────────────────────────────
# Fixtures / helpers
# ──────────────────────────────────────────────────────────────────────────────

TODAY = date(2026, 6, 29)
TODAY_STR = TODAY.isoformat()


def _tool(cve_id: str, output: str = "text") -> dict:
    return {
        "toolUseId": "tu-001",
        "input": {"cve_id": cve_id, "output": output},
    }


def _nvd_response(cve_id: str, score: float = 9.8, published: str = "2021-12-10T00:00:00.000") -> dict:
    """Minimal NVD API JSON for one CVE."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": published,
                    "descriptions": [{"lang": "en", "value": f"Critical vuln in {cve_id}"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": score,
                                    "baseSeverity": "CRITICAL",
                                    "attackVector": "NETWORK",
                                }
                            }
                        ]
                    },
                    "references": [
                        {"url": "https://github.com/org/repo/commit/abc123", "tags": ["patch"]},
                        {"url": "https://github.com/org/repo/releases/tag/v2.0", "tags": ["release"]},
                    ],
                }
            }
        ]
    }


def _nvd_response_no_patch(cve_id: str, score: float = 9.8) -> dict:
    """NVD response with no patch references."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": "2024-01-15T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "RCE vulnerability"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": score,
                                    "baseSeverity": "CRITICAL",
                                    "attackVector": "NETWORK",
                                }
                            }
                        ]
                    },
                    "references": [
                        {"url": "https://example.com/advisory", "tags": []},
                    ],
                }
            }
        ]
    }


def _epss_response(cve_id: str, current: float = 0.85, spike: bool = True, spike_days_ago: int = 10) -> dict:
    """FIRST.org EPSS time-series response."""
    today = TODAY
    pts = []
    # Build a series: stable low, then spike, then current
    for i in range(30, 0, -1):
        d = today - timedelta(days=i)
        if i == spike_days_ago and spike:
            pts.append({"date": d.isoformat(), "epss": str(round(current - 0.20, 4)), "percentile": "0.90"})
        elif i < spike_days_ago and spike:
            pts.append({"date": d.isoformat(), "epss": str(current), "percentile": "0.97"})
        else:
            pts.append({"date": d.isoformat(), "epss": "0.05", "percentile": "0.70"})

    return {
        "data": [
            {
                "cve": cve_id,
                "epss": str(current),
                "percentile": "0.97",
                "date": TODAY_STR,
                "time-series": pts,
            }
        ]
    }


def _epss_response_no_spike(cve_id: str, current: float = 0.03) -> dict:
    today = TODAY
    pts = [
        {"date": (today - timedelta(days=i)).isoformat(), "epss": str(current), "percentile": "0.50"}
        for i in range(30, 0, -1)
    ]
    return {
        "data": [
            {
                "cve": cve_id,
                "epss": str(current),
                "percentile": "0.50",
                "date": TODAY_STR,
                "time-series": pts,
            }
        ]
    }


def _kev_response(cve_id: str, in_kev: bool = True) -> dict:
    vulns = []
    if in_kev:
        vulns.append(
            {
                "cveID": cve_id,
                "dateAdded": "2021-12-11",
                "dueDate": "2022-01-03",
                "requiredAction": "Apply updates",
                "vendorProject": "Apache",
                "product": "Log4j",
            }
        )
    return {"vulnerabilities": vulns}


def _mock_requests_get(url, params=None, timeout=None):
    """Route URLs to canned responses."""
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    cve_id = (params or {}).get("cveId") or (params or {}).get("cve") or "CVE-2021-44228"
    if "nvd.nist.gov" in url:
        resp.json.return_value = _nvd_response(cve_id)
    elif "first.org" in url:
        resp.json.return_value = _epss_response(cve_id)
    elif "cisa.gov" in url:
        resp.json.return_value = _kev_response(cve_id)
    else:
        resp.json.return_value = {}
    return resp


# ──────────────────────────────────────────────────────────────────────────────
# Unit tests: _spike_decay
# ──────────────────────────────────────────────────────────────────────────────


def test_spike_decay_zero_days():
    """Decay at day 0 should be 1.0 (no attenuation)."""
    assert _spike_decay(0) == pytest.approx(1.0)


def test_spike_decay_half_life():
    """Decay at _SPIKE_HALF_LIFE_DAYS (30) should be ~0.5."""
    from manus_use.tools.score_temporal_priority import _SPIKE_HALF_LIFE_DAYS

    assert _spike_decay(_SPIKE_HALF_LIFE_DAYS) == pytest.approx(0.5, abs=0.01)


def test_spike_decay_one_year():
    """Decay at 365 days should be very small."""
    assert _spike_decay(365) < 0.05


def test_spike_decay_monotone():
    """Decay should be monotonically decreasing."""
    values = [_spike_decay(d) for d in range(0, 200, 10)]
    assert all(values[i] > values[i + 1] for i in range(len(values) - 1))


# ──────────────────────────────────────────────────────────────────────────────
# Unit tests: _fetch_nvd
# ──────────────────────────────────────────────────────────────────────────────


def test_fetch_nvd_success():
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = _nvd_response("CVE-2021-44228")
        mock_get.return_value = mock_resp

        result = _fetch_nvd("CVE-2021-44228")

    assert result["cve_id"] == "CVE-2021-44228"
    assert result["cvss_score"] == 9.8
    assert result["cvss_severity"] == "CRITICAL"
    assert result["attack_vector"] == "NETWORK"
    assert result["patch_signals"] >= 2


def test_fetch_nvd_not_found():
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"vulnerabilities": []}
        mock_get.return_value = mock_resp

        result = _fetch_nvd("CVE-9999-0000")

    assert "error" in result


def test_fetch_nvd_request_error():
    import requests

    with patch("requests.get", side_effect=requests.exceptions.ConnectionError("timeout")):
        result = _fetch_nvd("CVE-2021-44228")
    assert "error" in result


def test_fetch_nvd_cvss_v2_fallback():
    """Should use CVSSv2 when no v3 present."""
    nvd_data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2017-0001",
                    "published": "2017-03-17T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Old vuln"}],
                    "metrics": {
                        "cvssMetricV2": [
                            {
                                "cvssData": {"version": "2.0", "baseScore": 7.8},
                                "baseSeverity": "HIGH",
                            }
                        ]
                    },
                    "references": [],
                }
            }
        ]
    }
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = nvd_data
        mock_get.return_value = mock_resp

        result = _fetch_nvd("CVE-2017-0001")

    assert result["cvss_score"] == 7.8
    assert result["cvss_version"] == "2.0"


def test_fetch_nvd_no_patch_signals():
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = _nvd_response_no_patch("CVE-2024-1234")
        mock_get.return_value = mock_resp

        result = _fetch_nvd("CVE-2024-1234")

    assert result["patch_signals"] == 0


# ──────────────────────────────────────────────────────────────────────────────
# Unit tests: _fetch_epss
# ──────────────────────────────────────────────────────────────────────────────


def test_fetch_epss_with_spike():
    with patch("requests.get") as mock_get, patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = _epss_response("CVE-2021-44228", current=0.85, spike=True, spike_days_ago=10)
        mock_get.return_value = mock_resp

        result = _fetch_epss("CVE-2021-44228")

    assert result["current_epss"] == pytest.approx(0.85)
    assert result["spike_detected"] is True
    assert result["spike_magnitude"] > 0.10
    assert result["days_since_spike"] is not None


def test_fetch_epss_no_spike():
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = _epss_response_no_spike("CVE-2021-44228", current=0.03)
        mock_get.return_value = mock_resp

        result = _fetch_epss("CVE-2021-44228")

    assert result["current_epss"] == pytest.approx(0.03)
    assert result["spike_detected"] is False


def test_fetch_epss_not_found():
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"data": []}
        mock_get.return_value = mock_resp

        result = _fetch_epss("CVE-9999-0000")

    assert "error" in result


def test_fetch_epss_request_error():
    import requests

    with patch("requests.get", side_effect=requests.exceptions.Timeout("timeout")):
        result = _fetch_epss("CVE-2021-44228")
    assert "error" in result


# ──────────────────────────────────────────────────────────────────────────────
# Unit tests: _fetch_kev
# ──────────────────────────────────────────────────────────────────────────────


def test_fetch_kev_in_catalog():
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = _kev_response("CVE-2021-44228", in_kev=True)
        mock_get.return_value = mock_resp

        result = _fetch_kev("CVE-2021-44228")

    assert result["in_kev"] is True
    assert result["date_added"] == "2021-12-11"


def test_fetch_kev_not_in_catalog():
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = _kev_response("CVE-2021-44228", in_kev=False)
        mock_get.return_value = mock_resp

        result = _fetch_kev("CVE-9999-0000")

    assert result["in_kev"] is False


def test_fetch_kev_request_error():
    import requests

    with patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
        result = _fetch_kev("CVE-2021-44228")
    assert result["in_kev"] is False
    assert "error" in result


def test_fetch_kev_case_insensitive():
    """KEV lookup should be case-insensitive."""
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = _kev_response("CVE-2021-44228", in_kev=True)
        mock_get.return_value = mock_resp

        result = _fetch_kev("cve-2021-44228")

    assert result["in_kev"] is True


# ──────────────────────────────────────────────────────────────────────────────
# Unit tests: _compute_score
# ──────────────────────────────────────────────────────────────────────────────


def _make_nvd(score=9.8, published_days_ago=500, patch_signals=2):
    pub = (TODAY - timedelta(days=published_days_ago)).isoformat()
    return {
        "cve_id": "CVE-2021-44228",
        "cvss_score": score,
        "cvss_severity": "CRITICAL",
        "cvss_version": "3.1",
        "attack_vector": "NETWORK",
        "patch_signals": patch_signals,
        "published_date": pub,
        "description": "Remote code execution via JNDI lookup.",
    }


def _make_epss(current=0.85, spike=True, days_since=10, magnitude=0.20):
    return {
        "current_epss": current,
        "current_percentile": 0.97,
        "spike_detected": spike,
        "spike_magnitude": magnitude,
        "spike_date": (TODAY - timedelta(days=days_since)).isoformat() if spike else None,
        "days_since_spike": days_since if spike else None,
    }


def _make_kev(in_kev=True):
    if in_kev:
        return {"in_kev": True, "date_added": "2021-12-11", "due_date": "2022-01-03"}
    return {"in_kev": False}


def test_compute_score_critical_all_factors():
    with patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY):
        result = _compute_score(_make_nvd(), _make_epss(), _make_kev(True))
    assert result["urgency_score"] >= 80
    assert result["label"] == "CRITICAL"
    assert result["in_kev"] is True
    assert result["spike_detected"] is True


def test_compute_score_low_all_factors_minimal():
    with patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY):
        nvd = _make_nvd(score=2.0, published_days_ago=5, patch_signals=3)
        epss = _make_epss(current=0.001, spike=False)
        kev = _make_kev(False)
        result = _compute_score(nvd, epss, kev)
    assert result["urgency_score"] < 40
    assert result["label"] == "LOW"


def test_compute_score_capped_at_100():
    with patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY):
        nvd = _make_nvd(score=10.0, published_days_ago=1000, patch_signals=0)
        epss = _make_epss(current=1.0, spike=True, days_since=0, magnitude=1.0)
        kev = _make_kev(True)
        result = _compute_score(nvd, epss, kev)
    assert result["urgency_score"] <= 100.0


def test_compute_score_has_all_components():
    with patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY):
        result = _compute_score(_make_nvd(), _make_epss(), _make_kev())
    names = {c["name"] for c in result["components"]}
    assert "CVSS base score" in names
    assert "EPSS current score" in names
    assert "EPSS spike recency" in names
    assert "CISA KEV membership" in names
    assert "Patch unavailability" in names
    assert "CVE age pressure" in names


def test_compute_score_no_cvss():
    """Missing CVSS should score 0 for that component, not error."""
    with patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY):
        nvd = _make_nvd()
        nvd["cvss_score"] = None
        result = _compute_score(nvd, _make_epss(current=0.1, spike=False), _make_kev(False))
    cvss_comp = next(c for c in result["components"] if c["name"] == "CVSS base score")
    assert cvss_comp["score"] == 0.0


def test_compute_score_no_patch_signals_adds_pts():
    """No patch signal should add 10 pts."""
    with patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY):
        nvd_no_patch = _make_nvd(patch_signals=0)
        nvd_with_patch = _make_nvd(patch_signals=3)
        r_no = _compute_score(nvd_no_patch, _make_epss(spike=False), _make_kev(False))
        r_yes = _compute_score(nvd_with_patch, _make_epss(spike=False), _make_kev(False))
    patch_no = next(c for c in r_no["components"] if c["name"] == "Patch unavailability")
    patch_yes = next(c for c in r_yes["components"] if c["name"] == "Patch unavailability")
    assert patch_no["score"] == 10.0
    assert patch_yes["score"] == 0.0


def test_compute_score_kev_adds_20():
    """KEV membership should add exactly 20 pts."""
    with patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY):
        nvd = _make_nvd(score=5.0, patch_signals=2)
        epss = _make_epss(current=0.1, spike=False)
        r_kev = _compute_score(nvd, epss, _make_kev(True))
        r_no_kev = _compute_score(nvd, epss, _make_kev(False))
    kev_comp = next(c for c in r_kev["components"] if c["name"] == "CISA KEV membership")
    no_kev_comp = next(c for c in r_no_kev["components"] if c["name"] == "CISA KEV membership")
    assert kev_comp["score"] == 20.0
    assert no_kev_comp["score"] == 0.0


def test_compute_score_spike_recency_old_spike_less_than_fresh():
    """A 200-day-old spike should score less than a 5-day-old spike."""
    with patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY):
        nvd = _make_nvd()
        epss_fresh = _make_epss(spike=True, days_since=5, magnitude=0.20)
        epss_old = _make_epss(spike=True, days_since=200, magnitude=0.20)
        r_fresh = _compute_score(nvd, epss_fresh, _make_kev(False))
        r_old = _compute_score(nvd, epss_old, _make_kev(False))
    spike_fresh = next(c for c in r_fresh["components"] if c["name"] == "EPSS spike recency")
    spike_old = next(c for c in r_old["components"] if c["name"] == "EPSS spike recency")
    assert spike_fresh["score"] > spike_old["score"]


def test_compute_score_age_pressure_increases():
    """Older CVEs should have higher age pressure score."""
    with patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY):
        nvd_old = _make_nvd(published_days_ago=365)
        nvd_new = _make_nvd(published_days_ago=10)
        epss = _make_epss(spike=False)
        r_old = _compute_score(nvd_old, epss, _make_kev(False))
        r_new = _compute_score(nvd_new, epss, _make_kev(False))
    age_old = next(c for c in r_old["components"] if c["name"] == "CVE age pressure")
    age_new = next(c for c in r_new["components"] if c["name"] == "CVE age pressure")
    assert age_old["score"] > age_new["score"]


def test_compute_score_components_sorted_descending():
    """Components should be sorted by score descending."""
    with patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY):
        result = _compute_score(_make_nvd(), _make_epss(), _make_kev())
    scores = [c["score"] for c in result["components"]]
    assert scores == sorted(scores, reverse=True)


def test_compute_score_epss_error_graceful():
    """If EPSS fetch errored, scores should default gracefully (no exception)."""
    with patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY):
        result = _compute_score(_make_nvd(), {"error": "network down"}, _make_kev(False))
    assert isinstance(result["urgency_score"], float)


# ──────────────────────────────────────────────────────────────────────────────
# Unit tests: _render_text
# ──────────────────────────────────────────────────────────────────────────────


def test_render_text_contains_cve_id():
    with patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY):
        scored = _compute_score(_make_nvd(), _make_epss(), _make_kev())
    text = _render_text(scored)
    assert "CVE-2021-44228" in text


def test_render_text_contains_score():
    with patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY):
        scored = _compute_score(_make_nvd(), _make_epss(), _make_kev())
    text = _render_text(scored)
    assert str(int(scored["urgency_score"])) in text


def test_render_text_contains_label():
    with patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY):
        scored = _compute_score(_make_nvd(), _make_epss(), _make_kev())
    text = _render_text(scored)
    assert scored["label"] in text


def test_render_text_all_labels():
    """All four label tiers should render without error."""
    for forced_score, expected_label in [(90, "CRITICAL"), (65, "HIGH"), (50, "MEDIUM"), (20, "LOW")]:
        with patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY):
            scored = _compute_score(_make_nvd(), _make_epss(), _make_kev())
        scored["urgency_score"] = forced_score
        scored["label"] = expected_label
        text = _render_text(scored)
        assert expected_label in text


# ──────────────────────────────────────────────────────────────────────────────
# Integration tests: score_temporal_priority (mocked HTTP)
# ──────────────────────────────────────────────────────────────────────────────


def _make_mock_get(cve_id: str, nvd_score: float = 9.8, epss_current: float = 0.85, in_kev: bool = True):
    def mock_get(url, params=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        if "nvd.nist.gov" in url:
            resp.json.return_value = _nvd_response(cve_id, score=nvd_score)
        elif "first.org" in url:
            resp.json.return_value = _epss_response(cve_id, current=epss_current, spike=True, spike_days_ago=5)
        elif "cisa.gov" in url:
            resp.json.return_value = _kev_response(cve_id, in_kev=in_kev)
        else:
            resp.json.return_value = {}
        return resp

    return mock_get


def test_tool_text_output_success():
    cve = "CVE-2021-44228"
    with (
        patch("requests.get", side_effect=_make_mock_get(cve)),
        patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY),
    ):
        result = score_temporal_priority(_tool(cve, "text"))

    assert result["status"] == "success"
    texts = [c["text"] for c in result["content"] if "text" in c]
    assert texts
    assert cve in texts[0]


def test_tool_json_output_success():
    cve = "CVE-2021-44228"
    with (
        patch("requests.get", side_effect=_make_mock_get(cve)),
        patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY),
    ):
        result = score_temporal_priority(_tool(cve, "json"))

    assert result["status"] == "success"
    jsons = [c["json"] for c in result["content"] if "json" in c]
    assert jsons
    assert jsons[0]["cve_id"] == cve
    assert "urgency_score" in jsons[0]
    assert "label" in jsons[0]
    assert "components" in jsons[0]


def test_tool_invalid_cve_id():
    result = score_temporal_priority(_tool("NOT-A-CVE"))
    assert result["status"] == "error"
    assert "Invalid" in result["content"][0]["text"]


def test_tool_invalid_cve_id_lowercase():
    result = score_temporal_priority(_tool("cve2024-1234"))
    assert result["status"] == "error"


def test_tool_nvd_not_found():
    def mock_get(url, params=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        if "nvd.nist.gov" in url:
            resp.json.return_value = {"vulnerabilities": []}
        elif "first.org" in url:
            resp.json.return_value = _epss_response("CVE-9999-9999")
        elif "cisa.gov" in url:
            resp.json.return_value = _kev_response("CVE-9999-9999", in_kev=False)
        else:
            resp.json.return_value = {}
        return resp

    with patch("requests.get", side_effect=mock_get):
        result = score_temporal_priority(_tool("CVE-9999-9999"))
    assert result["status"] == "error"
    assert "NVD lookup failed" in result["content"][0]["text"]


def test_tool_epss_error_does_not_crash():
    """EPSS failure should degrade gracefully, not crash."""
    import requests

    def mock_get(url, params=None, timeout=None):
        if "first.org" in url:
            raise requests.exceptions.ConnectionError("no network")
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        if "nvd.nist.gov" in url:
            resp.json.return_value = _nvd_response("CVE-2021-44228")
        elif "cisa.gov" in url:
            resp.json.return_value = _kev_response("CVE-2021-44228", in_kev=False)
        else:
            resp.json.return_value = {}
        return resp

    with (
        patch("requests.get", side_effect=mock_get),
        patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY),
    ):
        result = score_temporal_priority(_tool("CVE-2021-44228"))
    assert result["status"] == "success"


def test_tool_kev_error_does_not_crash():
    """KEV failure should degrade gracefully."""
    import requests

    def mock_get(url, params=None, timeout=None):
        if "cisa.gov" in url:
            raise requests.exceptions.Timeout("timeout")
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        if "nvd.nist.gov" in url:
            resp.json.return_value = _nvd_response("CVE-2021-44228")
        elif "first.org" in url:
            resp.json.return_value = _epss_response("CVE-2021-44228")
        else:
            resp.json.return_value = {}
        return resp

    with (
        patch("requests.get", side_effect=mock_get),
        patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY),
    ):
        result = score_temporal_priority(_tool("CVE-2021-44228"))
    assert result["status"] == "success"


def test_tool_low_epss_no_kev_no_spike():
    """Low-risk CVE should score LOW."""
    cve = "CVE-2024-0001"

    def mock_get(url, params=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        if "nvd.nist.gov" in url:
            resp.json.return_value = _nvd_response(cve, score=3.5, published="2024-01-01T00:00:00.000")
        elif "first.org" in url:
            resp.json.return_value = _epss_response_no_spike(cve, current=0.005)
        elif "cisa.gov" in url:
            resp.json.return_value = _kev_response(cve, in_kev=False)
        else:
            resp.json.return_value = {}
        return resp

    with (
        patch("requests.get", side_effect=mock_get),
        patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY),
    ):
        result = score_temporal_priority(_tool(cve, "json"))

    jsons = [c["json"] for c in result["content"] if "json" in c]
    assert jsons[0]["label"] in ("LOW", "MEDIUM")


def test_tool_critical_all_signals():
    """High CVSS + KEV + fresh spike + no patch = CRITICAL."""
    cve = "CVE-2021-44228"
    with (
        patch("requests.get", side_effect=_make_mock_get(cve, nvd_score=9.8, epss_current=0.90, in_kev=True)),
        patch("manus_use.tools.score_temporal_priority._today", return_value=TODAY),
    ):
        result = score_temporal_priority(_tool(cve, "json"))

    jsons = [c["json"] for c in result["content"] if "json" in c]
    # Log4Shell with all signals should be CRITICAL
    assert jsons[0]["label"] == "CRITICAL"
    assert jsons[0]["urgency_score"] >= 80


# ──────────────────────────────────────────────────────────────────────────────
# Tool spec validation
# ──────────────────────────────────────────────────────────────────────────────


def test_tool_spec_structure():
    assert TOOL_SPEC["name"] == "score_temporal_priority"
    assert "description" in TOOL_SPEC
    assert "inputSchema" in TOOL_SPEC
    schema = TOOL_SPEC["inputSchema"]["json"]
    assert "cve_id" in schema["properties"]
    assert "cve_id" in schema["required"]


def test_tool_spec_output_enum():
    schema = TOOL_SPEC["inputSchema"]["json"]
    output_prop = schema["properties"].get("output", {})
    assert "enum" in output_prop
    assert "text" in output_prop["enum"]
    assert "json" in output_prop["enum"]
