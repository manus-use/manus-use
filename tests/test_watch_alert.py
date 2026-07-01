"""
Unit tests for watch_alert tool.

All HTTP calls are mocked — no real network requests.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers & fixtures
# ---------------------------------------------------------------------------

_SAMPLE_RECORDS = [
    {
        "cve_id": "CVE-2024-3094",
        "added_at": "2026-06-01",
        "last_checked": "2026-06-30",
        "last_epss": 0.70,
        "baseline_epss": 0.60,
    },
    {
        "cve_id": "CVE-2021-44228",
        "added_at": "2026-06-01",
        "last_checked": "2026-06-30",
        "last_epss": 0.95,
        "baseline_epss": 0.90,
    },
    {
        "cve_id": "CVE-2023-12345",
        "added_at": "2026-06-01",
        "last_checked": "2026-06-30",
        "last_epss": 0.05,
        "baseline_epss": 0.05,
    },
]

# New EPSS values: CVE-2024-3094 spikes (+0.20), Log4j stays high, the last stays low
_MOCK_EPSS_RESPONSE = {
    "data": [
        {"cve": "CVE-2024-3094", "epss": "0.90", "percentile": "0.99"},
        {"cve": "CVE-2021-44228", "epss": "0.97", "percentile": "0.999"},
        {"cve": "CVE-2023-12345", "epss": "0.04", "percentile": "0.20"},
    ]
}

_MOCK_NVD_RESPONSE_3094 = {
    "vulnerabilities": [
        {
            "cve": {
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                }
            }
        }
    ]
}

_MOCK_NVD_RESPONSE_44228 = {
    "vulnerabilities": [
        {
            "cve": {
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                }
            }
        }
    ]
}

_MOCK_NVD_RESPONSE_12345 = {
    "vulnerabilities": [
        {
            "cve": {
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 5.3,
                                "baseSeverity": "MEDIUM",
                            }
                        }
                    ]
                }
            }
        }
    ]
}

_MOCK_KEV = {
    "vulnerabilities": [
        {"cveID": "CVE-2024-3094"},
        {"cveID": "CVE-2021-44228"},
    ]
}


def _write_watchlist(tmp_path: Path, records: list[dict[str, Any]]) -> Path:
    p = tmp_path / "watchlist.jsonl"
    p.write_text(
        "\n".join(json.dumps(r) for r in records) + "\n",
        encoding="utf-8",
    )
    return p


def _make_nvd_side_effect(mapping: dict[str, dict[str, Any]]):
    """Return a side_effect fn that returns different NVD responses per CVE."""

    def _side_effect(url: str, params=None, timeout=None):
        cve_id = None
        if params and hasattr(params, "items"):
            cve_id = params.get("cveId", "").upper()
        elif isinstance(params, list):
            cve_id = dict(params).get("cveId", "").upper()
        elif params is None and "cveId=" in url:
            cve_id = url.split("cveId=")[1].split("&")[0].upper()
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = mapping.get(cve_id, {"vulnerabilities": []})
        return resp

    return _side_effect


# ---------------------------------------------------------------------------
# _fetch_current_epss
# ---------------------------------------------------------------------------


class TestFetchCurrentEpss:
    def test_returns_scores(self):
        from manus_agent.tools.watch_alert import _fetch_current_epss

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = _MOCK_EPSS_RESPONSE

        with patch("manus_agent.tools.watch_alert.requests.get", return_value=mock_resp):
            scores = _fetch_current_epss(["CVE-2024-3094", "CVE-2021-44228"])

        assert scores["CVE-2024-3094"] == pytest.approx(0.90)
        assert scores["CVE-2021-44228"] == pytest.approx(0.97)

    def test_empty_input(self):
        from manus_agent.tools.watch_alert import _fetch_current_epss

        scores = _fetch_current_epss([])
        assert scores == {}

    def test_network_error_returns_minus_one(self):
        import requests

        from manus_agent.tools.watch_alert import _fetch_current_epss

        with patch(
            "manus_agent.tools.watch_alert.requests.get",
            side_effect=requests.exceptions.ConnectionError("timeout"),
        ):
            scores = _fetch_current_epss(["CVE-2024-3094"])

        assert scores["CVE-2024-3094"] == -1.0

    def test_chunks_large_input(self):
        """Input > 50 CVEs should be batched into multiple requests."""
        from manus_agent.tools.watch_alert import _fetch_current_epss

        cve_ids = [f"CVE-2024-{i:04d}" for i in range(120)]

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"data": []}

        with patch("manus_agent.tools.watch_alert.requests.get", return_value=mock_resp) as mock_get:
            _fetch_current_epss(cve_ids)

        # 120 CVEs / 50 per chunk = 3 calls
        assert mock_get.call_count == 3

    def test_malformed_epss_value(self):
        """Malformed float should fall back to -1.0."""
        from manus_agent.tools.watch_alert import _fetch_current_epss

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"data": [{"cve": "CVE-2024-3094", "epss": "not-a-number"}]}

        with patch("manus_agent.tools.watch_alert.requests.get", return_value=mock_resp):
            scores = _fetch_current_epss(["CVE-2024-3094"])

        assert scores["CVE-2024-3094"] == -1.0

    def test_missing_cve_in_response(self):
        """CVE absent from API response should default to -1.0."""
        from manus_agent.tools.watch_alert import _fetch_current_epss

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"data": []}

        with patch("manus_agent.tools.watch_alert.requests.get", return_value=mock_resp):
            scores = _fetch_current_epss(["CVE-9999-9999"])

        assert scores["CVE-9999-9999"] == -1.0


# ---------------------------------------------------------------------------
# _fetch_nvd_cvss
# ---------------------------------------------------------------------------


class TestFetchNvdCvss:
    def _make_mock_get(self, cve_responses: dict[str, Any]):
        def _side_effect(url, params=None, timeout=None):
            cve_id = (params or {}).get("cveId", "").upper()
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            resp.json.return_value = cve_responses.get(cve_id, {"vulnerabilities": []})
            return resp

        return _side_effect

    def test_returns_cvss_v31(self):
        from manus_agent.tools.watch_alert import _fetch_nvd_cvss

        side_effect = self._make_mock_get({"CVE-2024-3094": _MOCK_NVD_RESPONSE_3094})
        with patch("manus_agent.tools.watch_alert.requests.get", side_effect=side_effect):
            result = _fetch_nvd_cvss(["CVE-2024-3094"])

        assert result["CVE-2024-3094"]["base_score"] == pytest.approx(10.0)
        assert result["CVE-2024-3094"]["severity"] == "CRITICAL"

    def test_empty_vulnerabilities(self):
        from manus_agent.tools.watch_alert import _fetch_nvd_cvss

        side_effect = self._make_mock_get({"CVE-9999-0001": {"vulnerabilities": []}})
        with patch("manus_agent.tools.watch_alert.requests.get", side_effect=side_effect):
            result = _fetch_nvd_cvss(["CVE-9999-0001"])

        assert result["CVE-9999-0001"]["base_score"] is None
        assert result["CVE-9999-0001"]["severity"] == "UNKNOWN"

    def test_network_error(self):
        import requests

        from manus_agent.tools.watch_alert import _fetch_nvd_cvss

        with patch(
            "manus_agent.tools.watch_alert.requests.get",
            side_effect=requests.exceptions.ConnectionError(),
        ):
            result = _fetch_nvd_cvss(["CVE-2024-3094"])

        assert result["CVE-2024-3094"]["base_score"] is None

    def test_falls_back_to_cvss_v2(self):
        from manus_agent.tools.watch_alert import _fetch_nvd_cvss

        v2_response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "metrics": {
                            "cvssMetricV2": [
                                {
                                    "cvssData": {
                                        "baseScore": 7.5,
                                        "baseSeverity": "HIGH",
                                    }
                                }
                            ]
                        }
                    }
                }
            ]
        }
        side_effect = self._make_mock_get({"CVE-2021-1234": v2_response})
        with patch("manus_agent.tools.watch_alert.requests.get", side_effect=side_effect):
            result = _fetch_nvd_cvss(["CVE-2021-1234"])

        assert result["CVE-2021-1234"]["base_score"] == pytest.approx(7.5)

    def test_multiple_cves(self):
        from manus_agent.tools.watch_alert import _fetch_nvd_cvss

        side_effect = self._make_mock_get(
            {
                "CVE-2024-3094": _MOCK_NVD_RESPONSE_3094,
                "CVE-2021-44228": _MOCK_NVD_RESPONSE_44228,
                "CVE-2023-12345": _MOCK_NVD_RESPONSE_12345,
            }
        )
        with patch("manus_agent.tools.watch_alert.requests.get", side_effect=side_effect):
            result = _fetch_nvd_cvss(["CVE-2024-3094", "CVE-2021-44228", "CVE-2023-12345"])

        assert result["CVE-2024-3094"]["severity"] == "CRITICAL"
        assert result["CVE-2021-44228"]["severity"] == "CRITICAL"
        assert result["CVE-2023-12345"]["severity"] == "MEDIUM"


# ---------------------------------------------------------------------------
# _fetch_kev_set
# ---------------------------------------------------------------------------


class TestFetchKevSet:
    def test_returns_set(self):
        from manus_agent.tools.watch_alert import _fetch_kev_set

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = _MOCK_KEV

        with patch("manus_agent.tools.watch_alert.requests.get", return_value=mock_resp):
            kev = _fetch_kev_set()

        assert "CVE-2024-3094" in kev
        assert "CVE-2021-44228" in kev
        assert "CVE-2023-12345" not in kev

    def test_network_error_returns_empty(self):
        import requests

        from manus_agent.tools.watch_alert import _fetch_kev_set

        with patch(
            "manus_agent.tools.watch_alert.requests.get",
            side_effect=requests.exceptions.ConnectionError(),
        ):
            kev = _fetch_kev_set()

        assert kev == set()

    def test_uppercase_normalisation(self):
        from manus_agent.tools.watch_alert import _fetch_kev_set

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "vulnerabilities": [{"cveID": "cve-2024-3094"}]  # lowercase
        }
        with patch("manus_agent.tools.watch_alert.requests.get", return_value=mock_resp):
            kev = _fetch_kev_set()

        assert "CVE-2024-3094" in kev


# ---------------------------------------------------------------------------
# Watchlist I/O
# ---------------------------------------------------------------------------


class TestWatchlistIO:
    def test_load_empty(self, tmp_path):
        from manus_agent.tools.watch_alert import _load_watchlist

        p = tmp_path / "watchlist.jsonl"
        assert _load_watchlist(p) == []

    def test_load_records(self, tmp_path):
        from manus_agent.tools.watch_alert import _load_watchlist

        p = _write_watchlist(tmp_path, _SAMPLE_RECORDS)
        loaded = _load_watchlist(p)
        assert len(loaded) == 3
        assert loaded[0]["cve_id"] == "CVE-2024-3094"

    def test_load_skips_corrupt_lines(self, tmp_path):
        from manus_agent.tools.watch_alert import _load_watchlist

        p = tmp_path / "watchlist.jsonl"
        p.write_text('{"cve_id": "CVE-2024-0001"}\nnot-json\n{"cve_id": "CVE-2024-0002"}\n')
        records = _load_watchlist(p)
        assert len(records) == 2

    def test_save_roundtrip(self, tmp_path):
        from manus_agent.tools.watch_alert import _load_watchlist, _save_watchlist

        p = tmp_path / "watchlist.jsonl"
        _save_watchlist(p, _SAMPLE_RECORDS)
        loaded = _load_watchlist(p)
        assert len(loaded) == len(_SAMPLE_RECORDS)
        assert loaded[0]["cve_id"] == "CVE-2024-3094"

    def test_resolve_path_creates_parents(self, tmp_path):
        from manus_agent.tools.watch_alert import _resolve_path

        override = str(tmp_path / "subdir" / "watchlist.jsonl")
        path = _resolve_path(override)
        assert path.parent.exists()


# ---------------------------------------------------------------------------
# _trend_arrow
# ---------------------------------------------------------------------------


class TestTrendArrow:
    @pytest.mark.parametrize(
        "delta, expected",
        [
            (0.10, "↑"),
            (0.02, "↑"),
            (-0.10, "↓"),
            (-0.02, "↓"),
            (0.01, "→"),
            (-0.01, "→"),
            (0.0, "→"),
            (None, "→"),
        ],
    )
    def test_trend_arrow(self, delta, expected):
        from manus_agent.tools.watch_alert import _trend_arrow

        assert _trend_arrow(delta) == expected


# ---------------------------------------------------------------------------
# _build_alert
# ---------------------------------------------------------------------------


class TestBuildAlert:
    def _patch_all(self, tmp_path):
        """Return a context-manager stack that mocks all HTTP calls."""
        epss_resp = MagicMock()
        epss_resp.raise_for_status = MagicMock()
        epss_resp.json.return_value = _MOCK_EPSS_RESPONSE

        kev_resp = MagicMock()
        kev_resp.raise_for_status = MagicMock()
        kev_resp.json.return_value = _MOCK_KEV

        nvd_mapping = {
            "CVE-2024-3094": _MOCK_NVD_RESPONSE_3094,
            "CVE-2021-44228": _MOCK_NVD_RESPONSE_44228,
            "CVE-2023-12345": _MOCK_NVD_RESPONSE_12345,
        }

        def _get_side_effect(url, params=None, timeout=None):
            if "first.org" in url:
                return epss_resp
            if "cisa.gov" in url:
                return kev_resp
            if "nvd.nist.gov" in url:
                cve_id = (params or {}).get("cveId", "").upper()
                resp = MagicMock()
                resp.raise_for_status = MagicMock()
                resp.json.return_value = nvd_mapping.get(cve_id, {"vulnerabilities": []})
                return resp
            raise ValueError(f"Unexpected URL: {url}")

        return patch("manus_agent.tools.watch_alert.requests.get", side_effect=_get_side_effect)

    def test_spike_detected(self, tmp_path):
        from manus_agent.tools.watch_alert import _build_alert

        path = _write_watchlist(tmp_path, _SAMPLE_RECORDS)
        records = _SAMPLE_RECORDS[:]

        with self._patch_all(tmp_path):
            updated, payload = _build_alert(records, path, spike_threshold=0.10, epss_alert_floor=0.30)

        # CVE-2024-3094 went 0.70 → 0.90 (delta +0.20 ≥ 0.10 threshold)
        spike_ids = [e["cve_id"] for e in payload["spikes"]]
        assert "CVE-2024-3094" in spike_ids

    def test_elevated_detected(self, tmp_path):
        from manus_agent.tools.watch_alert import _build_alert

        path = _write_watchlist(tmp_path, _SAMPLE_RECORDS)
        records = _SAMPLE_RECORDS[:]

        with self._patch_all(tmp_path):
            _updated, payload = _build_alert(records, path, spike_threshold=0.10, epss_alert_floor=0.30)

        # CVE-2021-44228 went 0.95 → 0.97, delta = 0.02 (< spike threshold)
        # but EPSS ≥ 0.30 → Elevated
        elevated_ids = [e["cve_id"] for e in payload["elevated"]]
        assert "CVE-2021-44228" in elevated_ids

    def test_stable_detected(self, tmp_path):
        from manus_agent.tools.watch_alert import _build_alert

        path = _write_watchlist(tmp_path, _SAMPLE_RECORDS)
        records = _SAMPLE_RECORDS[:]

        with self._patch_all(tmp_path):
            _updated, payload = _build_alert(records, path, spike_threshold=0.10, epss_alert_floor=0.30)

        stable_ids = [e["cve_id"] for e in payload["stable"]]
        assert "CVE-2023-12345" in stable_ids

    def test_kev_flag_set(self, tmp_path):
        from manus_agent.tools.watch_alert import _build_alert

        path = _write_watchlist(tmp_path, _SAMPLE_RECORDS)
        records = _SAMPLE_RECORDS[:]

        with self._patch_all(tmp_path):
            _updated, payload = _build_alert(records, path, spike_threshold=0.10, epss_alert_floor=0.30)

        all_entries = payload["spikes"] + payload["elevated"] + payload["stable"]
        kev_map = {e["cve_id"]: e["in_kev"] for e in all_entries}
        assert kev_map["CVE-2024-3094"] is True
        assert kev_map["CVE-2021-44228"] is True
        assert kev_map["CVE-2023-12345"] is False

    def test_watchlist_persisted(self, tmp_path):
        from manus_agent.tools.watch_alert import _build_alert, _load_watchlist

        path = _write_watchlist(tmp_path, _SAMPLE_RECORDS)
        records = _SAMPLE_RECORDS[:]

        with self._patch_all(tmp_path):
            _updated, _payload = _build_alert(records, path, spike_threshold=0.10, epss_alert_floor=0.30)

        # Reload the file — scores should be updated
        reloaded = _load_watchlist(path)
        by_id = {r["cve_id"]: r for r in reloaded}
        assert by_id["CVE-2024-3094"]["last_epss"] == pytest.approx(0.90)
        assert by_id["CVE-2021-44228"]["last_epss"] == pytest.approx(0.97)

    def test_empty_watchlist(self, tmp_path):
        from manus_agent.tools.watch_alert import _build_alert

        path = tmp_path / "watchlist.jsonl"
        path.write_text("")

        _updated, payload = _build_alert([], path, spike_threshold=0.10, epss_alert_floor=0.30)
        assert payload["watchlist_size"] == 0
        assert payload["spikes"] == []
        assert payload["elevated"] == []
        assert payload["stable"] == []

    def test_epss_unavailable(self, tmp_path):
        """When EPSS API fails, CVEs should not be classified as spikes."""
        import requests as _requests

        from manus_agent.tools.watch_alert import _build_alert

        path = _write_watchlist(tmp_path, [_SAMPLE_RECORDS[0]])
        records = [_SAMPLE_RECORDS[0]]

        def _fail_epss(url, params=None, timeout=None):
            if "first.org" in url:
                raise _requests.exceptions.ConnectionError("mocked failure")
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            resp.json.return_value = {"vulnerabilities": [], "data": []}
            return resp

        with patch("manus_agent.tools.watch_alert.requests.get", side_effect=_fail_epss):
            _updated, payload = _build_alert(records, path, spike_threshold=0.10, epss_alert_floor=0.30)

        assert payload["spikes"] == []
        all_entries = payload["spikes"] + payload["elevated"] + payload["stable"]
        unavail = [e for e in all_entries if e["epss_unavailable"]]
        assert len(unavail) == 1

    def test_baseline_delta_computed(self, tmp_path):
        from manus_agent.tools.watch_alert import _build_alert

        path = _write_watchlist(tmp_path, _SAMPLE_RECORDS)
        records = _SAMPLE_RECORDS[:]

        with self._patch_all(tmp_path):
            _updated, payload = _build_alert(records, path, spike_threshold=0.10, epss_alert_floor=0.30)

        # CVE-2024-3094 baseline=0.60, new=0.90 → baseline_delta ≈ 0.30
        spike_entry = next(e for e in payload["spikes"] if e["cve_id"] == "CVE-2024-3094")
        assert spike_entry["baseline_delta"] == pytest.approx(0.30, abs=1e-6)

    def test_first_check_sets_baseline(self, tmp_path):
        """When baseline_epss is None (first check), it should be set to current score."""
        from manus_agent.tools.watch_alert import _build_alert

        records_no_baseline = [
            {
                "cve_id": "CVE-2024-9999",
                "added_at": "2026-07-01",
                "last_checked": None,
                "last_epss": None,
                "baseline_epss": None,
            }
        ]
        path = _write_watchlist(tmp_path, records_no_baseline)

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"data": [{"cve": "CVE-2024-9999", "epss": "0.55"}]}

        def _side(url, params=None, timeout=None):
            if "first.org" in url:
                return mock_resp
            r = MagicMock()
            r.raise_for_status = MagicMock()
            r.json.return_value = {"vulnerabilities": [], "data": []}
            return r

        with patch("manus_agent.tools.watch_alert.requests.get", side_effect=_side):
            updated, _payload = _build_alert(records_no_baseline, path, spike_threshold=0.10, epss_alert_floor=0.30)

        by_id = {r["cve_id"]: r for r in updated}
        assert by_id["CVE-2024-9999"]["baseline_epss"] == pytest.approx(0.55)

    def test_spikes_sorted_by_delta(self, tmp_path):
        """Spikes list should be sorted delta-descending."""
        from manus_agent.tools.watch_alert import _build_alert

        # Two records that will both spike
        records = [
            {
                "cve_id": "CVE-2024-0001",
                "added_at": "2026-07-01",
                "last_checked": "2026-07-01",
                "last_epss": 0.10,
                "baseline_epss": 0.10,
            },
            {
                "cve_id": "CVE-2024-0002",
                "added_at": "2026-07-01",
                "last_checked": "2026-07-01",
                "last_epss": 0.10,
                "baseline_epss": 0.10,
            },
        ]
        path = _write_watchlist(tmp_path, records)

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        # CVE-0001 gets a bigger spike (+0.50) than CVE-0002 (+0.20)
        mock_resp.json.return_value = {
            "data": [
                {"cve": "CVE-2024-0001", "epss": "0.60"},
                {"cve": "CVE-2024-0002", "epss": "0.30"},
            ]
        }

        def _side(url, params=None, timeout=None):
            if "first.org" in url:
                return mock_resp
            r = MagicMock()
            r.raise_for_status = MagicMock()
            r.json.return_value = {"vulnerabilities": [], "data": []}
            return r

        with patch("manus_agent.tools.watch_alert.requests.get", side_effect=_side):
            _updated, payload = _build_alert(records, path, spike_threshold=0.10, epss_alert_floor=0.80)

        spikes = payload["spikes"]
        assert len(spikes) == 2
        assert spikes[0]["cve_id"] == "CVE-2024-0001"  # bigger spike first
        assert spikes[1]["cve_id"] == "CVE-2024-0002"


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


class TestRenderMarkdown:
    def _make_payload(
        self,
        spikes=None,
        elevated=None,
        stable=None,
    ) -> dict:
        return {
            "generated_at": "2026-07-01T12:00:00Z",
            "watchlist_size": 3,
            "spike_threshold": 0.10,
            "epss_alert_floor": 0.30,
            "spikes": spikes or [],
            "elevated": elevated or [],
            "stable": stable or [],
        }

    def _sample_entry(self, cve_id="CVE-2024-3094", in_kev=True, delta=0.20) -> dict:
        return {
            "cve_id": cve_id,
            "current_epss": 0.90,
            "prev_epss": 0.70,
            "baseline_epss": 0.60,
            "delta": delta,
            "baseline_delta": 0.30,
            "trend": "↑",
            "cvss_base_score": 10.0,
            "cvss_severity": "CRITICAL",
            "in_kev": in_kev,
            "added_at": "2026-06-01",
            "epss_unavailable": False,
        }

    def test_contains_header(self):
        from manus_agent.tools.watch_alert import _render_markdown

        md = _render_markdown(self._make_payload())
        assert "## EPSS Alert Digest" in md
        assert "2026-07-01" in md

    def test_spike_section_present(self):
        from manus_agent.tools.watch_alert import _render_markdown

        payload = self._make_payload(spikes=[self._sample_entry()])
        md = _render_markdown(payload)
        assert "🚨" in md
        assert "CVE-2024-3094" in md

    def test_kev_badge_shown(self):
        from manus_agent.tools.watch_alert import _render_markdown

        payload = self._make_payload(spikes=[self._sample_entry(in_kev=True)])
        md = _render_markdown(payload)
        assert "KEV" in md

    def test_no_kev_no_badge(self):
        from manus_agent.tools.watch_alert import _render_markdown

        payload = self._make_payload(elevated=[self._sample_entry(in_kev=False, delta=0.01)])
        md = _render_markdown(payload)
        assert "KEV" not in md

    def test_no_spikes_message(self):
        from manus_agent.tools.watch_alert import _render_markdown

        md = _render_markdown(self._make_payload())
        assert "No spikes detected" in md

    def test_elevated_section(self):
        from manus_agent.tools.watch_alert import _render_markdown

        payload = self._make_payload(elevated=[self._sample_entry(delta=0.01)])
        md = _render_markdown(payload)
        assert "⚠️" in md

    def test_stable_section(self):
        from manus_agent.tools.watch_alert import _render_markdown

        payload = self._make_payload(stable=[self._sample_entry(delta=0.01)])
        md = _render_markdown(payload)
        assert "✅" in md

    def test_epss_unavailable_note(self):
        from manus_agent.tools.watch_alert import _render_markdown

        entry = self._sample_entry()
        entry["epss_unavailable"] = True
        entry["current_epss"] = None
        payload = self._make_payload(stable=[entry])
        md = _render_markdown(payload)
        assert "EPSS unavailable" in md


class TestRenderText:
    def _make_payload(self) -> dict:
        return {
            "generated_at": "2026-07-01T12:00:00Z",
            "watchlist_size": 2,
            "spike_threshold": 0.10,
            "epss_alert_floor": 0.30,
            "spikes": [
                {
                    "cve_id": "CVE-2024-3094",
                    "current_epss": 0.90,
                    "prev_epss": 0.70,
                    "baseline_epss": 0.60,
                    "delta": 0.20,
                    "baseline_delta": 0.30,
                    "trend": "↑",
                    "cvss_base_score": 10.0,
                    "cvss_severity": "CRITICAL",
                    "in_kev": True,
                    "added_at": "2026-06-01",
                    "epss_unavailable": False,
                }
            ],
            "elevated": [],
            "stable": [],
        }

    def test_plain_text_output(self):
        from manus_agent.tools.watch_alert import _render_text

        text = _render_text(self._make_payload())
        assert "CVE-2024-3094" in text
        assert "[KEV]" in text
        assert "0.9000" in text

    def test_no_markdown_headings(self):
        from manus_agent.tools.watch_alert import _render_text

        text = _render_text(self._make_payload())
        assert "##" not in text
        assert "**" not in text


# ---------------------------------------------------------------------------
# watch_alert tool entry-point
# ---------------------------------------------------------------------------


class TestWatchAlertTool:
    def _make_tool_use(self, **kwargs) -> dict:
        return {"toolUseId": "test-use-id-001", "input": kwargs}

    def _patch_build_alert(self, payload_override=None):
        """Patch _build_alert to return a controllable payload."""
        default_payload = {
            "generated_at": "2026-07-01T12:00:00Z",
            "watchlist_size": 1,
            "spike_threshold": 0.10,
            "epss_alert_floor": 0.30,
            "spikes": [],
            "elevated": [],
            "stable": [],
        }
        payload = payload_override or default_payload

        def _fake_build_alert(records, path, spike_threshold, epss_alert_floor):
            return records, payload

        return patch("manus_agent.tools.watch_alert._build_alert", side_effect=_fake_build_alert)

    def test_empty_watchlist_returns_success(self, tmp_path):
        from manus_agent.tools.watch_alert import watch_alert

        wl = tmp_path / "wl.jsonl"
        wl.write_text("")
        tool = self._make_tool_use(watchlist_path=str(wl))
        result = watch_alert(tool)
        assert result["status"] == "success"
        assert "empty" in result["content"][0]["text"].lower()

    def test_markdown_output(self, tmp_path):
        from manus_agent.tools.watch_alert import watch_alert

        wl = _write_watchlist(tmp_path, [_SAMPLE_RECORDS[0]])
        tool = self._make_tool_use(watchlist_path=str(wl), output_format="markdown")
        with self._patch_build_alert():
            result = watch_alert(tool)
        assert result["status"] == "success"
        assert "## EPSS Alert Digest" in result["content"][0]["text"]

    def test_text_output(self, tmp_path):
        from manus_agent.tools.watch_alert import watch_alert

        wl = _write_watchlist(tmp_path, [_SAMPLE_RECORDS[0]])
        tool = self._make_tool_use(watchlist_path=str(wl), output_format="text")
        with self._patch_build_alert():
            result = watch_alert(tool)
        assert result["status"] == "success"
        assert "##" not in result["content"][0]["text"]

    def test_json_output(self, tmp_path):
        from manus_agent.tools.watch_alert import watch_alert

        wl = _write_watchlist(tmp_path, [_SAMPLE_RECORDS[0]])
        tool = self._make_tool_use(watchlist_path=str(wl), output_format="json")
        with self._patch_build_alert():
            result = watch_alert(tool)
        assert result["status"] == "success"
        parsed = json.loads(result["content"][0]["text"])
        assert "generated_at" in parsed

    def test_invalid_output_format_falls_back_to_markdown(self, tmp_path):
        from manus_agent.tools.watch_alert import watch_alert

        wl = _write_watchlist(tmp_path, [_SAMPLE_RECORDS[0]])
        tool = self._make_tool_use(watchlist_path=str(wl), output_format="bogus")
        with self._patch_build_alert():
            result = watch_alert(tool)
        assert "## EPSS Alert Digest" in result["content"][0]["text"]

    def test_build_alert_exception_returns_error(self, tmp_path):
        from manus_agent.tools.watch_alert import watch_alert

        wl = _write_watchlist(tmp_path, [_SAMPLE_RECORDS[0]])
        tool = self._make_tool_use(watchlist_path=str(wl))

        with patch(
            "manus_agent.tools.watch_alert._build_alert",
            side_effect=RuntimeError("mocked failure"),
        ):
            result = watch_alert(tool)

        assert result["status"] == "error"
        assert "mocked failure" in result["content"][0]["text"]

    def test_json_content_block_present(self, tmp_path):
        from manus_agent.tools.watch_alert import watch_alert

        wl = _write_watchlist(tmp_path, [_SAMPLE_RECORDS[0]])
        tool = self._make_tool_use(watchlist_path=str(wl))
        with self._patch_build_alert():
            result = watch_alert(tool)
        content_kinds = [list(c.keys())[0] for c in result["content"]]
        assert "json" in content_kinds

    def test_default_spike_threshold(self, tmp_path):
        from manus_agent.tools.watch_alert import watch_alert

        wl = _write_watchlist(tmp_path, [_SAMPLE_RECORDS[0]])
        tool = self._make_tool_use(watchlist_path=str(wl))

        calls: list[dict] = []

        def _capture(records, path, spike_threshold, epss_alert_floor):
            calls.append({"spike_threshold": spike_threshold, "epss_alert_floor": epss_alert_floor})
            return records, {
                "generated_at": "2026-07-01T12:00:00Z",
                "watchlist_size": 1,
                "spike_threshold": spike_threshold,
                "epss_alert_floor": epss_alert_floor,
                "spikes": [],
                "elevated": [],
                "stable": [],
            }

        with patch("manus_agent.tools.watch_alert._build_alert", side_effect=_capture):
            watch_alert(tool)

        assert calls[0]["spike_threshold"] == pytest.approx(0.10)
        assert calls[0]["epss_alert_floor"] == pytest.approx(0.30)

    def test_custom_thresholds(self, tmp_path):
        from manus_agent.tools.watch_alert import watch_alert

        wl = _write_watchlist(tmp_path, [_SAMPLE_RECORDS[0]])
        tool = self._make_tool_use(
            watchlist_path=str(wl),
            spike_threshold=0.05,
            epss_alert_floor=0.50,
        )

        calls: list[dict] = []

        def _capture(records, path, spike_threshold, epss_alert_floor):
            calls.append({"spike_threshold": spike_threshold, "epss_alert_floor": epss_alert_floor})
            return records, {
                "generated_at": "2026-07-01T12:00:00Z",
                "watchlist_size": 1,
                "spike_threshold": spike_threshold,
                "epss_alert_floor": epss_alert_floor,
                "spikes": [],
                "elevated": [],
                "stable": [],
            }

        with patch("manus_agent.tools.watch_alert._build_alert", side_effect=_capture):
            watch_alert(tool)

        assert calls[0]["spike_threshold"] == pytest.approx(0.05)
        assert calls[0]["epss_alert_floor"] == pytest.approx(0.50)

    def test_manus_watchlist_path_env(self, tmp_path, monkeypatch):
        """MANUS_WATCHLIST_PATH env var should be respected when no override in input."""
        from manus_agent.tools.watch_alert import watch_alert

        wl = _write_watchlist(tmp_path, [_SAMPLE_RECORDS[0]])
        monkeypatch.setenv("MANUS_WATCHLIST_PATH", str(wl))

        tool = self._make_tool_use()  # no watchlist_path in input
        with self._patch_build_alert():
            result = watch_alert(tool)

        assert result["status"] == "success"


# ---------------------------------------------------------------------------
# CLI: _run_watch_alert
# ---------------------------------------------------------------------------


class TestRunWatchAlertCli:
    def test_empty_watchlist_exits_zero(self, tmp_path):
        from manus_agent.cli import _run_watch_alert

        wl = tmp_path / "wl.jsonl"
        wl.write_text("")
        exit_code = _run_watch_alert(["--watchlist", str(wl)])
        assert exit_code == 0

    def test_markdown_output_to_stdout(self, tmp_path, capsys):
        from manus_agent.cli import _run_watch_alert

        wl = _write_watchlist(tmp_path, [_SAMPLE_RECORDS[0]])

        def _fake_build_alert(records, path, spike_threshold, epss_alert_floor):
            return records, {
                "generated_at": "2026-07-01T12:00:00Z",
                "watchlist_size": 1,
                "spike_threshold": spike_threshold,
                "epss_alert_floor": epss_alert_floor,
                "spikes": [],
                "elevated": [],
                "stable": [],
            }

        with patch("manus_agent.tools.watch_alert._build_alert", side_effect=_fake_build_alert):
            exit_code = _run_watch_alert(["--watchlist", str(wl), "--output", "markdown"])

        assert exit_code == 0
        captured = capsys.readouterr()
        assert "## EPSS Alert Digest" in captured.out

    def test_text_output_to_stdout(self, tmp_path, capsys):
        from manus_agent.cli import _run_watch_alert

        wl = _write_watchlist(tmp_path, [_SAMPLE_RECORDS[0]])

        def _fake_build_alert(records, path, spike_threshold, epss_alert_floor):
            return records, {
                "generated_at": "2026-07-01T12:00:00Z",
                "watchlist_size": 1,
                "spike_threshold": spike_threshold,
                "epss_alert_floor": epss_alert_floor,
                "spikes": [],
                "elevated": [],
                "stable": [],
            }

        with patch("manus_agent.tools.watch_alert._build_alert", side_effect=_fake_build_alert):
            exit_code = _run_watch_alert(["--watchlist", str(wl), "--output", "text"])

        assert exit_code == 0
        captured = capsys.readouterr()
        assert "##" not in captured.out

    def test_json_output_to_stdout(self, tmp_path, capsys):
        from manus_agent.cli import _run_watch_alert

        wl = _write_watchlist(tmp_path, [_SAMPLE_RECORDS[0]])

        def _fake_build_alert(records, path, spike_threshold, epss_alert_floor):
            return records, {
                "generated_at": "2026-07-01T12:00:00Z",
                "watchlist_size": 1,
                "spike_threshold": spike_threshold,
                "epss_alert_floor": epss_alert_floor,
                "spikes": [],
                "elevated": [],
                "stable": [],
            }

        with patch("manus_agent.tools.watch_alert._build_alert", side_effect=_fake_build_alert):
            exit_code = _run_watch_alert(["--watchlist", str(wl), "--output", "json"])

        assert exit_code == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert "generated_at" in parsed

    def test_build_alert_exception_returns_one(self, tmp_path):
        from manus_agent.cli import _run_watch_alert

        wl = _write_watchlist(tmp_path, [_SAMPLE_RECORDS[0]])

        with patch(
            "manus_agent.tools.watch_alert._build_alert",
            side_effect=RuntimeError("cli failure"),
        ):
            exit_code = _run_watch_alert(["--watchlist", str(wl)])

        assert exit_code == 1

    def test_custom_threshold_arg(self, tmp_path):
        from manus_agent.cli import _run_watch_alert

        wl = _write_watchlist(tmp_path, [_SAMPLE_RECORDS[0]])
        calls: list[dict] = []

        def _capture(records, path, spike_threshold, epss_alert_floor):
            calls.append({"spike_threshold": spike_threshold, "epss_alert_floor": epss_alert_floor})
            return records, {
                "generated_at": "2026-07-01T12:00:00Z",
                "watchlist_size": 1,
                "spike_threshold": spike_threshold,
                "epss_alert_floor": epss_alert_floor,
                "spikes": [],
                "elevated": [],
                "stable": [],
            }

        with patch("manus_agent.tools.watch_alert._build_alert", side_effect=_capture):
            _run_watch_alert(["--watchlist", str(wl), "--threshold", "0.05", "--floor", "0.50"])

        assert calls[0]["spike_threshold"] == pytest.approx(0.05)
        assert calls[0]["epss_alert_floor"] == pytest.approx(0.50)

    def test_main_dispatch_watch_alert(self, tmp_path, capsys):
        """main() should route 'watch-alert' to _run_watch_alert."""
        import sys

        from manus_agent.cli import main

        wl = tmp_path / "wl.jsonl"
        wl.write_text("")

        with patch.object(sys, "argv", ["manus-agent", "watch-alert", "--watchlist", str(wl)]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 0
