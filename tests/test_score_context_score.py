"""
Tests for score_context_score — composite contextual risk scorer with KEV dimension.

All HTTP calls are mocked with realistic payloads (CVE-2021-44228 / Log4Shell).
No real network calls are made.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from manus_agent.tools.score_context_score import (
    _WEIGHTS,
    _compute_composite,
    _dim_blast_radius,
    _dim_cvss_base,
    _dim_epss,
    _dim_epss_spike,
    _dim_exploit_complexity,
    _dim_kev,
    _render_text,
    _risk_tier,
    _run_context_score,
    score_context_score,
)

# ---------------------------------------------------------------------------
# Realistic fixtures (CVE-2021-44228 / Log4Shell)
# ---------------------------------------------------------------------------

_NVD_CVE = {
    "id": "CVE-2021-44228",
    "metrics": {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "attackVector": "NETWORK",
                    "attackComplexity": "LOW",
                    "privilegesRequired": "NONE",
                    "userInteraction": "NONE",
                    "scope": "CHANGED",
                    "baseScore": 10.0,
                }
            }
        ]
    },
    "configurations": [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {"criteria": "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"},
                        {"criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
                        {"criteria": "cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*"},
                        {"criteria": "cpe:2.3:a:apache:log4j:2.16.0:*:*:*:*:*:*:*"},
                        {"criteria": "cpe:2.3:a:apache:log4j:2.17.0:*:*:*:*:*:*:*"},
                    ]
                }
            ]
        }
    ],
}

_NVD_RESP = {"vulnerabilities": [{"cve": _NVD_CVE}]}

_EPSS_ROW = {"cve": "CVE-2021-44228", "epss": "0.97478", "percentile": "0.99989", "date": "2024-01-15"}

_EPSS_RESP = {"data": [_EPSS_ROW]}

_EPSS_SERIES_RAW = [
    {"date": f"2024-01-{i:02d}", "epss": str(round(0.90 + i * 0.001, 4)), "percentile": "0.999"} for i in range(1, 31)
]

_EPSS_SERIES_WITH_SPIKE = [
    {"date": "2024-01-01", "epss": "0.05", "percentile": "0.60"},
    {"date": "2024-01-02", "epss": "0.06", "percentile": "0.61"},
    {"date": "2024-01-10", "epss": "0.18", "percentile": "0.75"},  # +0.12 jump from day 1
    {"date": "2024-01-20", "epss": "0.20", "percentile": "0.80"},
    {"date": "2024-01-30", "epss": "0.22", "percentile": "0.82"},
]

_KEV_DATA = {
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j"},
        {"cveID": "CVE-2022-22965", "vendorProject": "VMware", "product": "Spring Framework"},
    ]
}


# ---------------------------------------------------------------------------
# Helper: build a mock requests.Response
# ---------------------------------------------------------------------------


def _mock_resp(payload: dict) -> MagicMock:
    m = MagicMock()
    m.raise_for_status.return_value = None
    m.json.return_value = payload
    return m


# ---------------------------------------------------------------------------
# Unit: weights
# ---------------------------------------------------------------------------


class TestWeights:
    def test_weights_sum_to_one(self):
        total = sum(_WEIGHTS.values())
        assert abs(total - 1.0) < 1e-9

    def test_all_six_dimensions_present(self):
        expected = {"epss", "cvss_base", "exploit_complexity", "epss_spike", "blast_radius", "kev_listed"}
        assert set(_WEIGHTS.keys()) == expected

    def test_kev_weight_is_fifteen_percent(self):
        assert abs(_WEIGHTS["kev_listed"] - 0.15) < 1e-9


# ---------------------------------------------------------------------------
# Unit: dimension scorers
# ---------------------------------------------------------------------------


class TestDimEpss:
    def test_high_epss(self):
        assert _dim_epss({"epss": "0.97478"}) == pytest.approx(97.478, abs=0.01)

    def test_zero_epss(self):
        assert _dim_epss({"epss": "0.0"}) == 0.0

    def test_missing_key(self):
        assert _dim_epss({}) == 0.0

    def test_capped_at_100(self):
        assert _dim_epss({"epss": "1.5"}) == 100.0

    def test_invalid_value(self):
        assert _dim_epss({"epss": "not-a-number"}) == 0.0


class TestDimCvssBase:
    def test_perfect_ten(self):
        assert _dim_cvss_base(_NVD_CVE) == pytest.approx(100.0)

    def test_cvss_7_5(self):
        nvd = {
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 7.5,
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE",
                        }
                    }
                ]
            }
        }
        assert _dim_cvss_base(nvd) == pytest.approx(75.0)

    def test_fallback_v30(self):
        nvd = {"metrics": {"cvssMetricV30": [{"cvssData": {"baseScore": 6.0}}]}}
        assert _dim_cvss_base(nvd) == pytest.approx(60.0)

    def test_missing_metrics(self):
        assert _dim_cvss_base({}) == 0.0

    def test_empty_metrics(self):
        assert _dim_cvss_base({"metrics": {}}) == 0.0


class TestDimExploitComplexity:
    def test_log4shell_worst_case(self):
        # AC=LOW, PR=NONE, UI=NONE → 40+35+25 = 100
        score = _dim_exploit_complexity(_NVD_CVE)
        assert score == pytest.approx(100.0)

    def test_high_complexity_no_score(self):
        nvd = {
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "attackComplexity": "HIGH",
                            "privilegesRequired": "HIGH",
                            "userInteraction": "REQUIRED",
                        }
                    }
                ]
            }
        }
        assert _dim_exploit_complexity(nvd) == 0.0

    def test_low_pr_contributes(self):
        nvd = {
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "attackComplexity": "HIGH",
                            "privilegesRequired": "LOW",
                            "userInteraction": "NONE",
                        }
                    }
                ]
            }
        }
        # AC=HIGH (+0), PR=LOW (+20), UI=NONE (+25) = 45
        assert _dim_exploit_complexity(nvd) == pytest.approx(45.0)

    def test_missing_metrics(self):
        assert _dim_exploit_complexity({}) == 0.0


class TestDimEpssSpike:
    def test_spike_detected(self):
        series = [
            {"date": f"2024-01-{i:02d}", "epss": v}
            for i, v in [
                (1, 0.01),
                (2, 0.02),
                (3, 0.03),
                (8, 0.15),  # +0.12 in 7 days
            ]
        ]
        assert _dim_epss_spike(series) == 100.0

    def test_no_spike(self):
        series = [{"date": f"2024-01-{i:02d}", "epss": 0.05 + i * 0.001} for i in range(1, 31)]
        assert _dim_epss_spike(series) == 0.0

    def test_empty_series(self):
        assert _dim_epss_spike([]) == 0.0

    def test_single_point(self):
        assert _dim_epss_spike([{"date": "2024-01-01", "epss": 0.9}]) == 0.0

    def test_exactly_threshold_is_spike(self):
        series = [
            {"date": "2024-01-01", "epss": 0.05},
            {"date": "2024-01-08", "epss": 0.16},  # +0.11 > threshold
        ]
        assert _dim_epss_spike(series) == 100.0

    def test_just_below_threshold_no_spike(self):
        series = [
            {"date": "2024-01-01", "epss": 0.05},
            {"date": "2024-01-08", "epss": 0.14},  # +0.09 < 0.10
        ]
        assert _dim_epss_spike(series) == 0.0


class TestDimBlastRadius:
    def test_5_cpes_returns_40(self):
        # 5 CPEs → bucket 3–9 → 40
        assert _dim_blast_radius(_NVD_CVE) == pytest.approx(40.0)

    def test_zero_cpes(self):
        assert _dim_blast_radius({}) == 0.0

    def test_one_cpe(self):
        nvd = {"configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:foo:bar:1.0"}]}]}]}
        assert _dim_blast_radius(nvd) == pytest.approx(20.0)

    def test_thirty_cpes_returns_80(self):
        nvd = {
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": f"cpe:2.3:a:foo:bar:{i}"} for i in range(30)]}]}]
        }
        assert _dim_blast_radius(nvd) == pytest.approx(80.0)

    def test_hundred_plus_returns_100(self):
        nvd = {
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": f"cpe:2.3:a:foo:bar:{i}"} for i in range(100)]}]}]
        }
        assert _dim_blast_radius(nvd) == pytest.approx(100.0)

    def test_empty_configurations(self):
        assert _dim_blast_radius({"configurations": []}) == 0.0


class TestDimKev:
    def test_kev_listed_returns_100(self):
        assert _dim_kev(True) == 100.0

    def test_kev_not_listed_returns_0(self):
        assert _dim_kev(False) == 0.0


# ---------------------------------------------------------------------------
# Unit: composite calculation and risk tiers
# ---------------------------------------------------------------------------


class TestComposite:
    def test_all_zeros(self):
        dims = {k: 0.0 for k in _WEIGHTS}
        assert _compute_composite(dims) == 0.0

    def test_all_hundreds(self):
        dims = {k: 100.0 for k in _WEIGHTS}
        assert _compute_composite(dims) == pytest.approx(100.0)

    def test_kev_only(self):
        dims = {k: 0.0 for k in _WEIGHTS}
        dims["kev_listed"] = 100.0
        expected = 100.0 * _WEIGHTS["kev_listed"]
        assert _compute_composite(dims) == pytest.approx(expected, abs=0.01)

    def test_log4shell_typical(self):
        dims = {
            "epss": 97.478,
            "cvss_base": 100.0,
            "exploit_complexity": 100.0,
            "epss_spike": 0.0,
            "blast_radius": 40.0,
            "kev_listed": 100.0,
        }
        score = _compute_composite(dims)
        assert 70.0 <= score <= 100.0


class TestRiskTier:
    def test_critical(self):
        assert _risk_tier(80.0) == "CRITICAL"
        assert _risk_tier(99.0) == "CRITICAL"

    def test_high(self):
        assert _risk_tier(60.0) == "HIGH"
        assert _risk_tier(79.9) == "HIGH"

    def test_medium(self):
        assert _risk_tier(40.0) == "MEDIUM"
        assert _risk_tier(59.9) == "MEDIUM"

    def test_low(self):
        assert _risk_tier(39.9) == "LOW"
        assert _risk_tier(0.0) == "LOW"


# ---------------------------------------------------------------------------
# Integration: _run_context_score with mocked HTTP
# ---------------------------------------------------------------------------


class TestRunContextScore:
    @patch("manus_agent.tools.score_context_score._fetch_kev")
    @patch("manus_agent.tools.score_context_score._fetch_epss_series")
    @patch("manus_agent.tools.score_context_score._fetch_epss")
    @patch("manus_agent.tools.score_context_score._fetch_nvd")
    def test_log4shell_full_pipeline(self, mock_nvd, mock_epss, mock_series, mock_kev):
        mock_nvd.return_value = _NVD_CVE
        mock_epss.return_value = _EPSS_ROW
        mock_series.return_value = [{"date": f"2024-01-{i:02d}", "epss": 0.97} for i in range(1, 31)]
        mock_kev.return_value = True

        result = _run_context_score("CVE-2021-44228")

        assert result["cve_id"] == "CVE-2021-44228"
        assert result["kev_listed"] is True
        assert result["risk_tier"] in ("CRITICAL", "HIGH")
        assert result["composite_score"] >= 60.0
        assert "dominant_factor" in result
        assert result["confidence"] in ("HIGH", "MEDIUM", "LOW")
        assert "risk_summary" in result
        assert result["nvd_available"] is True

    @patch("manus_agent.tools.score_context_score._fetch_kev")
    @patch("manus_agent.tools.score_context_score._fetch_epss_series")
    @patch("manus_agent.tools.score_context_score._fetch_epss")
    @patch("manus_agent.tools.score_context_score._fetch_nvd")
    def test_kev_not_listed_lower_score(self, mock_nvd, mock_epss, mock_series, mock_kev):
        mock_nvd.return_value = _NVD_CVE
        mock_epss.return_value = _EPSS_ROW
        mock_series.return_value = [{"date": "2024-01-15", "epss": 0.97}]
        mock_kev.return_value = False  # NOT on KEV

        result = _run_context_score("CVE-2021-44228")

        assert result["kev_listed"] is False
        # KEV dimension should contribute 0
        kev_dim = result["dimensions"]["kev_listed"]
        assert kev_dim["raw_score"] == 0.0
        assert kev_dim["weighted_contribution"] == 0.0

    @patch("manus_agent.tools.score_context_score._fetch_kev")
    @patch("manus_agent.tools.score_context_score._fetch_epss_series")
    @patch("manus_agent.tools.score_context_score._fetch_epss")
    @patch("manus_agent.tools.score_context_score._fetch_nvd")
    def test_kev_adds_bonus_vs_non_kev(self, mock_nvd, mock_epss, mock_series, mock_kev):
        """KEV-listed CVE scores higher than identical non-KEV CVE."""
        mock_nvd.return_value = _NVD_CVE
        mock_epss.return_value = _EPSS_ROW
        mock_series.return_value = [{"date": "2024-01-15", "epss": 0.50}]

        mock_kev.return_value = True
        result_kev = _run_context_score("CVE-2021-44228")

        mock_kev.return_value = False
        result_no_kev = _run_context_score("CVE-2021-44228")

        assert result_kev["composite_score"] > result_no_kev["composite_score"]

    @patch("manus_agent.tools.score_context_score._fetch_kev")
    @patch("manus_agent.tools.score_context_score._fetch_epss_series")
    @patch("manus_agent.tools.score_context_score._fetch_epss")
    @patch("manus_agent.tools.score_context_score._fetch_nvd")
    def test_kev_bonus_is_15_points(self, mock_nvd, mock_epss, mock_series, mock_kev):
        """KEV dimension contributes exactly 15 points (100 × 0.15) when listed."""
        mock_nvd.return_value = {}
        mock_epss.return_value = {}
        mock_series.return_value = []

        mock_kev.return_value = True
        result = _run_context_score("CVE-2021-44228")
        # All other dims are 0 → composite = 100 × 0.15 = 15.0
        assert result["composite_score"] == pytest.approx(15.0, abs=0.1)

    @patch("manus_agent.tools.score_context_score._fetch_kev")
    @patch("manus_agent.tools.score_context_score._fetch_epss_series")
    @patch("manus_agent.tools.score_context_score._fetch_epss")
    @patch("manus_agent.tools.score_context_score._fetch_nvd")
    def test_all_sources_unavailable_returns_zero(self, mock_nvd, mock_epss, mock_series, mock_kev):
        mock_nvd.return_value = {}
        mock_epss.return_value = {}
        mock_series.return_value = []
        mock_kev.return_value = False

        result = _run_context_score("CVE-2021-44228")

        assert result["composite_score"] == 0.0
        assert result["risk_tier"] == "LOW"
        assert result["confidence"] == "LOW"

    @patch("manus_agent.tools.score_context_score._fetch_kev")
    @patch("manus_agent.tools.score_context_score._fetch_epss_series")
    @patch("manus_agent.tools.score_context_score._fetch_epss")
    @patch("manus_agent.tools.score_context_score._fetch_nvd")
    def test_result_has_all_six_dimensions(self, mock_nvd, mock_epss, mock_series, mock_kev):
        mock_nvd.return_value = _NVD_CVE
        mock_epss.return_value = _EPSS_ROW
        mock_series.return_value = []
        mock_kev.return_value = True

        result = _run_context_score("CVE-2021-44228")

        assert set(result["dimensions"].keys()) == {
            "epss",
            "cvss_base",
            "exploit_complexity",
            "epss_spike",
            "blast_radius",
            "kev_listed",
        }

    @patch("manus_agent.tools.score_context_score._fetch_kev")
    @patch("manus_agent.tools.score_context_score._fetch_epss_series")
    @patch("manus_agent.tools.score_context_score._fetch_epss")
    @patch("manus_agent.tools.score_context_score._fetch_nvd")
    def test_dominant_factor_is_valid_key(self, mock_nvd, mock_epss, mock_series, mock_kev):
        mock_nvd.return_value = _NVD_CVE
        mock_epss.return_value = _EPSS_ROW
        mock_series.return_value = []
        mock_kev.return_value = True

        result = _run_context_score("CVE-2021-44228")
        assert result["dominant_factor"] in _WEIGHTS

    @patch("manus_agent.tools.score_context_score._fetch_kev")
    @patch("manus_agent.tools.score_context_score._fetch_epss_series")
    @patch("manus_agent.tools.score_context_score._fetch_epss")
    @patch("manus_agent.tools.score_context_score._fetch_nvd")
    def test_confidence_high_when_4_plus_dims_live(self, mock_nvd, mock_epss, mock_series, mock_kev):
        mock_nvd.return_value = _NVD_CVE
        mock_epss.return_value = _EPSS_ROW
        mock_series.return_value = [{"date": "2024-01-15", "epss": 0.20}, {"date": "2024-01-22", "epss": 0.35}]
        mock_kev.return_value = True

        result = _run_context_score("CVE-2021-44228")
        assert result["confidence"] == "HIGH"

    @patch("manus_agent.tools.score_context_score._fetch_kev")
    @patch("manus_agent.tools.score_context_score._fetch_epss_series")
    @patch("manus_agent.tools.score_context_score._fetch_epss")
    @patch("manus_agent.tools.score_context_score._fetch_nvd")
    def test_kev_note_in_risk_summary_when_listed(self, mock_nvd, mock_epss, mock_series, mock_kev):
        mock_nvd.return_value = {}
        mock_epss.return_value = {}
        mock_series.return_value = []
        mock_kev.return_value = True

        result = _run_context_score("CVE-2021-44228")
        assert "actively exploited" in result["risk_summary"].lower() or "KEV" in result["risk_summary"]


# ---------------------------------------------------------------------------
# Integration: _render_text
# ---------------------------------------------------------------------------


class TestRenderText:
    @patch("manus_agent.tools.score_context_score._fetch_kev")
    @patch("manus_agent.tools.score_context_score._fetch_epss_series")
    @patch("manus_agent.tools.score_context_score._fetch_epss")
    @patch("manus_agent.tools.score_context_score._fetch_nvd")
    def test_text_output_has_all_sections(self, mock_nvd, mock_epss, mock_series, mock_kev):
        mock_nvd.return_value = _NVD_CVE
        mock_epss.return_value = _EPSS_ROW
        mock_series.return_value = []
        mock_kev.return_value = True

        result = _run_context_score("CVE-2021-44228")
        text = _render_text(result)

        assert "CVE-2021-44228" in text
        assert "Composite score" in text
        assert "Risk tier" in text
        assert "Dominant factor" in text
        assert "CISA KEV" in text
        assert "CISA KEV listing" in text  # dimension row label in table

    @patch("manus_agent.tools.score_context_score._fetch_kev")
    @patch("manus_agent.tools.score_context_score._fetch_epss_series")
    @patch("manus_agent.tools.score_context_score._fetch_epss")
    @patch("manus_agent.tools.score_context_score._fetch_nvd")
    def test_kev_warning_shows_in_text(self, mock_nvd, mock_epss, mock_series, mock_kev):
        mock_nvd.return_value = {}
        mock_epss.return_value = {}
        mock_series.return_value = []
        mock_kev.return_value = True

        result = _run_context_score("CVE-2021-44228")
        text = _render_text(result)
        assert "YES" in text or "actively exploited" in text.lower()

    @patch("manus_agent.tools.score_context_score._fetch_kev")
    @patch("manus_agent.tools.score_context_score._fetch_epss_series")
    @patch("manus_agent.tools.score_context_score._fetch_epss")
    @patch("manus_agent.tools.score_context_score._fetch_nvd")
    def test_kev_not_listed_shows_in_text(self, mock_nvd, mock_epss, mock_series, mock_kev):
        mock_nvd.return_value = {}
        mock_epss.return_value = {}
        mock_series.return_value = []
        mock_kev.return_value = False

        result = _run_context_score("CVE-2021-44228")
        text = _render_text(result)
        assert "not listed" in text


# ---------------------------------------------------------------------------
# Integration: score_context_score Strands entry point
# ---------------------------------------------------------------------------


class TestScoreContextScoreTool:
    @patch("manus_agent.tools.score_context_score._fetch_kev")
    @patch("manus_agent.tools.score_context_score._fetch_epss_series")
    @patch("manus_agent.tools.score_context_score._fetch_epss")
    @patch("manus_agent.tools.score_context_score._fetch_nvd")
    def test_text_output_default(self, mock_nvd, mock_epss, mock_series, mock_kev):
        mock_nvd.return_value = _NVD_CVE
        mock_epss.return_value = _EPSS_ROW
        mock_series.return_value = []
        mock_kev.return_value = True

        text = score_context_score("CVE-2021-44228")
        assert "CVE-2021-44228" in text
        assert "Risk tier" in text

    @patch("manus_agent.tools.score_context_score._fetch_kev")
    @patch("manus_agent.tools.score_context_score._fetch_epss_series")
    @patch("manus_agent.tools.score_context_score._fetch_epss")
    @patch("manus_agent.tools.score_context_score._fetch_nvd")
    def test_json_output(self, mock_nvd, mock_epss, mock_series, mock_kev):
        mock_nvd.return_value = _NVD_CVE
        mock_epss.return_value = _EPSS_ROW
        mock_series.return_value = []
        mock_kev.return_value = False

        text = score_context_score("CVE-2021-44228", output="json")
        data = json.loads(text)
        assert data["cve_id"] == "CVE-2021-44228"
        assert "composite_score" in data
        assert "risk_tier" in data
        assert "kev_listed" in data
        assert data["kev_listed"] is False

    def test_invalid_cve_returns_error(self):
        result = score_context_score("NOT-A-CVE")
        assert "Error" in result

    def test_empty_string_returns_error(self):
        result = score_context_score("")
        assert "Error" in result

    @patch("manus_agent.tools.score_context_score._fetch_kev")
    @patch("manus_agent.tools.score_context_score._fetch_epss_series")
    @patch("manus_agent.tools.score_context_score._fetch_epss")
    @patch("manus_agent.tools.score_context_score._fetch_nvd")
    def test_case_insensitive_cve_id(self, mock_nvd, mock_epss, mock_series, mock_kev):
        mock_nvd.return_value = _NVD_CVE
        mock_epss.return_value = _EPSS_ROW
        mock_series.return_value = []
        mock_kev.return_value = False

        text = score_context_score("cve-2021-44228")
        assert "CVE-2021-44228" in text

    @patch("manus_agent.tools.score_context_score._fetch_kev")
    @patch("manus_agent.tools.score_context_score._fetch_epss_series")
    @patch("manus_agent.tools.score_context_score._fetch_epss")
    @patch("manus_agent.tools.score_context_score._fetch_nvd")
    def test_score_is_higher_with_kev(self, mock_nvd, mock_epss, mock_series, mock_kev):
        """Verify KEV listing raises the composite score."""
        mock_nvd.return_value = {}
        mock_epss.return_value = {}
        mock_series.return_value = []

        mock_kev.return_value = True
        kev_text = score_context_score("CVE-2021-44228", output="json")
        kev_score = json.loads(kev_text)["composite_score"]

        mock_kev.return_value = False
        no_kev_text = score_context_score("CVE-2021-44228", output="json")
        no_kev_score = json.loads(no_kev_text)["composite_score"]

        assert kev_score > no_kev_score

    @patch("manus_agent.tools.score_context_score._fetch_kev")
    @patch("manus_agent.tools.score_context_score._fetch_epss_series")
    @patch("manus_agent.tools.score_context_score._fetch_epss")
    @patch("manus_agent.tools.score_context_score._fetch_nvd")
    def test_json_has_dimensions_with_weighted_contribution(self, mock_nvd, mock_epss, mock_series, mock_kev):
        mock_nvd.return_value = _NVD_CVE
        mock_epss.return_value = _EPSS_ROW
        mock_series.return_value = []
        mock_kev.return_value = True

        data = json.loads(score_context_score("CVE-2021-44228", output="json"))
        for dim in ("epss", "cvss_base", "exploit_complexity", "epss_spike", "blast_radius", "kev_listed"):
            assert dim in data["dimensions"]
            d = data["dimensions"][dim]
            assert "raw_score" in d
            assert "weight" in d
            assert "weighted_contribution" in d


# ---------------------------------------------------------------------------
# Unit: TOOL_SPEC schema
# ---------------------------------------------------------------------------


class TestToolSpec:
    def test_tool_spec_importable(self):
        from manus_agent.tools.score_context_score import TOOL_SPEC

        assert TOOL_SPEC["name"] == "score_context_score"
        assert "kev" in TOOL_SPEC["description"].lower()
        schema = TOOL_SPEC["inputSchema"]["json"]
        assert "cve_id" in schema["properties"]
        assert "output" in schema["properties"]
        assert "weights" in schema["properties"]
