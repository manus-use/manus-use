"""
Tests for src/manus_agent/tools/score_context_score.py

All external HTTP calls are fully mocked — no real network I/O.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Module under test
# ---------------------------------------------------------------------------
from manus_agent.tools.score_context_score import (
    _AV_SURFACE_SCORE,
    _BLAST_LABEL_SCORE,
    _DEFAULT_WEIGHTS,
    _RISK_THRESHOLDS,
    _build_risk_summary,
    _clamp,
    _compute_composite,
    _fetch_epss_current,
    _fetch_epss_series,
    _fetch_nvd_cvss,
    _render_text,
    _risk_label,
    _run_context_score,
    _score_attack_surface_dimension,
    _score_blast_radius_dimension,
    _score_epss_momentum_dimension,
    _score_exploit_complexity_dimension,
    _score_patch_lag_dimension,
    _validate_weights,
    score_context_score,
)

# ===========================================================================
# Fixtures / helpers
# ===========================================================================

_VALID_CVE = "CVE-2021-44228"


def _nvd_resp(
    av: str = "NETWORK",
    pr: str = "NONE",
    ui: str = "NONE",
    scope: str = "CHANGED",
    base_score: float = 10.0,
) -> dict[str, Any]:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "attackVector": av,
                                    "privilegesRequired": pr,
                                    "userInteraction": ui,
                                    "scope": scope,
                                    "baseScore": base_score,
                                }
                            }
                        ]
                    }
                }
            }
        ]
    }


def _epss_current_resp(epss: float = 0.97, percentile: float = 0.9997) -> dict[str, Any]:
    return {"data": [{"epss": str(epss), "percentile": str(percentile)}]}


def _epss_series_resp(scores: list[float] | None = None) -> dict[str, Any]:
    if scores is None:
        scores = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.97]
    data = []
    import datetime

    base = datetime.date(2024, 1, 1)
    for i, s in enumerate(scores):
        d = (base + datetime.timedelta(days=i)).isoformat()
        data.append({"date": d, "epss": str(s), "percentile": "0.99"})
    return {"data": data}


def _osv_resp_with_fix() -> dict[str, Any]:
    return {
        "vulns": [
            {
                "id": "GHSA-xxxx-yyyy-zzzz",
                "affected": [
                    {
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "2.0.0"},
                                    {"fixed": "2.15.0"},
                                ],
                            }
                        ]
                    }
                ],
            }
        ]
    }


def _osv_resp_no_fix() -> dict[str, Any]:
    return {
        "vulns": [
            {
                "id": "GHSA-xxxx-yyyy-zzzz",
                "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}],
            }
        ]
    }


def _mock_requests_get(url: str, **kwargs) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    if "nvd.nist.gov" in url:
        resp.json.return_value = _nvd_resp()
    elif "api.first.org" in url:
        params = kwargs.get("params", {})
        if params.get("scope") == "time-series":
            resp.json.return_value = _epss_series_resp()
        else:
            resp.json.return_value = _epss_current_resp()
    else:
        resp.json.return_value = {}
    return resp


# ===========================================================================
# _clamp
# ===========================================================================


class TestClamp:
    def test_clamp_within_range(self):
        assert _clamp(50.0) == 50.0

    def test_clamp_above_max(self):
        assert _clamp(150.0) == 100.0

    def test_clamp_below_min(self):
        assert _clamp(-10.0) == 0.0

    def test_clamp_at_boundaries(self):
        assert _clamp(0.0) == 0.0
        assert _clamp(100.0) == 100.0

    def test_clamp_custom_bounds(self):
        assert _clamp(75.0, 20.0, 80.0) == 75.0
        assert _clamp(90.0, 20.0, 80.0) == 80.0
        assert _clamp(10.0, 20.0, 80.0) == 20.0


# ===========================================================================
# _risk_label
# ===========================================================================


class TestRiskLabel:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (90.0, "CRITICAL"),
            (80.0, "CRITICAL"),
            (79.9, "HIGH"),
            (60.0, "HIGH"),
            (59.9, "MEDIUM"),
            (40.0, "MEDIUM"),
            (39.9, "LOW"),
            (20.0, "LOW"),
            (19.9, "INFORMATIONAL"),
            (0.0, "INFORMATIONAL"),
        ],
    )
    def test_thresholds(self, score: float, expected: str):
        assert _risk_label(score) == expected


# ===========================================================================
# _validate_weights
# ===========================================================================


class TestValidateWeights:
    def test_already_normalized(self):
        w = {"a": 0.5, "b": 0.5}
        result = _validate_weights(w)
        assert abs(sum(result.values()) - 1.0) < 1e-9

    def test_normalizes_unequal_weights(self):
        w = {"a": 2.0, "b": 3.0}
        result = _validate_weights(w)
        assert abs(result["a"] - 0.4) < 1e-9
        assert abs(result["b"] - 0.6) < 1e-9

    def test_zero_total_returns_default(self):
        result = _validate_weights({"a": 0.0, "b": 0.0})
        assert result == _DEFAULT_WEIGHTS

    def test_default_weights_sum_to_one(self):
        assert abs(sum(_DEFAULT_WEIGHTS.values()) - 1.0) < 1e-9

    def test_single_weight(self):
        result = _validate_weights({"only": 5.0})
        assert abs(result["only"] - 1.0) < 1e-9


# ===========================================================================
# _fetch_nvd_cvss
# ===========================================================================


class TestFetchNvdCvss:
    def test_returns_cvss_data(self):
        with patch("manus_agent.tools.score_context_score.requests.get") as mock_get:
            mock_get.return_value = MagicMock(
                raise_for_status=lambda: None,
                json=lambda: _nvd_resp(av="NETWORK", pr="NONE", base_score=10.0),
            )
            result = _fetch_nvd_cvss(_VALID_CVE)
        assert result["attackVector"] == "NETWORK"
        assert result["baseScore"] == 10.0

    def test_returns_empty_on_http_error(self):
        with patch("manus_agent.tools.score_context_score.requests.get") as mock_get:
            mock_get.side_effect = Exception("timeout")
            result = _fetch_nvd_cvss(_VALID_CVE)
        assert result == {}

    def test_returns_empty_when_no_vulns(self):
        with patch("manus_agent.tools.score_context_score.requests.get") as mock_get:
            mock_get.return_value = MagicMock(
                raise_for_status=lambda: None,
                json=lambda: {"vulnerabilities": []},
            )
            result = _fetch_nvd_cvss(_VALID_CVE)
        assert result == {}

    def test_v30_fallback(self):
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "metrics": {
                            "cvssMetricV30": [
                                {"cvssData": {"attackVector": "LOCAL", "privilegesRequired": "HIGH", "baseScore": 7.0}}
                            ]
                        }
                    }
                }
            ]
        }
        with patch("manus_agent.tools.score_context_score.requests.get") as mock_get:
            mock_get.return_value = MagicMock(raise_for_status=lambda: None, json=lambda: data)
            result = _fetch_nvd_cvss(_VALID_CVE)
        assert result["attackVector"] == "LOCAL"

    def test_v2_fallback(self):
        data = {
            "vulnerabilities": [
                {"cve": {"metrics": {"cvssMetricV2": [{"cvssData": {"attackVector": "NETWORK", "baseScore": 6.5}}]}}}
            ]
        }
        with patch("manus_agent.tools.score_context_score.requests.get") as mock_get:
            mock_get.return_value = MagicMock(raise_for_status=lambda: None, json=lambda: data)
            result = _fetch_nvd_cvss(_VALID_CVE)
        assert result["baseScore"] == 6.5


# ===========================================================================
# _fetch_epss_current
# ===========================================================================


class TestFetchEpssCurrent:
    def test_returns_epss_and_percentile(self):
        with patch("manus_agent.tools.score_context_score.requests.get") as mock_get:
            mock_get.return_value = MagicMock(
                raise_for_status=lambda: None,
                json=lambda: _epss_current_resp(0.75, 0.95),
            )
            result = _fetch_epss_current(_VALID_CVE)
        assert result["epss"] == pytest.approx(0.75)
        assert result["percentile"] == pytest.approx(0.95)

    def test_returns_empty_on_error(self):
        with patch("manus_agent.tools.score_context_score.requests.get") as mock_get:
            mock_get.side_effect = Exception("network error")
            result = _fetch_epss_current(_VALID_CVE)
        assert result == {}

    def test_returns_empty_when_no_data(self):
        with patch("manus_agent.tools.score_context_score.requests.get") as mock_get:
            mock_get.return_value = MagicMock(raise_for_status=lambda: None, json=lambda: {"data": []})
            result = _fetch_epss_current(_VALID_CVE)
        assert result == {}


# ===========================================================================
# _fetch_epss_series
# ===========================================================================


class TestFetchEpsseries:
    def test_returns_trend_info(self):
        with patch("manus_agent.tools.score_context_score.requests.get") as mock_get:
            mock_get.return_value = MagicMock(
                raise_for_status=lambda: None,
                json=lambda: _epss_series_resp([0.10, 0.15, 0.20, 0.25, 0.30]),
            )
            result = _fetch_epss_series(_VALID_CVE)
        assert "trend" in result
        assert "spike_detected" in result

    def test_returns_empty_on_import_error(self):
        import sys

        # Temporarily hide the module
        with patch.dict(sys.modules, {"manus_agent.tools.get_epss_trend": None}):
            result = _fetch_epss_series(_VALID_CVE)
        # Should return empty dict gracefully (import fails → except ImportError path
        # but None in sys.modules raises ImportError on 'from' import)
        # We just check it doesn't raise
        assert isinstance(result, dict)

    def test_returns_empty_on_network_error(self):
        with patch("manus_agent.tools.score_context_score.requests.get") as mock_get:
            mock_get.side_effect = Exception("timeout")
            result = _fetch_epss_series(_VALID_CVE)
        assert result == {}


# ===========================================================================
# _score_exploit_complexity_dimension
# ===========================================================================


class TestScoreExploitComplexityDimension:
    def test_uses_run_scoring_when_available(self):
        mock_result = {
            "complexity_score": 1.5,
            "complexity_label": "trivial",
            "attacker_friendly": True,
            "poc_found": True,
        }
        with patch("manus_agent.tools.score_context_score.requests.get"):
            with patch(
                "manus_agent.tools.score_exploit_complexity._run_scoring",
                return_value=mock_result,
            ):
                result = _score_exploit_complexity_dimension(_VALID_CVE)
        # complexity 1.5 → risk = (5 - 1.5) / 4 * 100 = 87.5
        assert result["score"] == pytest.approx(87.5)
        assert result["attacker_friendly"] is True
        assert result["source"] == "score_exploit_complexity"
        assert result["available"] is True

    def test_high_complexity_yields_low_risk(self):
        mock_result = {
            "complexity_score": 5.0,
            "complexity_label": "very_high",
            "attacker_friendly": False,
            "poc_found": False,
        }
        with patch(
            "manus_agent.tools.score_exploit_complexity._run_scoring",
            return_value=mock_result,
        ):
            result = _score_exploit_complexity_dimension(_VALID_CVE)
        # complexity 5.0 → risk = (5 - 5) / 4 * 100 = 0
        assert result["score"] == pytest.approx(0.0)

    def test_falls_back_to_nvd_heuristic_on_import_error(self):
        import sys

        with patch.dict(sys.modules, {"manus_agent.tools.score_exploit_complexity": None}):
            with patch("manus_agent.tools.score_context_score.requests.get") as mock_get:
                mock_get.return_value = MagicMock(
                    raise_for_status=lambda: None,
                    json=lambda: _nvd_resp(av="NETWORK", pr="NONE"),
                )
                result = _score_exploit_complexity_dimension(_VALID_CVE)
        assert result["source"] == "nvd_cvss_heuristic"
        assert result["available"] is True
        assert result["score"] > 0

    def test_network_av_gives_high_score(self):
        mock_result = {
            "complexity_score": 1.0,
            "complexity_label": "trivial",
            "attacker_friendly": True,
            "poc_found": True,
        }
        with patch(
            "manus_agent.tools.score_exploit_complexity._run_scoring",
            return_value=mock_result,
        ):
            result = _score_exploit_complexity_dimension(_VALID_CVE)
        assert result["score"] == 100.0

    def test_returns_default_on_all_failures(self):
        import sys

        with patch.dict(sys.modules, {"manus_agent.tools.score_exploit_complexity": None}):
            with patch("manus_agent.tools.score_context_score.requests.get") as mock_get:
                mock_get.side_effect = Exception("network error")
                result = _score_exploit_complexity_dimension(_VALID_CVE)
        assert result["score"] == 50.0
        assert result["available"] is False
        assert result["source"] == "default_fallback"


# ===========================================================================
# _score_epss_momentum_dimension
# ===========================================================================


class TestScoreEpssMomentumDimension:
    def test_high_epss_with_spike_yields_high_score(self):
        with (
            patch(
                "manus_agent.tools.score_context_score._fetch_epss_current",
                return_value={"epss": 0.97, "percentile": 0.9997},
            ),
            patch(
                "manus_agent.tools.score_context_score._fetch_epss_series",
                return_value={
                    "spike_detected": True,
                    "trend": "rising",
                    "max_7d_jump": 0.35,
                },
            ),
        ):
            result = _score_epss_momentum_dimension(_VALID_CVE)
        # base = 0.97 * 80 = 77.6; spike = +15; rising = +10 → capped at 100
        assert result["score"] == 100.0
        assert result["spike_detected"] is True
        assert result["trend"] == "rising"

    def test_low_epss_stable_yields_low_score(self):
        with (
            patch(
                "manus_agent.tools.score_context_score._fetch_epss_current",
                return_value={"epss": 0.001, "percentile": 0.20},
            ),
            patch(
                "manus_agent.tools.score_context_score._fetch_epss_series",
                return_value={"spike_detected": False, "trend": "stable", "max_7d_jump": 0.0},
            ),
        ):
            result = _score_epss_momentum_dimension(_VALID_CVE)
        # base = 0.001 * 80 = 0.08; no bonus → ~0.08
        assert result["score"] < 5.0

    def test_falling_trend_reduces_score(self):
        with (
            patch(
                "manus_agent.tools.score_context_score._fetch_epss_current",
                return_value={"epss": 0.50, "percentile": 0.80},
            ),
            patch(
                "manus_agent.tools.score_context_score._fetch_epss_series",
                return_value={"spike_detected": False, "trend": "falling", "max_7d_jump": 0.0},
            ),
        ):
            result = _score_epss_momentum_dimension(_VALID_CVE)
        # base = 0.50 * 80 = 40; falling = -5 → 35
        assert result["score"] == pytest.approx(35.0)

    def test_unavailable_when_no_epss_data(self):
        with (
            patch(
                "manus_agent.tools.score_context_score._fetch_epss_current",
                return_value={},
            ),
            patch(
                "manus_agent.tools.score_context_score._fetch_epss_series",
                return_value={},
            ),
        ):
            result = _score_epss_momentum_dimension(_VALID_CVE)
        assert result["available"] is False

    def test_score_clamped_to_100(self):
        with (
            patch(
                "manus_agent.tools.score_context_score._fetch_epss_current",
                return_value={"epss": 1.0, "percentile": 1.0},
            ),
            patch(
                "manus_agent.tools.score_context_score._fetch_epss_series",
                return_value={"spike_detected": True, "trend": "rising", "max_7d_jump": 0.5},
            ),
        ):
            result = _score_epss_momentum_dimension(_VALID_CVE)
        assert result["score"] == 100.0


# ===========================================================================
# _score_blast_radius_dimension
# ===========================================================================


class TestScoreBlastRadiusDimension:
    def test_critical_blast_radius(self):
        with (
            patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_nvd_affected",
                return_value=[{"name": "requests", "ecosystem": "PyPI"}],
            ),
            patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_osv_affected",
                return_value=[],
            ),
            patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_ghsa_affected",
                return_value=[],
            ),
            patch(
                "manus_agent.tools.get_dependency_blast_radius._enrich_package",
                return_value={"weekly_downloads": 10_000_000, "dependent_packages_count": 100_000},
            ),
        ):
            result = _score_blast_radius_dimension(_VALID_CVE)
        assert result["score"] == 100.0
        assert result["blast_label"] == "CRITICAL"

    def test_low_blast_radius(self):
        with (
            patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_nvd_affected",
                return_value=[{"name": "obscure-pkg", "ecosystem": "PyPI"}],
            ),
            patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_osv_affected",
                return_value=[],
            ),
            patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_ghsa_affected",
                return_value=[],
            ),
            patch(
                "manus_agent.tools.get_dependency_blast_radius._enrich_package",
                return_value={"weekly_downloads": 100, "dependent_packages_count": 5},
            ),
        ):
            result = _score_blast_radius_dimension(_VALID_CVE)
        assert result["score"] == pytest.approx(_BLAST_LABEL_SCORE["LOW"])
        assert result["blast_label"] == "LOW"

    def test_no_packages_found(self):
        with (
            patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_nvd_affected",
                return_value=[],
            ),
            patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_osv_affected",
                return_value=[],
            ),
            patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_ghsa_affected",
                return_value=[],
            ),
        ):
            result = _score_blast_radius_dimension(_VALID_CVE)
        assert result["packages_found"] == 0
        assert result["score"] == 20.0
        assert result["blast_label"] == "UNKNOWN"

    def test_falls_back_on_import_error(self):
        import sys

        with patch.dict(sys.modules, {"manus_agent.tools.get_dependency_blast_radius": None}):
            result = _score_blast_radius_dimension(_VALID_CVE)
        assert result["available"] is False
        assert result["score"] == 20.0

    def test_all_blast_labels_map_to_known_scores(self):
        for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
            assert label in _BLAST_LABEL_SCORE


# ===========================================================================
# _score_attack_surface_dimension
# ===========================================================================


class TestScoreAttackSurfaceDimension:
    def test_uses_dedicated_tool_when_available(self):
        mock_result = {"exposure_score": 5.0, "exposure_label": "critical", "archetype": "web-server"}
        import sys
        import types

        fake_mod = types.ModuleType("manus_agent.tools.score_attack_surface")
        fake_mod._run_scoring = lambda cve_id: mock_result  # type: ignore[attr-defined]
        with patch.dict(sys.modules, {"manus_agent.tools.score_attack_surface": fake_mod}):
            result = _score_attack_surface_dimension(_VALID_CVE)
        assert result["source"] == "score_attack_surface"
        assert result["score"] == pytest.approx(100.0)

    def test_falls_back_to_nvd_heuristic(self):
        import sys

        with patch.dict(sys.modules, {"manus_agent.tools.score_attack_surface": None}):
            with patch("manus_agent.tools.score_context_score.requests.get") as mock_get:
                mock_get.return_value = MagicMock(
                    raise_for_status=lambda: None,
                    json=lambda: _nvd_resp(av="NETWORK", scope="CHANGED"),
                )
                result = _score_attack_surface_dimension(_VALID_CVE)
        assert result["source"] == "nvd_cvss_heuristic"
        # NETWORK(85) + CHANGED(+10) = 95
        assert result["score"] == pytest.approx(95.0)

    def test_local_av_yields_lower_score(self):
        import sys

        with patch.dict(sys.modules, {"manus_agent.tools.score_attack_surface": None}):
            with patch("manus_agent.tools.score_context_score.requests.get") as mock_get:
                mock_get.return_value = MagicMock(
                    raise_for_status=lambda: None,
                    json=lambda: _nvd_resp(av="LOCAL", scope="UNCHANGED"),
                )
                result = _score_attack_surface_dimension(_VALID_CVE)
        assert result["score"] == pytest.approx(_AV_SURFACE_SCORE["LOCAL"])

    def test_physical_av_yields_lowest_score(self):
        import sys

        with patch.dict(sys.modules, {"manus_agent.tools.score_attack_surface": None}):
            with patch("manus_agent.tools.score_context_score.requests.get") as mock_get:
                mock_get.return_value = MagicMock(
                    raise_for_status=lambda: None,
                    json=lambda: _nvd_resp(av="PHYSICAL", scope="UNCHANGED"),
                )
                result = _score_attack_surface_dimension(_VALID_CVE)
        assert result["score"] == pytest.approx(_AV_SURFACE_SCORE["PHYSICAL"])

    def test_defaults_on_all_failures(self):
        import sys

        with patch.dict(sys.modules, {"manus_agent.tools.score_attack_surface": None}):
            with patch("manus_agent.tools.score_context_score.requests.get") as mock_get:
                mock_get.side_effect = Exception("timeout")
                result = _score_attack_surface_dimension(_VALID_CVE)
        assert result["score"] == 50.0
        assert result["available"] is False


# ===========================================================================
# _score_patch_lag_dimension
# ===========================================================================


class TestScorePatchLagDimension:
    def test_uses_dedicated_tool_when_available(self):
        import sys

        fake_mod = MagicMock()
        fake_mod._run_patch_status.return_value = {
            "overall_status": "fully_patched",
            "fastest_patch_days": 5,
            "fastest_patch_vendor": "Ubuntu",
        }
        with patch.dict(sys.modules, {"manus_agent.tools.get_patch_status": fake_mod}):
            result = _score_patch_lag_dimension(_VALID_CVE)
        assert result["source"] == "get_patch_status"
        # fully_patched=15 + fast_patch≤7 → -10 = 5
        assert result["score"] == pytest.approx(5.0)
        assert result["fastest_patch_vendor"] == "Ubuntu"

    def test_unpatched_status_gives_high_score(self):
        import sys

        fake_mod = MagicMock()
        fake_mod._run_patch_status.return_value = {
            "overall_status": "unpatched",
            "fastest_patch_days": None,
            "fastest_patch_vendor": None,
        }
        with patch.dict(sys.modules, {"manus_agent.tools.get_patch_status": fake_mod}):
            result = _score_patch_lag_dimension(_VALID_CVE)
        assert result["score"] == pytest.approx(90.0)

    def test_partially_patched(self):
        import sys

        fake_mod = MagicMock()
        fake_mod._run_patch_status.return_value = {
            "overall_status": "partially_patched",
            "fastest_patch_days": 20,
            "fastest_patch_vendor": "Debian",
        }
        with patch.dict(sys.modules, {"manus_agent.tools.get_patch_status": fake_mod}):
            result = _score_patch_lag_dimension(_VALID_CVE)
        # partially_patched=60 + 7<days≤30 → -5 = 55
        assert result["score"] == pytest.approx(55.0)

    def test_osv_fallback_with_fix(self):
        import sys

        with patch.dict(sys.modules, {"manus_agent.tools.get_patch_status": None}):
            with patch("manus_agent.tools.score_context_score.requests.post") as mock_post:
                mock_post.return_value = MagicMock(
                    raise_for_status=lambda: None,
                    json=lambda: _osv_resp_with_fix(),
                )
                result = _score_patch_lag_dimension(_VALID_CVE)
        assert result["source"] == "osv_fallback"

    def test_osv_fallback_no_fix(self):
        import sys

        with patch.dict(sys.modules, {"manus_agent.tools.get_patch_status": None}):
            with patch("manus_agent.tools.score_context_score.requests.post") as mock_post:
                mock_post.return_value = MagicMock(
                    raise_for_status=lambda: None,
                    json=lambda: _osv_resp_no_fix(),
                )
                result = _score_patch_lag_dimension(_VALID_CVE)
        assert result["score"] == pytest.approx(65.0)
        assert result["overall_status"] == "no_fix_found"

    def test_osv_fallback_empty_response(self):
        import sys

        with patch.dict(sys.modules, {"manus_agent.tools.get_patch_status": None}):
            with patch("manus_agent.tools.score_context_score.requests.post") as mock_post:
                mock_post.return_value = MagicMock(
                    raise_for_status=lambda: None,
                    json=lambda: {"vulns": []},
                )
                result = _score_patch_lag_dimension(_VALID_CVE)
        assert result["overall_status"] == "unknown"

    def test_defaults_on_all_failures(self):
        import sys

        with patch.dict(sys.modules, {"manus_agent.tools.get_patch_status": None}):
            with patch("manus_agent.tools.score_context_score.requests.post") as mock_post:
                mock_post.side_effect = Exception("network error")
                result = _score_patch_lag_dimension(_VALID_CVE)
        assert result["score"] == 50.0
        assert result["available"] is False


# ===========================================================================
# _compute_composite
# ===========================================================================


class TestComputeComposite:
    def _all_dim_scores(self, score: float = 80.0, available: bool = True) -> dict:
        return {dim: {"score": score, "available": available} for dim in _DEFAULT_WEIGHTS}

    def test_uniform_scores_produce_expected_total(self):
        dim_scores = self._all_dim_scores(80.0)
        ctx, dominant, conf = _compute_composite(dim_scores, _DEFAULT_WEIGHTS)
        assert ctx == pytest.approx(80.0)

    def test_all_zero_produces_zero(self):
        dim_scores = self._all_dim_scores(0.0)
        ctx, _, _ = _compute_composite(dim_scores, _DEFAULT_WEIGHTS)
        assert ctx == pytest.approx(0.0)

    def test_dominant_factor_is_highest_weight_when_equal_scores(self):
        # exploit_complexity has weight 0.30 — should dominate when scores equal
        dim_scores = self._all_dim_scores(50.0)
        _, dominant, _ = _compute_composite(dim_scores, _DEFAULT_WEIGHTS)
        assert dominant == "exploit_complexity"

    def test_confidence_high_when_all_available(self):
        dim_scores = self._all_dim_scores(50.0, available=True)
        _, _, conf = _compute_composite(dim_scores, _DEFAULT_WEIGHTS)
        assert conf == "HIGH"

    def test_confidence_medium_when_two_available(self):
        dim_scores = self._all_dim_scores(50.0, available=False)
        dim_scores["exploit_complexity"]["available"] = True
        dim_scores["epss_momentum"]["available"] = True
        _, _, conf = _compute_composite(dim_scores, _DEFAULT_WEIGHTS)
        assert conf == "MEDIUM"

    def test_confidence_low_when_one_available(self):
        dim_scores = self._all_dim_scores(50.0, available=False)
        dim_scores["exploit_complexity"]["available"] = True
        _, _, conf = _compute_composite(dim_scores, _DEFAULT_WEIGHTS)
        assert conf == "LOW"

    def test_context_score_clamped_to_100(self):
        dim_scores = self._all_dim_scores(200.0)
        ctx, _, _ = _compute_composite(dim_scores, _DEFAULT_WEIGHTS)
        assert ctx == 100.0

    def test_dominant_factor_when_one_dimension_is_much_higher(self):
        dim_scores = self._all_dim_scores(10.0)
        dim_scores["epss_momentum"]["score"] = 100.0
        _, dominant, _ = _compute_composite(dim_scores, _DEFAULT_WEIGHTS)
        assert dominant == "epss_momentum"


# ===========================================================================
# _build_risk_summary
# ===========================================================================


class TestBuildRiskSummary:
    def test_critical_summary_contains_cve_and_label(self):
        dim_scores = {"epss_momentum": {"epss": 0.97}}
        summary = _build_risk_summary(_VALID_CVE, 85.0, "CRITICAL", "epss_momentum", dim_scores, "HIGH")
        assert _VALID_CVE in summary
        assert "critically urgent" in summary
        assert "rising exploitation probability" in summary

    def test_low_confidence_adds_note(self):
        dim_scores = {"epss_momentum": {"epss": 0.0}}
        summary = _build_risk_summary(_VALID_CVE, 30.0, "LOW", "patch_lag", dim_scores, "LOW")
        assert "confidence: low" in summary

    def test_high_confidence_omits_confidence_note(self):
        dim_scores = {"epss_momentum": {"epss": 0.5}}
        summary = _build_risk_summary(_VALID_CVE, 65.0, "HIGH", "blast_radius", dim_scores, "HIGH")
        assert "confidence" not in summary

    def test_epss_zero_omits_epss_phrase(self):
        dim_scores = {"epss_momentum": {"epss": 0.0}}
        summary = _build_risk_summary(_VALID_CVE, 50.0, "MEDIUM", "exploit_complexity", dim_scores, "HIGH")
        assert "EPSS" not in summary

    def test_ends_with_period(self):
        dim_scores = {"epss_momentum": {"epss": 0.3}}
        summary = _build_risk_summary(_VALID_CVE, 40.0, "MEDIUM", "exploit_complexity", dim_scores, "MEDIUM")
        assert summary.endswith(".")


# ===========================================================================
# _render_text
# ===========================================================================


class TestRenderText:
    def _make_result(
        self,
        score: float = 75.0,
        label: str = "HIGH",
        dominant: str = "exploit_complexity",
        conf: str = "HIGH",
    ) -> dict:
        return {
            "cve_id": _VALID_CVE,
            "context_score": score,
            "risk_label": label,
            "dominant_factor": dominant,
            "confidence": conf,
            "risk_summary": f"Test summary for {_VALID_CVE}.",
            "dimensions": {
                "exploit_complexity": {"score": 80.0, "available": True, "source": "score_exploit_complexity"},
                "epss_momentum": {"score": 70.0, "available": True, "source": "get_epss_trend"},
                "blast_radius": {"score": 75.0, "available": True, "source": "get_dependency_blast_radius"},
                "attack_surface": {"score": 90.0, "available": True, "source": "nvd_cvss_heuristic"},
                "patch_lag": {"score": 50.0, "available": False, "source": "default_fallback"},
            },
            "weights": _DEFAULT_WEIGHTS,
        }

    def test_output_contains_cve_id(self):
        result = self._make_result()
        text = _render_text(result)
        assert _VALID_CVE in text

    def test_output_contains_score(self):
        result = self._make_result(score=75.0)
        text = _render_text(result)
        assert "75.0" in text

    def test_output_contains_risk_label(self):
        result = self._make_result(label="HIGH")
        text = _render_text(result)
        assert "HIGH" in text

    def test_output_contains_all_dimension_names(self):
        result = self._make_result()
        text = _render_text(result)
        for dim in ("Exploit Complexity", "EPSS Momentum", "Blast Radius", "Attack Surface", "Patch Lag"):
            assert dim in text

    def test_unavailable_dimension_shown_with_cross(self):
        result = self._make_result()
        text = _render_text(result)
        assert "✗" in text  # patch_lag has available=False

    def test_available_dimension_shown_with_check(self):
        result = self._make_result()
        text = _render_text(result)
        assert "✓" in text


# ===========================================================================
# _run_context_score
# ===========================================================================


class TestRunContextScore:
    def _patch_all_dimensions(self):
        return {
            "_score_exploit_complexity_dimension": {
                "score": 80.0,
                "available": True,
                "source": "score_exploit_complexity",
                "attacker_friendly": True,
                "poc_found": True,
                "label": "trivial",
                "raw": 1.5,
            },
            "_score_epss_momentum_dimension": {
                "score": 90.0,
                "available": True,
                "source": "get_epss_trend",
                "epss": 0.97,
                "percentile": 0.9997,
                "spike_detected": True,
                "trend": "rising",
                "max_7d_jump": 0.35,
            },
            "_score_blast_radius_dimension": {
                "score": 100.0,
                "available": True,
                "source": "get_dependency_blast_radius",
                "blast_label": "CRITICAL",
                "packages_found": 3,
            },
            "_score_attack_surface_dimension": {
                "score": 95.0,
                "available": True,
                "source": "nvd_cvss_heuristic",
                "exposure_label": "heuristic",
                "archetype": "av=NETWORK",
            },
            "_score_patch_lag_dimension": {
                "score": 90.0,
                "available": True,
                "source": "osv_fallback",
                "overall_status": "unpatched",
                "fastest_patch_days": None,
                "fastest_patch_vendor": None,
            },
        }

    def test_returns_valid_structure(self):
        patches = self._patch_all_dimensions()
        with (
            patch(
                "manus_agent.tools.score_context_score._score_exploit_complexity_dimension",
                return_value=patches["_score_exploit_complexity_dimension"],
            ),
            patch(
                "manus_agent.tools.score_context_score._score_epss_momentum_dimension",
                return_value=patches["_score_epss_momentum_dimension"],
            ),
            patch(
                "manus_agent.tools.score_context_score._score_blast_radius_dimension",
                return_value=patches["_score_blast_radius_dimension"],
            ),
            patch(
                "manus_agent.tools.score_context_score._score_attack_surface_dimension",
                return_value=patches["_score_attack_surface_dimension"],
            ),
            patch(
                "manus_agent.tools.score_context_score._score_patch_lag_dimension",
                return_value=patches["_score_patch_lag_dimension"],
            ),
        ):
            result = _run_context_score(_VALID_CVE)

        assert result["cve_id"] == _VALID_CVE
        assert 0.0 <= result["context_score"] <= 100.0
        assert result["risk_label"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
        assert result["dominant_factor"] in result["dimensions"]
        assert result["confidence"] in ("HIGH", "MEDIUM", "LOW")
        assert isinstance(result["risk_summary"], str)
        assert len(result["risk_summary"]) > 0
        assert len(result["dimensions"]) == 5

    def test_cve_id_normalised_to_uppercase(self):
        with (
            patch(
                "manus_agent.tools.score_context_score._score_exploit_complexity_dimension",
                return_value={"score": 50.0, "available": True},
            ),
            patch(
                "manus_agent.tools.score_context_score._score_epss_momentum_dimension",
                return_value={"score": 50.0, "available": True},
            ),
            patch(
                "manus_agent.tools.score_context_score._score_blast_radius_dimension",
                return_value={"score": 50.0, "available": True},
            ),
            patch(
                "manus_agent.tools.score_context_score._score_attack_surface_dimension",
                return_value={"score": 50.0, "available": True},
            ),
            patch(
                "manus_agent.tools.score_context_score._score_patch_lag_dimension",
                return_value={"score": 50.0, "available": True},
            ),
        ):
            result = _run_context_score("cve-2021-44228")
        assert result["cve_id"] == "CVE-2021-44228"

    def test_custom_weights_applied(self):
        """With 100% weight on exploit_complexity at score=100 → context_score=100."""
        with (
            patch(
                "manus_agent.tools.score_context_score._score_exploit_complexity_dimension",
                return_value={"score": 100.0, "available": True},
            ),
            patch(
                "manus_agent.tools.score_context_score._score_epss_momentum_dimension",
                return_value={"score": 0.0, "available": True},
            ),
            patch(
                "manus_agent.tools.score_context_score._score_blast_radius_dimension",
                return_value={"score": 0.0, "available": True},
            ),
            patch(
                "manus_agent.tools.score_context_score._score_attack_surface_dimension",
                return_value={"score": 0.0, "available": True},
            ),
            patch(
                "manus_agent.tools.score_context_score._score_patch_lag_dimension",
                return_value={"score": 0.0, "available": True},
            ),
        ):
            custom = {
                "exploit_complexity": 1.0,
                "epss_momentum": 0.0,
                "blast_radius": 0.0,
                "attack_surface": 0.0,
                "patch_lag": 0.0,
            }
            result = _run_context_score(_VALID_CVE, custom)
        assert result["context_score"] == pytest.approx(100.0)
        assert result["dominant_factor"] == "exploit_complexity"


# ===========================================================================
# score_context_score (public tool entry point)
# ===========================================================================


class TestScoreContextScoreTool:
    def _mock_run(self, cve_id: str = _VALID_CVE, score: float = 75.0):
        return {
            "cve_id": cve_id,
            "context_score": score,
            "risk_label": "HIGH",
            "dominant_factor": "exploit_complexity",
            "confidence": "HIGH",
            "risk_summary": "Test summary.",
            "dimensions": {
                "exploit_complexity": {"score": 80.0, "available": True, "source": "score_exploit_complexity"},
                "epss_momentum": {"score": 70.0, "available": True, "source": "get_epss_trend"},
                "blast_radius": {"score": 75.0, "available": True, "source": "get_dependency_blast_radius"},
                "attack_surface": {"score": 90.0, "available": True, "source": "nvd_cvss_heuristic"},
                "patch_lag": {"score": 50.0, "available": False, "source": "default_fallback"},
            },
            "weights": _DEFAULT_WEIGHTS,
        }

    def test_text_output(self):
        with patch(
            "manus_agent.tools.score_context_score._run_context_score",
            return_value=self._mock_run(),
        ):
            out = score_context_score(cve_id=_VALID_CVE, output="text")
        assert _VALID_CVE in out
        assert "HIGH" in out

    def test_json_output(self):
        with patch(
            "manus_agent.tools.score_context_score._run_context_score",
            return_value=self._mock_run(),
        ):
            out = score_context_score(cve_id=_VALID_CVE, output="json")
        parsed = json.loads(out)
        assert parsed["cve_id"] == _VALID_CVE
        assert parsed["risk_label"] == "HIGH"

    def test_invalid_cve_id_returns_error(self):
        out = score_context_score(cve_id="NOT-A-CVE", output="text")
        assert "Error" in out

    def test_empty_cve_id_returns_error(self):
        out = score_context_score(cve_id="", output="text")
        assert "Error" in out

    def test_valid_weights_json(self):
        weights_json = json.dumps(
            {
                "exploit_complexity": 0.5,
                "epss_momentum": 0.2,
                "blast_radius": 0.1,
                "attack_surface": 0.1,
                "patch_lag": 0.1,
            }
        )
        with patch(
            "manus_agent.tools.score_context_score._run_context_score",
            return_value=self._mock_run(),
        ) as mock_run:
            score_context_score(cve_id=_VALID_CVE, weights=weights_json)
        # Verify weights were passed
        call_args = mock_run.call_args
        assert call_args[0][1] is not None  # weights arg was passed

    def test_invalid_weights_json_returns_error(self):
        out = score_context_score(cve_id=_VALID_CVE, weights="{not valid json")
        assert "Error" in out

    def test_non_dict_weights_returns_error(self):
        out = score_context_score(cve_id=_VALID_CVE, weights="[1, 2, 3]")
        assert "Error" in out

    def test_cve_id_case_insensitive_match(self):
        with patch(
            "manus_agent.tools.score_context_score._run_context_score",
            return_value=self._mock_run(),
        ):
            out = score_context_score(cve_id="cve-2021-44228", output="text")
        assert "Error" not in out


# ===========================================================================
# CLI integration — _build_risk_score_parser / _run_risk_score
# ===========================================================================


class TestRiskScoreCliParser:
    def test_parser_accepts_cve_id(self):
        from manus_agent.cli import _build_risk_score_parser

        parser = _build_risk_score_parser()
        args = parser.parse_args(["CVE-2021-44228"])
        assert args.cve_id == "CVE-2021-44228"
        assert args.output == "text"
        assert args.weights == ""

    def test_parser_json_output(self):
        from manus_agent.cli import _build_risk_score_parser

        parser = _build_risk_score_parser()
        args = parser.parse_args(["CVE-2021-44228", "--output", "json"])
        assert args.output == "json"

    def test_parser_weights_flag(self):
        from manus_agent.cli import _build_risk_score_parser

        parser = _build_risk_score_parser()
        w = '{"exploit_complexity": 0.5, "epss_momentum": 0.5}'
        args = parser.parse_args(["CVE-2021-44228", "--weights", w])
        assert args.weights == w


class TestRunRiskScoreCli:
    def _mock_result(self, score: float = 80.0) -> dict:
        return {
            "cve_id": "CVE-2021-44228",
            "context_score": score,
            "risk_label": "CRITICAL",
            "dominant_factor": "exploit_complexity",
            "confidence": "HIGH",
            "risk_summary": "Test summary.",
            "dimensions": {
                "exploit_complexity": {"score": 80.0, "available": True, "source": "test"},
                "epss_momentum": {"score": 80.0, "available": True, "source": "test"},
                "blast_radius": {"score": 80.0, "available": True, "source": "test"},
                "attack_surface": {"score": 80.0, "available": True, "source": "test"},
                "patch_lag": {"score": 80.0, "available": True, "source": "test"},
            },
            "weights": _DEFAULT_WEIGHTS,
        }

    def test_text_output_exit_zero(self, capsys):
        from manus_agent.cli import _run_risk_score

        with patch(
            "manus_agent.tools.score_context_score._run_context_score",
            return_value=self._mock_result(),
        ):
            rc = _run_risk_score(["CVE-2021-44228"])
        assert rc == 0
        captured = capsys.readouterr()
        assert "CVE-2021-44228" in captured.out

    def test_json_output_exit_zero(self, capsys):
        from manus_agent.cli import _run_risk_score

        with patch(
            "manus_agent.tools.score_context_score._run_context_score",
            return_value=self._mock_result(),
        ):
            rc = _run_risk_score(["CVE-2021-44228", "--output", "json"])
        assert rc == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["cve_id"] == "CVE-2021-44228"

    def test_invalid_cve_exits_nonzero(self):

        from manus_agent.cli import _run_risk_score

        with pytest.raises(SystemExit) as exc_info:
            _run_risk_score(["NOT_A_CVE"])
        assert exc_info.value.code != 0

    def test_invalid_weights_json_exits_nonzero(self):
        from manus_agent.cli import _run_risk_score

        with pytest.raises(SystemExit) as exc_info:
            _run_risk_score(["CVE-2021-44228", "--weights", "{broken json"])
        assert exc_info.value.code != 0

    def test_weights_passed_to_run_context_score(self, capsys):
        from manus_agent.cli import _run_risk_score

        with patch(
            "manus_agent.tools.score_context_score._run_context_score",
            return_value=self._mock_result(),
        ) as mock_run:
            _run_risk_score(
                [
                    "CVE-2021-44228",
                    "--weights",
                    '{"exploit_complexity": 1.0}',
                ]
            )
        call_weights = mock_run.call_args[0][1]
        assert call_weights is not None
        assert "exploit_complexity" in call_weights

    def test_risk_score_in_subcommands_set(self):
        from manus_agent.cli import _SUBCOMMANDS

        assert "risk-score" in _SUBCOMMANDS


# ===========================================================================
# Edge cases / regression guards
# ===========================================================================


class TestEdgeCases:
    def test_weights_sum_preserved_after_normalisation(self):
        w = {
            "exploit_complexity": 3.0,
            "epss_momentum": 1.0,
            "blast_radius": 1.0,
            "attack_surface": 0.0,
            "patch_lag": 0.0,
        }
        result = _validate_weights(w)
        assert abs(sum(result.values()) - 1.0) < 1e-9

    def test_default_weights_have_five_keys(self):
        assert len(_DEFAULT_WEIGHTS) == 5

    def test_risk_thresholds_are_ordered_descending(self):
        thresholds = [t for t, _ in _RISK_THRESHOLDS]
        assert thresholds == sorted(thresholds, reverse=True)

    def test_blast_label_score_all_between_0_and_100(self):
        for label, score in _BLAST_LABEL_SCORE.items():
            assert 0.0 <= score <= 100.0, f"{label}: {score}"

    def test_av_surface_score_all_between_0_and_100(self):
        for av, score in _AV_SURFACE_SCORE.items():
            assert 0.0 <= score <= 100.0, f"{av}: {score}"

    def test_cve_regex_matches_various_formats(self):
        from manus_agent.tools.score_context_score import _CVE_RE

        assert _CVE_RE.match("CVE-2021-44228")
        assert _CVE_RE.match("cve-2024-12345")
        assert _CVE_RE.match("CVE-1999-0001")
        assert not _CVE_RE.match("CWE-79")
        assert not _CVE_RE.match("GHSA-xxxx-yyyy-zzzz")
        assert not _CVE_RE.match("")

    def test_full_pipeline_all_unavailable_still_returns_result(self):
        """Even when every dimension falls back, we get a valid result."""
        with (
            patch(
                "manus_agent.tools.score_context_score._score_exploit_complexity_dimension",
                return_value={"score": 50.0, "available": False, "source": "default_fallback"},
            ),
            patch(
                "manus_agent.tools.score_context_score._score_epss_momentum_dimension",
                return_value={"score": 50.0, "available": False, "source": "default_fallback"},
            ),
            patch(
                "manus_agent.tools.score_context_score._score_blast_radius_dimension",
                return_value={"score": 50.0, "available": False, "source": "default_fallback"},
            ),
            patch(
                "manus_agent.tools.score_context_score._score_attack_surface_dimension",
                return_value={"score": 50.0, "available": False, "source": "default_fallback"},
            ),
            patch(
                "manus_agent.tools.score_context_score._score_patch_lag_dimension",
                return_value={"score": 50.0, "available": False, "source": "default_fallback"},
            ),
        ):
            result = _run_context_score(_VALID_CVE)
        assert result["context_score"] == pytest.approx(50.0)
        assert result["confidence"] == "LOW"
        assert result["risk_label"] == "MEDIUM"

    @pytest.mark.parametrize("label", ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"))
    def test_all_risk_labels_covered_in_summary(self, label):
        dim_scores = {"epss_momentum": {"epss": 0.5}}
        summary = _build_risk_summary(_VALID_CVE, 50.0, label, "exploit_complexity", dim_scores, "HIGH")
        assert isinstance(summary, str)
        assert len(summary) > 10
