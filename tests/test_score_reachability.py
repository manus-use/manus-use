"""
Tests for src/manus_agent/tools/score_reachability.py

All external HTTP calls are mocked — no real network I/O.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from manus_agent.tools.score_reachability import (
    _AV_SCORE,
    _CWE_HIGH,
    _CWE_LOW,
    _CWE_MEDIUM,
    _PR_SCORE,
    _UI_SCORE,
    _WEIGHTS,
    _cwe_reachability_score,
    _fetch_epss,
    _fetch_nvd_cvss,
    _fetch_poc_available,
    _reachability_level,
    _render_text,
    _run_scoring,
    score_reachability,
)

# ===========================================================================
# Helpers
# ===========================================================================

CVE_ID = "CVE-2024-3094"
YEAR = "2024"


def _nvd_response(
    av: str = "NETWORK",
    pr: str = "NONE",
    ui: str = "NONE",
    cwe_ids: list[int] | None = None,
) -> dict:
    """Build a minimal NVD API v2 response for a single CVE."""
    weaknesses = []
    if cwe_ids:
        weaknesses = [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "description": [{"lang": "en", "value": f"CWE-{c}"} for c in cwe_ids],
            }
        ]
    return {
        "resultsPerPage": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": CVE_ID,
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "vectorString": "CVSS:3.1/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseScore": 9.8,
                                    "attackVector": av,
                                    "privilegesRequired": pr,
                                    "userInteraction": ui,
                                },
                            }
                        ]
                    },
                    "weaknesses": weaknesses,
                }
            }
        ],
    }


def _epss_response(score: float = 0.85) -> dict:
    return {
        "status": "OK",
        "data": [{"cve": CVE_ID, "epss": str(score), "percentile": "0.99"}],
    }


# ===========================================================================
# Unit tests: pure scoring helpers
# ===========================================================================


class TestReachabilityLevel:
    def test_critical(self):
        assert _reachability_level(15.0) == "CRITICAL"
        assert _reachability_level(19.9) == "CRITICAL"
        assert _reachability_level(20.0) == "CRITICAL"

    def test_high(self):
        assert _reachability_level(10.0) == "HIGH"
        assert _reachability_level(14.9) == "HIGH"

    def test_medium(self):
        assert _reachability_level(6.0) == "MEDIUM"
        assert _reachability_level(9.9) == "MEDIUM"

    def test_low(self):
        assert _reachability_level(0.0) == "LOW"
        assert _reachability_level(5.9) == "LOW"


class TestCweReachabilityScore:
    def test_high_cwe(self):
        # CWE-79 (XSS) is in HIGH tier
        score, tier = _cwe_reachability_score([79])
        assert tier == "HIGH"
        assert score == 20.0

    def test_medium_cwe(self):
        # CWE-918 (SSRF) is in MEDIUM tier
        score, tier = _cwe_reachability_score([918])
        assert tier == "MEDIUM"
        assert score == 13.0

    def test_low_cwe(self):
        # CWE-208 (timing side-channel) is in LOW tier
        score, tier = _cwe_reachability_score([208])
        assert tier == "LOW"
        assert score == 6.0

    def test_unknown_cwe(self):
        # An unclassified CWE
        score, tier = _cwe_reachability_score([9999])
        assert tier == "UNKNOWN"
        assert score == 10.0

    def test_empty_cwe_list(self):
        score, tier = _cwe_reachability_score([])
        assert tier == "UNKNOWN"
        assert score == 10.0

    def test_high_dominates_medium(self):
        # HIGH tier should short-circuit over MEDIUM
        score, tier = _cwe_reachability_score([918, 79])
        assert tier == "HIGH"

    def test_medium_over_low(self):
        # MEDIUM should beat LOW
        score, tier = _cwe_reachability_score([208, 918])
        assert tier == "MEDIUM"

    def test_multiple_unknown(self):
        score, tier = _cwe_reachability_score([8888, 9999])
        assert tier == "UNKNOWN"

    def test_cwe_94_high(self):
        # CWE-94 (code injection) is in HIGH
        score, tier = _cwe_reachability_score([94])
        assert tier == "HIGH"

    def test_cwe_352_medium(self):
        # CWE-352 (CSRF)
        score, tier = _cwe_reachability_score([352])
        assert tier == "MEDIUM"


class TestWeights:
    def test_weights_sum_to_one(self):
        total = sum(_WEIGHTS.values())
        assert abs(total - 1.0) < 1e-9, f"Weights sum to {total}, expected 1.0"

    def test_all_dimensions_present(self):
        expected = {
            "attack_vector",
            "privileges_required",
            "user_interaction",
            "cwe_class",
            "poc_available",
            "epss_score",
        }
        assert set(_WEIGHTS) == expected


class TestScoreMappings:
    def test_av_network_is_max(self):
        assert _AV_SCORE["NETWORK"] == max(_AV_SCORE.values())

    def test_av_physical_is_min(self):
        assert _AV_SCORE["PHYSICAL"] == min(_AV_SCORE.values())

    def test_pr_none_is_max(self):
        assert _PR_SCORE["NONE"] == max(_PR_SCORE.values())

    def test_ui_none_is_max(self):
        assert _UI_SCORE["NONE"] == max(_UI_SCORE.values())


# ===========================================================================
# Unit tests: _fetch_nvd_cvss
# ===========================================================================


class TestFetchNvdCvss:
    def _mock_response(self, data: dict) -> MagicMock:
        m = MagicMock()
        m.raise_for_status.return_value = None
        m.json.return_value = data
        return m

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_network_none_none(self, mock_get):
        mock_get.return_value = self._mock_response(_nvd_response(av="NETWORK", pr="NONE", ui="NONE", cwe_ids=[79]))
        result = _fetch_nvd_cvss(CVE_ID)
        assert result["av"] == "NETWORK"
        assert result["pr"] == "NONE"
        assert result["ui"] == "NONE"
        assert 79 in result["cwe_ids"]

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_local_high_required(self, mock_get):
        mock_get.return_value = self._mock_response(_nvd_response(av="LOCAL", pr="HIGH", ui="REQUIRED", cwe_ids=[208]))
        result = _fetch_nvd_cvss(CVE_ID)
        assert result["av"] == "LOCAL"
        assert result["pr"] == "HIGH"
        assert result["ui"] == "REQUIRED"

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_empty_vulnerabilities(self, mock_get):
        mock_get.return_value = self._mock_response({"resultsPerPage": 0, "vulnerabilities": []})
        result = _fetch_nvd_cvss(CVE_ID)
        assert result["av"] is None
        assert result["pr"] is None
        assert result["ui"] is None
        assert result["cwe_ids"] == []

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_multiple_cwes_extracted(self, mock_get):
        mock_get.return_value = self._mock_response(_nvd_response(cwe_ids=[79, 89, 918]))
        result = _fetch_nvd_cvss(CVE_ID)
        assert set(result["cwe_ids"]) == {79, 89, 918}

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_cvss_v2_fallback(self, mock_get):
        """When only cvssMetricV2 is present, we still parse AV and authentication."""
        nvd_data = {
            "resultsPerPage": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": CVE_ID,
                        "metrics": {
                            "cvssMetricV2": [
                                {
                                    "source": "nvd@nist.gov",
                                    "cvssData": {
                                        "accessVector": "NETWORK",
                                        "authentication": "NONE",
                                    },
                                }
                            ]
                        },
                        "weaknesses": [],
                    }
                }
            ],
        }
        mock_get.return_value = self._mock_response(nvd_data)
        result = _fetch_nvd_cvss(CVE_ID)
        assert result["av"] == "NETWORK"
        assert result["pr"] == "NONE"

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_http_error_propagates(self, mock_get):
        import requests as _req

        mock_get.side_effect = _req.RequestException("timeout")
        with pytest.raises(_req.RequestException):
            _fetch_nvd_cvss(CVE_ID)


# ===========================================================================
# Unit tests: _fetch_poc_available
# ===========================================================================


class TestFetchPocAvailable:
    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_poc_found_with_github_url(self, mock_get):
        m = MagicMock()
        m.status_code = 200
        m.text = "## PoC\nhttps://github.com/user/repo-exploit\n"
        mock_get.return_value = m
        found, reason = _fetch_poc_available(CVE_ID)
        assert found is True
        assert "Trickest" in reason

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_poc_found_with_poc_section(self, mock_get):
        m = MagicMock()
        m.status_code = 200
        m.text = "# CVE-2024-3094\n## PoC References\nhttps://github.com/foo/bar\n"
        mock_get.return_value = m
        found, reason = _fetch_poc_available(CVE_ID)
        assert found is True

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_no_poc_page_exists_but_empty(self, mock_get):
        m = MagicMock()
        m.status_code = 200
        m.text = "# CVE-2024-3094\nNo public exploits.\n"
        mock_get.return_value = m
        found, reason = _fetch_poc_available(CVE_ID)
        assert found is False
        assert "no PoC" in reason

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_404_returns_false(self, mock_get):
        m = MagicMock()
        m.status_code = 404
        mock_get.return_value = m
        found, reason = _fetch_poc_available(CVE_ID)
        assert found is False
        assert "no Trickest entry" in reason

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_http_error_degrades_gracefully(self, mock_get):
        import requests as _req

        mock_get.side_effect = _req.RequestException("connection refused")
        found, reason = _fetch_poc_available(CVE_ID)
        assert found is False
        assert "failed" in reason.lower()

    def test_invalid_cve_returns_false(self):
        found, reason = _fetch_poc_available("NOT-A-CVE")
        assert found is False
        assert "invalid" in reason.lower()


# ===========================================================================
# Unit tests: _fetch_epss
# ===========================================================================


class TestFetchEpss:
    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_high_epss(self, mock_get):
        m = MagicMock()
        m.raise_for_status.return_value = None
        m.json.return_value = _epss_response(0.85)
        mock_get.return_value = m
        score, reason = _fetch_epss(CVE_ID)
        assert score == pytest.approx(0.85, abs=1e-4)
        assert "EPSS" in reason

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_low_epss(self, mock_get):
        m = MagicMock()
        m.raise_for_status.return_value = None
        m.json.return_value = _epss_response(0.01)
        mock_get.return_value = m
        score, reason = _fetch_epss(CVE_ID)
        assert score == pytest.approx(0.01, abs=1e-4)

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_empty_data_returns_none(self, mock_get):
        m = MagicMock()
        m.raise_for_status.return_value = None
        m.json.return_value = {"status": "OK", "data": []}
        mock_get.return_value = m
        score, reason = _fetch_epss(CVE_ID)
        assert score is None
        assert "no EPSS" in reason

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_network_failure_returns_none(self, mock_get):
        import requests as _req

        mock_get.side_effect = _req.RequestException("timeout")
        score, reason = _fetch_epss(CVE_ID)
        assert score is None
        assert "failed" in reason.lower()


# ===========================================================================
# Integration tests: _run_scoring (all HTTP mocked)
# ===========================================================================


class TestRunScoring:
    """Tests for the full scoring pipeline with all HTTP calls mocked."""

    def _setup_mocks(
        self,
        mock_get: MagicMock,
        av: str = "NETWORK",
        pr: str = "NONE",
        ui: str = "NONE",
        cwe_ids: list[int] | None = None,
        epss: float = 0.75,
        poc_status: int = 200,
        poc_body: str = "## PoC\nhttps://github.com/foo/bar\n",
    ) -> None:
        """Configure side_effect so each URL gets the right mock response."""

        def side_effect(url, **kwargs):
            m = MagicMock()
            if "nvd.nist.gov" in url or "services.nvd" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _nvd_response(av=av, pr=pr, ui=ui, cwe_ids=cwe_ids or [79])
            elif "first.org" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _epss_response(epss)
            else:
                # Trickest
                m.status_code = poc_status
                m.text = poc_body
            return m

        mock_get.side_effect = side_effect

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_critical_scenario(self, mock_get):
        """NETWORK+NONE+NONE+HIGH_CWE+PoC+high EPSS => CRITICAL."""
        self._setup_mocks(
            mock_get,
            av="NETWORK",
            pr="NONE",
            ui="NONE",
            cwe_ids=[79],
            epss=0.90,
            poc_status=200,
            poc_body="## PoC\nhttps://github.com/user/cve-poc\n",
        )
        result = _run_scoring(CVE_ID)
        assert result["reachability_level"] == "CRITICAL"
        assert result["reachability_score"] >= 15.0
        assert "error" not in result

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_low_scenario(self, mock_get):
        """PHYSICAL+HIGH+REQUIRED+LOW_CWE+no_PoC+low_EPSS => LOW."""
        self._setup_mocks(
            mock_get,
            av="PHYSICAL",
            pr="HIGH",
            ui="REQUIRED",
            cwe_ids=[208],
            epss=0.001,
            poc_status=404,
        )
        result = _run_scoring(CVE_ID)
        assert result["reachability_level"] == "LOW"
        assert result["reachability_score"] < 6.0

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_result_structure(self, mock_get):
        """Result always has all required keys."""
        self._setup_mocks(mock_get)
        result = _run_scoring(CVE_ID)
        assert "reachability_score" in result
        assert "reachability_level" in result
        assert "dimension_scores" in result
        assert "dimension_details" in result
        assert "summary_reasons" in result
        assert "warnings" in result
        assert "scoring_weights" in result
        assert set(result["dimension_scores"]) == set(_WEIGHTS)

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_score_in_range(self, mock_get):
        """Score is always between 0 and 20."""
        self._setup_mocks(mock_get)
        result = _run_scoring(CVE_ID)
        assert 0.0 <= result["reachability_score"] <= 20.0

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_epss_unavailable_uses_neutral(self, mock_get):
        """When EPSS fails, the tool falls back to a neutral 10/20 value."""
        import requests as _req

        call_count = 0

        def side_effect(url, **kwargs):
            nonlocal call_count
            call_count += 1
            m = MagicMock()
            if "nvd.nist.gov" in url or "services.nvd" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _nvd_response()
            elif "first.org" in url:
                raise _req.RequestException("EPSS down")
            else:
                m.status_code = 404
            return m

        mock_get.side_effect = side_effect
        result = _run_scoring(CVE_ID)
        assert "error" not in result
        assert any("EPSS" in w for w in result.get("warnings", []))

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_nvd_failure_returns_error(self, mock_get):
        """When NVD is unavailable, _run_scoring returns error dict."""
        import requests as _req

        mock_get.side_effect = _req.RequestException("NVD down")
        result = _run_scoring(CVE_ID)
        assert "error" in result
        assert "NVD" in result["error"]

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_poc_failure_degrades_gracefully(self, mock_get):
        """When Trickest request fails, poc_available is treated as absent (0)."""
        import requests as _req

        def side_effect(url, **kwargs):
            m = MagicMock()
            if "nvd.nist.gov" in url or "services.nvd" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _nvd_response()
            elif "first.org" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _epss_response(0.5)
            else:
                raise _req.RequestException("Trickest down")
            return m

        mock_get.side_effect = side_effect
        result = _run_scoring(CVE_ID)
        assert "error" not in result
        assert result["dimension_scores"]["poc_available"] == 0.0

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_weighted_sum_matches_manual_calc(self, mock_get):
        """Verify the final score equals the manually computed weighted sum."""
        self._setup_mocks(
            mock_get,
            av="NETWORK",  # 20
            pr="NONE",  # 20
            ui="NONE",  # 20
            cwe_ids=[79],  # HIGH → 20
            epss=1.0,  # 20
            poc_status=200,
            poc_body="## PoC\nhttps://github.com/x/y\n",
        )
        result = _run_scoring(CVE_ID)
        # With all max scores, weighted sum = 20 * (0.25 + 0.15 + 0.10 + 0.20 + 0.20 + 0.10)
        expected = 20.0 * 1.0
        assert result["reachability_score"] == pytest.approx(expected, abs=0.01)

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_unknown_av_uses_neutral(self, mock_get):
        """An unrecognised attack vector falls back to neutral 10/20."""
        nvd_data = {
            "resultsPerPage": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": CVE_ID,
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "source": "nvd@nist.gov",
                                    "cvssData": {
                                        "attackVector": "UNKNOWN_FUTURE",
                                        "privilegesRequired": "NONE",
                                        "userInteraction": "NONE",
                                    },
                                }
                            ]
                        },
                        "weaknesses": [],
                    }
                }
            ],
        }

        def side_effect(url, **kwargs):
            m = MagicMock()
            if "nvd.nist.gov" in url or "services.nvd" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = nvd_data
            elif "first.org" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _epss_response(0.5)
            else:
                m.status_code = 404
            return m

        mock_get.side_effect = side_effect
        result = _run_scoring(CVE_ID)
        assert "error" not in result
        # Neutral AV score = 10.0
        assert result["dimension_scores"]["attack_vector"] == pytest.approx(10.0)

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_dimension_details_present_for_all_dims(self, mock_get):
        self._setup_mocks(mock_get)
        result = _run_scoring(CVE_ID)
        for dim in _WEIGHTS:
            assert dim in result["dimension_details"], f"Missing detail for {dim}"


# ===========================================================================
# _render_text
# ===========================================================================


class TestRenderText:
    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_renders_without_error(self, mock_get):
        m_nvd = MagicMock()
        m_nvd.raise_for_status.return_value = None
        m_nvd.json.return_value = _nvd_response(cwe_ids=[79])
        m_epss = MagicMock()
        m_epss.raise_for_status.return_value = None
        m_epss.json.return_value = _epss_response(0.8)
        m_trickest = MagicMock()
        m_trickest.status_code = 404

        def side_effect(url, **kwargs):
            if "nvd.nist.gov" in url or "services.nvd" in url:
                return m_nvd
            if "first.org" in url:
                return m_epss
            return m_trickest

        mock_get.side_effect = side_effect
        result = _run_scoring(CVE_ID)
        text = _render_text(result)
        assert CVE_ID in text
        assert "Score:" in text
        assert "Dimension breakdown:" in text

    def test_renders_error_result(self):
        error_result = {"cve_id": CVE_ID, "error": "NVD down"}
        text = _render_text(error_result)
        assert "ERROR" in text
        assert "NVD down" in text


# ===========================================================================
# score_reachability (Strands @tool entry point)
# ===========================================================================


class TestScoreReachabilityTool:
    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_valid_cve_returns_report(self, mock_get):
        def side_effect(url, **kwargs):
            m = MagicMock()
            if "nvd.nist.gov" in url or "services.nvd" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _nvd_response(cwe_ids=[79])
            elif "first.org" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _epss_response(0.7)
            else:
                m.status_code = 200
                m.text = "## PoC\nhttps://github.com/user/poc\n"
            return m

        mock_get.side_effect = side_effect
        result = score_reachability(cve_id=CVE_ID)
        assert "error" not in result
        assert "report" in result
        assert "reachability_score" in result
        assert "reachability_level" in result

    def test_invalid_cve_format(self):
        result = score_reachability(cve_id="not-a-cve")
        assert "error" in result

    def test_invalid_cve_too_short(self):
        result = score_reachability(cve_id="CVE-123")
        assert "error" in result

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_report_field_is_string(self, mock_get):
        def side_effect(url, **kwargs):
            m = MagicMock()
            if "nvd.nist.gov" in url or "services.nvd" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _nvd_response()
            elif "first.org" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _epss_response(0.2)
            else:
                m.status_code = 404
            return m

        mock_get.side_effect = side_effect
        result = score_reachability(cve_id=CVE_ID)
        assert isinstance(result.get("report"), str)

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_nvd_failure_is_in_result(self, mock_get):
        import requests as _req

        mock_get.side_effect = _req.RequestException("timeout")
        result = score_reachability(cve_id=CVE_ID)
        assert "error" in result

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_result_is_json_serialisable(self, mock_get):
        def side_effect(url, **kwargs):
            m = MagicMock()
            if "nvd.nist.gov" in url or "services.nvd" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _nvd_response()
            elif "first.org" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _epss_response(0.5)
            else:
                m.status_code = 404
            return m

        mock_get.side_effect = side_effect
        result = score_reachability(cve_id=CVE_ID)
        # Should not raise
        serialised = json.dumps(result)
        assert CVE_ID in serialised

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_summary_reasons_is_list(self, mock_get):
        def side_effect(url, **kwargs):
            m = MagicMock()
            if "nvd.nist.gov" in url or "services.nvd" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _nvd_response()
            elif "first.org" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _epss_response(0.5)
            else:
                m.status_code = 404
            return m

        mock_get.side_effect = side_effect
        result = score_reachability(cve_id=CVE_ID)
        assert isinstance(result.get("summary_reasons"), list)


# ===========================================================================
# CLI tests
# ===========================================================================


class TestCli:
    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_cli_text_output(self, mock_get):
        """Smoke-test the _run_reachability CLI with text output."""
        from manus_agent.cli import _run_reachability

        def side_effect(url, **kwargs):
            m = MagicMock()
            if "nvd.nist.gov" in url or "services.nvd" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _nvd_response(cwe_ids=[79])
            elif "first.org" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _epss_response(0.75)
            else:
                m.status_code = 200
                m.text = "## PoC\nhttps://github.com/user/poc\n"
            return m

        mock_get.side_effect = side_effect
        rc = _run_reachability([CVE_ID])
        assert rc == 0

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_cli_json_output(self, mock_get, capsys):
        """JSON output goes to stdout and is parseable."""
        from manus_agent.cli import _run_reachability

        def side_effect(url, **kwargs):
            m = MagicMock()
            if "nvd.nist.gov" in url or "services.nvd" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _nvd_response(cwe_ids=[79])
            elif "first.org" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _epss_response(0.75)
            else:
                m.status_code = 404
            return m

        mock_get.side_effect = side_effect
        rc = _run_reachability([CVE_ID, "--output", "json"])
        assert rc == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "reachability_score" in data

    def test_cli_invalid_cve(self):
        """Invalid CVE ID should return non-zero exit code."""
        from manus_agent.cli import _run_reachability

        rc = _run_reachability(["NOT-A-CVE"])
        assert rc == 1

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_cli_save_to_file(self, mock_get, tmp_path):
        """--save writes the report to disk."""
        from manus_agent.cli import _run_reachability

        def side_effect(url, **kwargs):
            m = MagicMock()
            if "nvd.nist.gov" in url or "services.nvd" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _nvd_response()
            elif "first.org" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _epss_response(0.5)
            else:
                m.status_code = 404
            return m

        mock_get.side_effect = side_effect
        outfile = tmp_path / "report.txt"
        rc = _run_reachability([CVE_ID, "--save", str(outfile)])
        assert rc == 0
        assert outfile.exists()
        content = outfile.read_text()
        assert CVE_ID in content

    @patch("manus_agent.tools.score_reachability.requests.get")
    def test_cli_save_json_to_file(self, mock_get, tmp_path):
        """--output json --save writes JSON to disk."""
        from manus_agent.cli import _run_reachability

        def side_effect(url, **kwargs):
            m = MagicMock()
            if "nvd.nist.gov" in url or "services.nvd" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _nvd_response()
            elif "first.org" in url:
                m.raise_for_status.return_value = None
                m.json.return_value = _epss_response(0.5)
            else:
                m.status_code = 404
            return m

        mock_get.side_effect = side_effect
        outfile = tmp_path / "report.json"
        rc = _run_reachability([CVE_ID, "--output", "json", "--save", str(outfile)])
        assert rc == 0
        assert outfile.exists()
        data = json.loads(outfile.read_text())
        assert "reachability_score" in data


# ===========================================================================
# CWE tier coverage — verify no overlap
# ===========================================================================


class TestCweTierCoverage:
    def test_no_overlap_between_high_and_medium(self):
        overlap = _CWE_HIGH & _CWE_MEDIUM
        assert not overlap, f"CWEs in both HIGH and MEDIUM: {overlap}"

    def test_no_overlap_between_high_and_low(self):
        overlap = _CWE_HIGH & _CWE_LOW
        assert not overlap, f"CWEs in both HIGH and LOW: {overlap}"

    def test_no_overlap_between_medium_and_low(self):
        overlap = _CWE_MEDIUM & _CWE_LOW
        assert not overlap, f"CWEs in both MEDIUM and LOW: {overlap}"

    def test_all_tiers_nonempty(self):
        assert len(_CWE_HIGH) > 0
        assert len(_CWE_MEDIUM) > 0
        assert len(_CWE_LOW) > 0
