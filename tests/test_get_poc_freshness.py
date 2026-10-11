"""Comprehensive test suite for get_poc_freshness module.

All HTTP calls are mocked — no real network requests.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, mock_open, patch

import pytest

# ---------------------------------------------------------------------------
# Module under test
# ---------------------------------------------------------------------------
from manus_agent.tools.get_poc_freshness import (
    _CVE_RE,
    _FRESHNESS_HALF_LIFE_DAYS,
    _days_ago,
    _decay_score,
    _fetch_epss_signals,
    _fetch_exploitdb_signals,
    _fetch_github_signals,
    _fetch_nvd_signals,
    _parse_date,
    assess_poc_freshness,
    compute_freshness,
    get_poc_freshness,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iso(days_ago: float = 0) -> str:
    """Return an ISO timestamp for *days_ago* days in the past."""
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _date(days_ago: float = 0) -> str:
    """Return a YYYY-MM-DD string for *days_ago* days in the past."""
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.strftime("%Y-%m-%d")


def _github_item(
    name: str = "poc-repo",
    pushed_days_ago: float = 5,
    stars: int = 10,
    desc: str = "PoC",
) -> dict:
    return {
        "full_name": f"user/{name}",
        "html_url": f"https://github.com/user/{name}",
        "pushed_at": _iso(pushed_days_ago),
        "stargazers_count": stars,
        "description": desc,
        "owner": {"login": "user"},
    }


# ===================================================================
# _parse_date
# ===================================================================


class TestParseDate:
    def test_none_input(self):
        assert _parse_date(None) is None

    def test_empty_string(self):
        assert _parse_date("") is None

    def test_iso_with_z(self):
        dt = _parse_date("2024-06-15T10:30:00Z")
        assert dt is not None
        assert dt.year == 2024
        assert dt.month == 6

    def test_iso_without_z(self):
        dt = _parse_date("2024-06-15T10:30:00")
        assert dt is not None
        assert dt.year == 2024

    def test_date_only(self):
        dt = _parse_date("2024-06-15")
        assert dt is not None
        assert dt.day == 15

    def test_invalid_format(self):
        assert _parse_date("not-a-date") is None

    def test_extra_chars_truncated(self):
        dt = _parse_date("2024-06-15T10:30:00.123456Z")
        assert dt is not None


# ===================================================================
# _days_ago
# ===================================================================


class TestDaysAgo:
    def test_none(self):
        assert _days_ago(None) is None

    def test_now(self):
        now = datetime.now(timezone.utc)
        d = _days_ago(now)
        assert d is not None
        assert d < 0.01  # less than ~15 minutes

    def test_one_week_ago(self):
        week_ago = datetime.now(timezone.utc) - timedelta(days=7)
        d = _days_ago(week_ago)
        assert d is not None
        assert 6.9 < d < 7.1


# ===================================================================
# _decay_score
# ===================================================================


class TestDecayScore:
    def test_zero_days(self):
        assert _decay_score(0.0, 40.0) == 40.0

    def test_half_life(self):
        score = _decay_score(_FRESHNESS_HALF_LIFE_DAYS, 40.0)
        assert abs(score - 20.0) < 0.1  # should be ~half

    def test_none_days(self):
        assert _decay_score(None, 40.0) == 0.0

    def test_very_old(self):
        score = _decay_score(365 * 5, 40.0)
        assert score < 0.01

    def test_negative_clamped(self):
        # Negative days should be clamped to 0
        assert _decay_score(-10.0, 40.0) == 40.0


# ===================================================================
# _CVE_RE
# ===================================================================


class TestCveRegex:
    def test_valid(self):
        assert _CVE_RE.match("CVE-2024-3094")

    def test_valid_long(self):
        assert _CVE_RE.match("CVE-2024-123456")

    def test_lowercase(self):
        assert _CVE_RE.match("cve-2024-3094")

    def test_invalid_no_prefix(self):
        assert not _CVE_RE.match("2024-3094")

    def test_invalid_garbage(self):
        assert not _CVE_RE.match("hello")


# ===================================================================
# _fetch_github_signals
# ===================================================================


class TestFetchGithubSignals:
    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_success_with_repos(self, mock_get):
        mock_get.return_value = {
            "items": [
                _github_item("poc1", pushed_days_ago=2, stars=20),
                _github_item("poc2", pushed_days_ago=60, stars=3),
            ]
        }
        result = _fetch_github_signals("CVE-2024-1234")
        assert result["status"] == "ok"
        assert result["repo_count"] == 2
        assert result["most_recent_push_days_ago"] is not None
        assert result["most_recent_push_days_ago"] < 5
        assert result["hot_repos"] >= 1  # poc1 is hot (recent + stars)
        assert result["total_stars"] == 23

    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_empty_results(self, mock_get):
        mock_get.return_value = {"items": []}
        result = _fetch_github_signals("CVE-2024-9999")
        assert result["status"] == "ok"
        assert result["repo_count"] == 0
        assert result["most_recent_push"] is None
        assert result["hot_repos"] == 0

    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_api_error(self, mock_get):
        mock_get.side_effect = Exception("rate limited")
        result = _fetch_github_signals("CVE-2024-1234")
        assert result["status"] == "error"
        assert "rate limited" in result["error"]

    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_github_token_used(self, mock_get):
        mock_get.return_value = {"items": []}
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_test123"}):
            _fetch_github_signals("CVE-2024-1234")
        call_args = mock_get.call_args
        assert "Authorization" in call_args[1].get("headers", {}) or (
            len(call_args[0]) > 1 and "Authorization" in (call_args[0][1] or {})
        )

    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_no_hot_repos_when_low_stars(self, mock_get):
        mock_get.return_value = {
            "items": [
                _github_item("poc1", pushed_days_ago=2, stars=1),  # recent but low stars
            ]
        }
        result = _fetch_github_signals("CVE-2024-1234")
        assert result["hot_repos"] == 0

    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_no_hot_repos_when_old(self, mock_get):
        mock_get.return_value = {
            "items": [
                _github_item("poc1", pushed_days_ago=200, stars=100),  # old but many stars
            ]
        }
        result = _fetch_github_signals("CVE-2024-1234")
        assert result["hot_repos"] == 0

    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_repo_details_capped(self, mock_get):
        mock_get.return_value = {"items": [_github_item(f"poc{i}") for i in range(10)]}
        result = _fetch_github_signals("CVE-2024-1234")
        assert len(result["repos"]) == 10


# ===================================================================
# _fetch_exploitdb_signals
# ===================================================================


class TestFetchExploitdbSignals:
    def _csv_content(self, rows: list[dict]) -> str:
        header = "id,description,date_published,codes,type,platform,author\n"
        lines = []
        for r in rows:
            lines.append(
                f"{r.get('id', '')},{r.get('description', '')},{r.get('date_published', '')},{r.get('codes', '')},{r.get('type', '')},{r.get('platform', '')},{r.get('author', '')}"
            )
        return header + "\n".join(lines)

    @patch("manus_agent.tools.get_poc_freshness._ensure_exploitdb_cache")
    def test_cache_unavailable(self, mock_cache):
        mock_cache.return_value = None
        result = _fetch_exploitdb_signals("CVE-2024-1234")
        assert result["status"] == "error"

    @patch("manus_agent.tools.get_poc_freshness._ensure_exploitdb_cache")
    def test_no_matches(self, mock_cache, tmp_path):
        csv_file = tmp_path / "exploitdb.csv"
        csv_file.write_text(
            self._csv_content(
                [{"id": "1", "description": "test", "date_published": "2024-01-01", "codes": "CVE-2023-9999"}]
            )
        )
        mock_cache.return_value = str(csv_file)
        result = _fetch_exploitdb_signals("CVE-2024-1234")
        assert result["status"] == "ok"
        assert result["entry_count"] == 0

    @patch("manus_agent.tools.get_poc_freshness._ensure_exploitdb_cache")
    def test_matching_entries(self, mock_cache, tmp_path):
        csv_file = tmp_path / "exploitdb.csv"
        csv_file.write_text(
            self._csv_content(
                [
                    {
                        "id": "12345",
                        "description": "Buffer overflow",
                        "date_published": _date(10),
                        "codes": "CVE-2024-1234;CVE-2024-5678",
                    },
                    {
                        "id": "12346",
                        "description": "RCE",
                        "date_published": _date(30),
                        "codes": "CVE-2024-1234",
                    },
                ]
            )
        )
        mock_cache.return_value = str(csv_file)
        result = _fetch_exploitdb_signals("CVE-2024-1234")
        assert result["status"] == "ok"
        assert result["entry_count"] == 2
        assert result["most_recent_days_ago"] is not None
        assert result["most_recent_days_ago"] < 15

    @patch("manus_agent.tools.get_poc_freshness._ensure_exploitdb_cache")
    def test_entries_capped_at_10(self, mock_cache, tmp_path):
        csv_file = tmp_path / "exploitdb.csv"
        rows = [
            {"id": str(i), "description": f"exploit {i}", "date_published": "2024-01-01", "codes": "CVE-2024-1234"}
            for i in range(15)
        ]
        csv_file.write_text(self._csv_content(rows))
        mock_cache.return_value = str(csv_file)
        result = _fetch_exploitdb_signals("CVE-2024-1234")
        assert len(result["entries"]) == 10  # capped

    @patch("manus_agent.tools.get_poc_freshness._ensure_exploitdb_cache")
    def test_case_insensitive_match(self, mock_cache, tmp_path):
        csv_file = tmp_path / "exploitdb.csv"
        csv_file.write_text(
            self._csv_content(
                [{"id": "1", "description": "test", "date_published": "2024-01-01", "codes": "cve-2024-1234"}]
            )
        )
        mock_cache.return_value = str(csv_file)
        result = _fetch_exploitdb_signals("CVE-2024-1234")
        assert result["entry_count"] == 1


# ===================================================================
# _fetch_nvd_signals
# ===================================================================


class TestFetchNvdSignals:
    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_success_with_poc_refs(self, mock_get):
        mock_get.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "published": _iso(90),
                        "lastModified": _iso(5),
                        "references": [
                            {"url": "https://github.com/poc", "tags": ["Exploit"]},
                            {"url": "https://example.com/advisory", "tags": ["Vendor Advisory"]},
                            {"url": "https://exploit-db.com/1", "tags": ["Third Party Advisory", "Proof of Concept"]},
                        ],
                    }
                }
            ]
        }
        result = _fetch_nvd_signals("CVE-2024-1234")
        assert result["status"] == "ok"
        assert result["has_exploit_refs"] is True
        assert result["has_poc_refs"] is True
        assert result["exploit_ref_count"] == 1
        assert result["poc_ref_count"] == 1

    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_no_vulnerabilities(self, mock_get):
        mock_get.return_value = {"vulnerabilities": []}
        result = _fetch_nvd_signals("CVE-2024-9999")
        assert result["status"] == "ok"
        assert result["has_poc_refs"] is False
        assert result["has_exploit_refs"] is False

    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_api_error(self, mock_get):
        mock_get.side_effect = Exception("timeout")
        result = _fetch_nvd_signals("CVE-2024-1234")
        assert result["status"] == "error"

    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_nvd_api_key_used(self, mock_get):
        mock_get.return_value = {"vulnerabilities": []}
        with patch.dict(os.environ, {"NVD_API_KEY": "test-key"}):
            _fetch_nvd_signals("CVE-2024-1234")
        call_args = mock_get.call_args
        headers = call_args[1].get("headers", {}) if len(call_args) > 1 else {}
        if not headers and len(call_args[0]) > 1:
            headers = call_args[0][1] or {}
        assert "apiKey" in headers

    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_last_modified_days_ago(self, mock_get):
        mock_get.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "published": _iso(365),
                        "lastModified": _iso(3),
                        "references": [],
                    }
                }
            ]
        }
        result = _fetch_nvd_signals("CVE-2024-1234")
        assert result["last_modified_days_ago"] is not None
        assert result["last_modified_days_ago"] < 5


# ===================================================================
# _fetch_epss_signals
# ===================================================================


class TestFetchEpssSignals:
    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_flat_format(self, mock_get):
        # Flat entries with date and epss
        now_date = _date(0)
        old_date = _date(45)
        mock_get.return_value = {
            "data": [
                {"date": old_date, "epss": "0.05", "percentile": "0.70"},
                {"date": now_date, "epss": "0.15", "percentile": "0.85"},
            ]
        }
        result = _fetch_epss_signals("CVE-2024-1234")
        assert result["status"] == "ok"
        assert result["current_score"] == 0.15
        assert result["momentum"] > 0

    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_nested_format(self, mock_get):
        now_date = _date(0)
        old_date = _date(45)
        mock_get.return_value = {
            "data": [
                {
                    "cve": "CVE-2024-1234",
                    "epss": "0.20",
                    "percentile": "0.90",
                    "time-series": [
                        {"date": old_date, "epss": "0.10"},
                        {"date": now_date, "epss": "0.20"},
                    ],
                }
            ]
        }
        result = _fetch_epss_signals("CVE-2024-1234")
        assert result["status"] == "ok"
        assert result["current_score"] == 0.20
        assert result["momentum"] > 0

    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_empty_data(self, mock_get):
        mock_get.return_value = {"data": []}
        result = _fetch_epss_signals("CVE-2024-9999")
        assert result["status"] == "ok"
        assert result["current_score"] is None
        assert result["momentum"] == 0.0

    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_api_error(self, mock_get):
        mock_get.side_effect = Exception("connection error")
        result = _fetch_epss_signals("CVE-2024-1234")
        assert result["status"] == "error"

    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_negative_momentum(self, mock_get):
        now_date = _date(0)
        old_date = _date(45)
        mock_get.return_value = {
            "data": [
                {"date": old_date, "epss": "0.30"},
                {"date": now_date, "epss": "0.10"},
            ]
        }
        result = _fetch_epss_signals("CVE-2024-1234")
        assert result["momentum"] < 0

    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_no_30d_ago_entry(self, mock_get):
        """When all entries are very recent, score_30d_ago is None."""
        recent = _date(2)
        mock_get.return_value = {
            "data": [
                {"date": recent, "epss": "0.50"},
            ]
        }
        result = _fetch_epss_signals("CVE-2024-1234")
        assert result["score_30d_ago"] is None
        assert result["momentum"] == 0.0


# ===================================================================
# compute_freshness
# ===================================================================


class TestComputeFreshness:
    def test_all_zeros(self):
        result = compute_freshness(
            github={},
            exploitdb={},
            nvd={},
            epss={},
        )
        assert result["freshness_score"] == 0.0
        assert result["classification"] == "none"

    def test_very_recent_activity(self):
        result = compute_freshness(
            github={"most_recent_push_days_ago": 1, "hot_repos": 3, "total_stars": 100},
            exploitdb={"most_recent_days_ago": 2},
            nvd={"last_modified_days_ago": 3},
            epss={"momentum": 0.15},
        )
        assert result["freshness_score"] >= 75
        assert result["classification"] == "critical"

    def test_moderate_activity(self):
        result = compute_freshness(
            github={"most_recent_push_days_ago": 45, "hot_repos": 0, "total_stars": 5},
            exploitdb={},
            nvd={"last_modified_days_ago": 60},
            epss={"momentum": 0.02},
        )
        assert 10 < result["freshness_score"] < 75
        assert result["classification"] in ("moderate", "low")

    def test_old_activity(self):
        result = compute_freshness(
            github={"most_recent_push_days_ago": 500},
            exploitdb={"most_recent_days_ago": 400},
            nvd={},
            epss={},
        )
        assert result["freshness_score"] < 10
        assert result["classification"] in ("low", "none")

    def test_breadth_scoring(self):
        """Multiple recent sources increase breadth score."""
        # Only one source recent
        r1 = compute_freshness(
            github={"most_recent_push_days_ago": 10, "hot_repos": 0, "total_stars": 0},
            exploitdb={},
            nvd={},
            epss={},
        )
        # Three sources recent
        r2 = compute_freshness(
            github={"most_recent_push_days_ago": 10, "hot_repos": 0, "total_stars": 0},
            exploitdb={"most_recent_days_ago": 10},
            nvd={"last_modified_days_ago": 10},
            epss={},
        )
        assert r2["breakdown"]["breadth_points"] > r1["breakdown"]["breadth_points"]

    def test_star_velocity_bonus(self):
        """Hot repos increase star velocity score."""
        r_cold = compute_freshness(
            github={"most_recent_push_days_ago": 10, "hot_repos": 0, "total_stars": 0},
            exploitdb={},
            nvd={},
            epss={},
        )
        r_hot = compute_freshness(
            github={"most_recent_push_days_ago": 10, "hot_repos": 3, "total_stars": 100},
            exploitdb={},
            nvd={},
            epss={},
        )
        assert r_hot["breakdown"]["star_velocity_points"] > r_cold["breakdown"]["star_velocity_points"]

    def test_high_total_stars_bonus(self):
        """High total stars give a bonus even without hot repos."""
        result = compute_freshness(
            github={"most_recent_push_days_ago": 200, "hot_repos": 0, "total_stars": 100},
            exploitdb={},
            nvd={},
            epss={},
        )
        assert result["breakdown"]["star_velocity_points"] >= 5

    def test_epss_momentum_scoring(self):
        """EPSS momentum increases score."""
        r_flat = compute_freshness(github={}, exploitdb={}, nvd={}, epss={"momentum": 0.0})
        r_spike = compute_freshness(github={}, exploitdb={}, nvd={}, epss={"momentum": 0.10})
        assert r_spike["breakdown"]["epss_momentum_points"] > r_flat["breakdown"]["epss_momentum_points"]

    def test_score_capped_at_100(self):
        """Score never exceeds 100."""
        result = compute_freshness(
            github={"most_recent_push_days_ago": 0, "hot_repos": 10, "total_stars": 1000},
            exploitdb={"most_recent_days_ago": 0},
            nvd={"last_modified_days_ago": 0},
            epss={"momentum": 0.50},
        )
        assert result["freshness_score"] <= 100.0

    def test_classification_boundaries(self):
        """Verify classification thresholds."""
        assert (
            compute_freshness(
                github={"most_recent_push_days_ago": 0, "hot_repos": 5, "total_stars": 200},
                exploitdb={"most_recent_days_ago": 0},
                nvd={"last_modified_days_ago": 0},
                epss={"momentum": 0.2},
            )["classification"]
            == "critical"
        )

    def test_recent_sources_dict(self):
        """recent_sources tracks which signals are active."""
        result = compute_freshness(
            github={"most_recent_push_days_ago": 10},
            exploitdb={},
            nvd={"last_modified_days_ago": 200},
            epss={"momentum": 0.05},
        )
        assert result["recent_sources"]["github"] is True
        assert result["recent_sources"]["exploitdb"] is False
        assert result["recent_sources"]["nvd"] is False
        assert result["recent_sources"]["epss"] is True

    def test_most_recent_picks_minimum(self):
        """most_recent_activity_days_ago picks the smallest value."""
        result = compute_freshness(
            github={"most_recent_push_days_ago": 50},
            exploitdb={"most_recent_days_ago": 10},
            nvd={"last_modified_days_ago": 200},
            epss={},
        )
        assert result["most_recent_activity_days_ago"] == 10


# ===================================================================
# assess_poc_freshness (integration of all signals)
# ===================================================================


class TestAssessPocFreshness:
    @patch("manus_agent.tools.get_poc_freshness._fetch_epss_signals")
    @patch("manus_agent.tools.get_poc_freshness._fetch_nvd_signals")
    @patch("manus_agent.tools.get_poc_freshness._fetch_exploitdb_signals")
    @patch("manus_agent.tools.get_poc_freshness._fetch_github_signals")
    def test_full_assessment(self, mock_gh, mock_edb, mock_nvd, mock_epss):
        mock_gh.return_value = {
            "status": "ok",
            "repo_count": 2,
            "most_recent_push_days_ago": 3,
            "hot_repos": 1,
            "total_stars": 50,
            "repos": [],
        }
        mock_edb.return_value = {
            "status": "ok",
            "entry_count": 1,
            "most_recent_days_ago": 15,
            "entries": [],
        }
        mock_nvd.return_value = {
            "status": "ok",
            "has_poc_refs": True,
            "last_modified_days_ago": 10,
        }
        mock_epss.return_value = {
            "status": "ok",
            "current_score": 0.30,
            "momentum": 0.05,
        }

        result = assess_poc_freshness("CVE-2024-1234")
        assert result["cve_id"] == "CVE-2024-1234"
        assert "freshness_score" in result
        assert "classification" in result
        assert "signals" in result
        assert "github" in result["signals"]
        assert "exploitdb" in result["signals"]
        assert "nvd" in result["signals"]
        assert "epss" in result["signals"]

    @patch("manus_agent.tools.get_poc_freshness._fetch_epss_signals")
    @patch("manus_agent.tools.get_poc_freshness._fetch_nvd_signals")
    @patch("manus_agent.tools.get_poc_freshness._fetch_exploitdb_signals")
    @patch("manus_agent.tools.get_poc_freshness._fetch_github_signals")
    def test_handles_source_errors(self, mock_gh, mock_edb, mock_nvd, mock_epss):
        mock_gh.side_effect = Exception("network error")
        mock_edb.return_value = {"status": "error", "error": "cache fail"}
        mock_nvd.return_value = {"status": "ok", "last_modified_days_ago": 5}
        mock_epss.return_value = {"status": "ok", "momentum": 0}

        result = assess_poc_freshness("CVE-2024-1234")
        # Should not raise; returns a valid result
        assert result["cve_id"] == "CVE-2024-1234"
        assert "freshness_score" in result

    @patch("manus_agent.tools.get_poc_freshness._fetch_epss_signals")
    @patch("manus_agent.tools.get_poc_freshness._fetch_nvd_signals")
    @patch("manus_agent.tools.get_poc_freshness._fetch_exploitdb_signals")
    @patch("manus_agent.tools.get_poc_freshness._fetch_github_signals")
    def test_cve_uppercased(self, mock_gh, mock_edb, mock_nvd, mock_epss):
        for m in (mock_gh, mock_edb, mock_nvd, mock_epss):
            m.return_value = {"status": "ok"}
        result = assess_poc_freshness("cve-2024-1234")
        assert result["cve_id"] == "CVE-2024-1234"


# ===================================================================
# get_poc_freshness (Strands tool entry point)
# ===================================================================


class TestGetPocFreshnessTool:
    @patch("manus_agent.tools.get_poc_freshness.assess_poc_freshness")
    def test_valid_cve(self, mock_assess):
        mock_assess.return_value = {
            "cve_id": "CVE-2024-1234",
            "freshness_score": 65.0,
            "classification": "high",
        }
        result = get_poc_freshness("CVE-2024-1234")
        assert result["freshness_score"] == 65.0
        mock_assess.assert_called_once_with("CVE-2024-1234")

    def test_invalid_cve(self):
        result = get_poc_freshness("not-a-cve")
        assert result["freshness_score"] == 0
        assert result["classification"] == "none"
        assert "error" in result

    def test_empty_cve(self):
        result = get_poc_freshness("")
        assert result["freshness_score"] == 0

    @patch("manus_agent.tools.get_poc_freshness.assess_poc_freshness")
    def test_whitespace_stripped(self, mock_assess):
        mock_assess.return_value = {"cve_id": "CVE-2024-1234", "freshness_score": 50}
        get_poc_freshness("  CVE-2024-1234  ")
        mock_assess.assert_called_once_with("CVE-2024-1234")


# ===================================================================
# CLI: _build_poc_freshness_parser / _run_poc_freshness
# ===================================================================


class TestCliPocFreshness:
    def test_parser_builds(self):
        from manus_agent.cli import _build_poc_freshness_parser

        p = _build_poc_freshness_parser()
        args = p.parse_args(["CVE-2024-1234"])
        assert args.cve_id == "CVE-2024-1234"
        assert args.output == "text"

    def test_parser_json_output(self):
        from manus_agent.cli import _build_poc_freshness_parser

        p = _build_poc_freshness_parser()
        args = p.parse_args(["CVE-2024-1234", "--output", "json"])
        assert args.output == "json"

    @patch("manus_agent.tools.get_poc_freshness.assess_poc_freshness")
    def test_run_text_output(self, mock_assess, capsys):
        from manus_agent.cli import _run_poc_freshness

        mock_assess.return_value = {
            "cve_id": "CVE-2024-1234",
            "freshness_score": 72.5,
            "classification": "high",
            "description": "Significant recent PoC activity",
            "breakdown": {
                "recency_points": 35.0,
                "breadth_points": 15.0,
                "star_velocity_points": 12.5,
                "epss_momentum_points": 10.0,
            },
            "most_recent_activity_days_ago": 3.5,
            "recent_sources": {"github": True, "exploitdb": True, "nvd": False, "epss": True},
            "signals": {
                "github": {
                    "status": "ok",
                    "repo_count": 3,
                    "repos": [
                        {"name": "user/poc", "stars": 25, "pushed_at": _iso(3), "description": "PoC exploit"},
                    ],
                },
                "exploitdb": {"status": "ok"},
                "nvd": {"status": "ok"},
                "epss": {
                    "status": "ok",
                    "current_score": 0.25,
                    "momentum": 0.05,
                },
            },
        }

        rc = _run_poc_freshness(["CVE-2024-1234"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "72.5/100" in out
        assert "HIGH" in out
        assert "CVE-2024-1234" in out

    @patch("manus_agent.tools.get_poc_freshness.assess_poc_freshness")
    def test_run_json_output(self, mock_assess, capsys):
        from manus_agent.cli import _run_poc_freshness

        mock_assess.return_value = {
            "cve_id": "CVE-2024-1234",
            "freshness_score": 50.0,
        }
        rc = _run_poc_freshness(["CVE-2024-1234", "--output", "json"])
        assert rc == 0
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["freshness_score"] == 50.0

    def test_run_invalid_cve(self):
        from manus_agent.cli import _run_poc_freshness

        with pytest.raises(SystemExit):
            _run_poc_freshness(["not-a-cve"])

    @patch("manus_agent.tools.get_poc_freshness.assess_poc_freshness")
    def test_run_no_activity_text(self, mock_assess, capsys):
        from manus_agent.cli import _run_poc_freshness

        mock_assess.return_value = {
            "cve_id": "CVE-2024-9999",
            "freshness_score": 0.0,
            "classification": "none",
            "description": "No PoC activity detected",
            "breakdown": {
                "recency_points": 0,
                "breadth_points": 0,
                "star_velocity_points": 0,
                "epss_momentum_points": 0,
            },
            "most_recent_activity_days_ago": None,
            "recent_sources": {"github": False, "exploitdb": False, "nvd": False, "epss": False},
            "signals": {
                "github": {"status": "ok", "repo_count": 0, "repos": []},
                "exploitdb": {"status": "ok"},
                "nvd": {"status": "ok"},
                "epss": {"status": "ok", "current_score": None},
            },
        }
        rc = _run_poc_freshness(["CVE-2024-9999"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "no activity detected" in out

    @patch("manus_agent.tools.get_poc_freshness.assess_poc_freshness")
    def test_run_epss_display(self, mock_assess, capsys):
        from manus_agent.cli import _run_poc_freshness

        mock_assess.return_value = {
            "cve_id": "CVE-2024-1234",
            "freshness_score": 30.0,
            "classification": "moderate",
            "description": "Some PoC activity",
            "breakdown": {
                "recency_points": 20,
                "breadth_points": 5,
                "star_velocity_points": 0,
                "epss_momentum_points": 5,
            },
            "most_recent_activity_days_ago": 20,
            "recent_sources": {"github": True, "exploitdb": False, "nvd": False, "epss": False},
            "signals": {
                "github": {"status": "ok", "repo_count": 0, "repos": []},
                "exploitdb": {"status": "ok"},
                "nvd": {"status": "ok"},
                "epss": {
                    "status": "ok",
                    "current_score": 0.0500,
                    "momentum": -0.01,
                },
            },
        }
        rc = _run_poc_freshness(["CVE-2024-1234"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "EPSS" in out
        # Negative momentum should show down arrow
        assert "\u2193" in out


# ===================================================================
# _ensure_exploitdb_cache
# ===================================================================


class TestEnsureExploitdbCache:
    @patch("manus_agent.tools.get_poc_freshness.os.path.getmtime")
    @patch("manus_agent.tools.get_poc_freshness.time.time")
    def test_fresh_cache_returns_path(self, mock_time, mock_mtime):
        mock_time.return_value = 1000000
        mock_mtime.return_value = 999999  # 1 second old
        from manus_agent.tools.get_poc_freshness import _ensure_exploitdb_cache

        result = _ensure_exploitdb_cache()
        assert result == "/tmp/exploitdb_cache.csv"

    @patch("manus_agent.tools.get_poc_freshness.os.path.getmtime")
    @patch("manus_agent.tools.get_poc_freshness.time.time")
    @patch("manus_agent.tools.get_poc_freshness.urllib.request.urlopen")
    def test_stale_cache_downloads(self, mock_urlopen, mock_time, mock_mtime):
        mock_time.return_value = 1100000
        mock_mtime.return_value = 1000000  # stale (>86400s old)

        mock_resp = MagicMock()
        mock_resp.read.return_value = b"id,description\n"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        from manus_agent.tools.get_poc_freshness import _ensure_exploitdb_cache

        with patch("builtins.open", mock_open()):
            result = _ensure_exploitdb_cache()
        assert result == "/tmp/exploitdb_cache.csv"

    @patch("manus_agent.tools.get_poc_freshness.os.path.getmtime")
    def test_no_cache_file(self, mock_mtime):
        mock_mtime.side_effect = FileNotFoundError

        from manus_agent.tools.get_poc_freshness import _ensure_exploitdb_cache

        with patch("manus_agent.tools.get_poc_freshness.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = Exception("network error")
            result = _ensure_exploitdb_cache()
        assert result is None


# ===================================================================
# Edge cases and regression tests
# ===================================================================


class TestEdgeCases:
    def test_decay_at_exactly_half_life(self):
        score = _decay_score(float(_FRESHNESS_HALF_LIFE_DAYS), 100.0)
        assert 49.0 < score < 51.0

    def test_compute_freshness_all_errors(self):
        """All signal sources errored — should still return valid result."""
        result = compute_freshness(
            github={"status": "error"},
            exploitdb={"status": "error"},
            nvd={"status": "error"},
            epss={"status": "error"},
        )
        assert result["freshness_score"] == 0.0
        assert result["classification"] == "none"

    @patch("manus_agent.tools.get_poc_freshness._fetch_epss_signals")
    @patch("manus_agent.tools.get_poc_freshness._fetch_nvd_signals")
    @patch("manus_agent.tools.get_poc_freshness._fetch_exploitdb_signals")
    @patch("manus_agent.tools.get_poc_freshness._fetch_github_signals")
    def test_assess_whitespace_cve(self, mock_gh, mock_edb, mock_nvd, mock_epss):
        for m in (mock_gh, mock_edb, mock_nvd, mock_epss):
            m.return_value = {"status": "ok"}
        result = assess_poc_freshness("  cve-2024-1234  ")
        assert result["cve_id"] == "CVE-2024-1234"

    def test_breadth_with_epss_momentum(self):
        """EPSS momentum >0.01 counts as a recent source."""
        result = compute_freshness(
            github={},
            exploitdb={},
            nvd={},
            epss={"momentum": 0.02},
        )
        assert result["recent_sources"]["epss"] is True
        assert result["breakdown"]["breadth_points"] >= 5

    def test_breadth_epss_below_threshold(self):
        """EPSS momentum <=0.01 does NOT count as recent."""
        result = compute_freshness(
            github={},
            exploitdb={},
            nvd={},
            epss={"momentum": 0.005},
        )
        assert result["recent_sources"]["epss"] is False

    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_github_no_token(self, mock_get):
        """Without GITHUB_TOKEN, no Authorization header."""
        mock_get.return_value = {"items": []}
        with patch.dict(os.environ, {}, clear=True):
            # Remove GITHUB_TOKEN if present
            os.environ.pop("GITHUB_TOKEN", None)
            _fetch_github_signals("CVE-2024-1234")

    @patch("manus_agent.tools.get_poc_freshness._get")
    def test_nvd_no_api_key(self, mock_get):
        """Without NVD_API_KEY, no apiKey header."""
        mock_get.return_value = {"vulnerabilities": []}
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("NVD_API_KEY", None)
            _fetch_nvd_signals("CVE-2024-1234")

    def test_classification_low(self):
        """Score between 1-24 is 'low'."""
        result = compute_freshness(
            github={"most_recent_push_days_ago": 60, "hot_repos": 0, "total_stars": 0},
            exploitdb={},
            nvd={},
            epss={},
        )
        assert result["freshness_score"] > 0
        assert result["classification"] in ("low", "moderate")

    def test_classification_high(self):
        """Score between 50-74 is 'high'."""
        result = compute_freshness(
            github={"most_recent_push_days_ago": 5, "hot_repos": 2, "total_stars": 30},
            exploitdb={"most_recent_days_ago": 10},
            nvd={"last_modified_days_ago": 15},
            epss={"momentum": 0.03},
        )
        assert result["classification"] in ("high", "critical")
