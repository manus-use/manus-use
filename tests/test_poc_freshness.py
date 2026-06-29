"""Tests for check_poc_freshness tool and poc-freshness CLI subcommand."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import patch

from manus_use.tools.check_poc_freshness import (
    _classify_github_repo,
    _fetch_nvd_poc_urls,
    _fetch_trickest_poc_urls,
    _probe_non_github_url,
    check_poc_freshness,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NOW = datetime(2026, 6, 28, 0, 0, 0, tzinfo=timezone.utc)
ACTIVE_DAYS = 90
STALE_THRESHOLD = ACTIVE_DAYS + 1


def _make_repo_data(
    archived: bool = False,
    pushed_at: str = "2026-06-20T00:00:00Z",
    stars: int = 5,
    watchers: int = 5,
    forks: int = 2,
) -> dict[str, Any]:
    return {
        "archived": archived,
        "pushed_at": pushed_at,
        "stargazers_count": stars,
        "watchers_count": watchers,
        "forks_count": forks,
    }


# ---------------------------------------------------------------------------
# _fetch_trickest_poc_urls
# ---------------------------------------------------------------------------


class TestFetchTrickestPocUrls:
    def test_invalid_cve_returns_empty(self):
        assert _fetch_trickest_poc_urls("NOT-A-CVE") == []

    def test_http_error_returns_empty(self):

        with patch(
            "manus_use.tools.check_poc_freshness._fetch_text",
            return_value=(404, ""),
        ):
            result = _fetch_trickest_poc_urls("CVE-2024-3094")
        assert result == []

    def test_parses_github_urls_from_markdown(self):
        markdown = """### POC
#### Github
- https://github.com/owner/exploit-repo
- https://github.com/another/poc (some note)
"""
        with patch(
            "manus_use.tools.check_poc_freshness._fetch_text",
            return_value=(200, markdown),
        ):
            result = _fetch_trickest_poc_urls("CVE-2024-3094")
        assert "https://github.com/owner/exploit-repo" in result
        assert "https://github.com/another/poc" in result

    def test_excludes_commit_urls(self):
        markdown = """### POC
#### Github
- https://github.com/owner/repo/commit/abc123def456
- https://github.com/owner/repo
"""
        with patch(
            "manus_use.tools.check_poc_freshness._fetch_text",
            return_value=(200, markdown),
        ):
            result = _fetch_trickest_poc_urls("CVE-2024-3094")
        # commit URL should be excluded; repo URL should be included
        assert all("/commit/" not in u for u in result)
        assert "https://github.com/owner/repo" in result

    def test_deduplicates_urls(self):
        markdown = """### POC
#### Github
- https://github.com/owner/repo
- https://github.com/owner/repo
"""
        with patch(
            "manus_use.tools.check_poc_freshness._fetch_text",
            return_value=(200, markdown),
        ):
            result = _fetch_trickest_poc_urls("CVE-2024-3094")
        assert result.count("https://github.com/owner/repo") == 1

    def test_strips_trailing_parens(self):
        markdown = """### POC
#### Github
- https://github.com/owner/repo)
"""
        with patch(
            "manus_use.tools.check_poc_freshness._fetch_text",
            return_value=(200, markdown),
        ):
            result = _fetch_trickest_poc_urls("CVE-2024-3094")
        assert "https://github.com/owner/repo" in result
        assert "https://github.com/owner/repo)" not in result

    def test_empty_response_returns_empty(self):
        with patch(
            "manus_use.tools.check_poc_freshness._fetch_text",
            return_value=(200, "### Description\nNo PoCs here."),
        ):
            result = _fetch_trickest_poc_urls("CVE-2024-3094")
        assert result == []


# ---------------------------------------------------------------------------
# _fetch_nvd_poc_urls
# ---------------------------------------------------------------------------


class TestFetchNvdPocUrls:
    def test_none_data_returns_empty(self):
        with patch("manus_use.tools.check_poc_freshness._fetch_json", return_value=None):
            result = _fetch_nvd_poc_urls("CVE-2024-3094")
        assert result == []

    def test_no_vulnerabilities_returns_empty(self):
        with patch(
            "manus_use.tools.check_poc_freshness._fetch_json",
            return_value={"vulnerabilities": []},
        ):
            result = _fetch_nvd_poc_urls("CVE-2024-3094")
        assert result == []

    def test_parses_github_refs(self):
        nvd_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "references": [
                            {"url": "https://github.com/owner/vuln-repo"},
                            {"url": "https://example.com/advisory"},
                        ]
                    }
                }
            ]
        }
        with patch("manus_use.tools.check_poc_freshness._fetch_json", return_value=nvd_data):
            result = _fetch_nvd_poc_urls("CVE-2024-3094")
        assert "https://github.com/owner/vuln-repo" in result
        assert "https://example.com/advisory" not in result

    def test_excludes_commit_refs(self):
        nvd_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "references": [
                            {"url": "https://github.com/owner/repo/commit/abc123"},
                            {"url": "https://github.com/owner/repo"},
                        ]
                    }
                }
            ]
        }
        with patch("manus_use.tools.check_poc_freshness._fetch_json", return_value=nvd_data):
            result = _fetch_nvd_poc_urls("CVE-2024-3094")
        assert all("/commit/" not in u for u in result)
        assert "https://github.com/owner/repo" in result

    def test_deduplicates(self):
        nvd_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "references": [
                            {"url": "https://github.com/owner/repo"},
                            {"url": "https://github.com/owner/repo"},
                        ]
                    }
                }
            ]
        }
        with patch("manus_use.tools.check_poc_freshness._fetch_json", return_value=nvd_data):
            result = _fetch_nvd_poc_urls("CVE-2024-3094")
        assert result.count("https://github.com/owner/repo") == 1


# ---------------------------------------------------------------------------
# _classify_github_repo
# ---------------------------------------------------------------------------


class TestClassifyGithubRepo:
    def _mock_classify(
        self,
        repo_data: dict[str, Any] | None,
        contribs: list | None = None,
        commit_count: int | None = 3,
        active_days: int = ACTIVE_DAYS,
        now: datetime = NOW,
    ) -> dict[str, Any]:
        contribs = contribs if contribs is not None else [{"login": "user1"}]
        with (
            patch(
                "manus_use.tools.check_poc_freshness._fetch_json",
                side_effect=[repo_data, contribs],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._get_commit_count",
                return_value=commit_count,
            ),
        ):
            return _classify_github_repo("owner", "repo", active_days, now)

    def test_deleted_when_data_is_none(self):
        record = self._mock_classify(None)
        assert record["status"] == "deleted"

    def test_archived_when_repo_archived(self):
        record = self._mock_classify(_make_repo_data(archived=True, pushed_at="2026-01-01T00:00:00Z"))
        assert record["status"] == "archived"
        assert record["archived"] is True

    def test_active_when_pushed_recently(self):
        # pushed 8 days ago -- well within 90-day threshold
        recent = (NOW - timedelta(days=8)).strftime("%Y-%m-%dT%H:%M:%SZ")
        record = self._mock_classify(_make_repo_data(pushed_at=recent))
        assert record["status"] == "active"
        assert record["days_since_commit"] == 8

    def test_stale_when_pushed_long_ago(self):
        old = (NOW - timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        record = self._mock_classify(_make_repo_data(pushed_at=old))
        assert record["status"] == "stale"
        assert record["days_since_commit"] == 200

    def test_framework_when_thresholds_met(self):
        recent = (NOW - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        # 10 watchers, 6 contributors, 60 commits
        many_contribs = [{"login": f"u{i}"} for i in range(6)]
        with (
            patch(
                "manus_use.tools.check_poc_freshness._fetch_json",
                side_effect=[
                    _make_repo_data(pushed_at=recent, watchers=10),
                    many_contribs,
                ],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._get_commit_count",
                return_value=60,
            ),
        ):
            record = _classify_github_repo("owner", "repo", ACTIVE_DAYS, NOW)
        assert record["status"] == "framework"
        assert record["is_framework"] is True

    def test_not_framework_when_contributors_too_few(self):
        recent = (NOW - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        few_contribs = [{"login": "u1"}, {"login": "u2"}]  # < 5
        with (
            patch(
                "manus_use.tools.check_poc_freshness._fetch_json",
                side_effect=[
                    _make_repo_data(pushed_at=recent, watchers=10),
                    few_contribs,
                ],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._get_commit_count",
                return_value=60,
            ),
        ):
            record = _classify_github_repo("owner", "repo", ACTIVE_DAYS, NOW)
        assert record["is_framework"] is False

    def test_stars_forks_watchers_populated(self):
        recent = (NOW - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        record = self._mock_classify(_make_repo_data(pushed_at=recent, stars=42, watchers=7, forks=3))
        assert record["stars"] == 42
        assert record["watchers"] == 7
        assert record["forks"] == 3

    def test_unknown_when_push_date_missing(self):
        data = {
            "archived": False,
            "pushed_at": None,
            "stargazers_count": 0,
            "watchers_count": 0,
            "forks_count": 0,
        }
        record = self._mock_classify(data, contribs=[], commit_count=None)
        assert record["status"] == "unknown"


# ---------------------------------------------------------------------------
# _probe_non_github_url
# ---------------------------------------------------------------------------


class TestProbeNonGithubUrl:
    def test_accessible_when_200(self):
        with patch("manus_use.tools.check_poc_freshness._fetch_text", return_value=(200, "body")):
            result = _probe_non_github_url("https://exploit-db.com/exploits/12345")
        assert result["status"] == "non_github"
        assert result["http_status"] == 200
        assert "accessible" in result["note"]

    def test_dead_when_404(self):
        with patch("manus_use.tools.check_poc_freshness._fetch_text", return_value=(404, "")):
            result = _probe_non_github_url("https://exploit-db.com/exploits/99999")
        assert result["http_status"] == 404
        assert "404" in result["note"]


# ---------------------------------------------------------------------------
# check_poc_freshness (main tool)
# ---------------------------------------------------------------------------


class TestCheckPocFreshness:
    def test_invalid_cve_id(self):
        result = check_poc_freshness("not-a-cve")
        assert "Invalid CVE ID" in result

    def test_no_pocs_found(self):
        with (
            patch(
                "manus_use.tools.check_poc_freshness._fetch_trickest_poc_urls",
                return_value=[],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_nvd_poc_urls",
                return_value=[],
            ),
        ):
            result = check_poc_freshness("CVE-9999-99999")
        assert "No public PoC repositories found" in result

    def test_report_header_present(self):
        recent_push = (NOW - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with (
            patch(
                "manus_use.tools.check_poc_freshness._fetch_trickest_poc_urls",
                return_value=["https://github.com/hacker/exploit"],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_nvd_poc_urls",
                return_value=[],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_json",
                side_effect=[
                    _make_repo_data(pushed_at=recent_push),
                    [],  # contributors
                ],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._get_commit_count",
                return_value=5,
            ),
        ):
            result = check_poc_freshness("CVE-2024-3094")
        assert "PoC Freshness Report: CVE-2024-3094" in result

    def test_active_repo_triggers_warning(self):
        recent_push = (NOW - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with (
            patch(
                "manus_use.tools.check_poc_freshness._fetch_trickest_poc_urls",
                return_value=["https://github.com/hacker/exploit"],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_nvd_poc_urls",
                return_value=[],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_json",
                side_effect=[
                    _make_repo_data(pushed_at=recent_push),
                    [],
                ],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._get_commit_count",
                return_value=3,
            ),
        ):
            result = check_poc_freshness("CVE-2024-3094")
        assert "ACTIVE PoC ACTIVITY" in result

    def test_stale_repo_no_warning(self):
        old_push = (NOW - timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with (
            patch(
                "manus_use.tools.check_poc_freshness._fetch_trickest_poc_urls",
                return_value=["https://github.com/hacker/old-poc"],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_nvd_poc_urls",
                return_value=[],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_json",
                side_effect=[
                    _make_repo_data(pushed_at=old_push),
                    [],
                ],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._get_commit_count",
                return_value=3,
            ),
        ):
            result = check_poc_freshness("CVE-2024-3094")
        assert "ACTIVE PoC ACTIVITY" not in result
        assert "STALE" in result.upper() or "stale" in result

    def test_summary_counts_correct(self):
        recent = (NOW - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        old = (NOW - timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with (
            patch(
                "manus_use.tools.check_poc_freshness._fetch_trickest_poc_urls",
                return_value=[
                    "https://github.com/h1/active-poc",
                    "https://github.com/h2/stale-poc",
                ],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_nvd_poc_urls",
                return_value=[],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_json",
                side_effect=[
                    _make_repo_data(pushed_at=recent),
                    [],  # contribs for first repo
                    _make_repo_data(pushed_at=old),
                    [],  # contribs for second repo
                ],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._get_commit_count",
                return_value=3,
            ),
        ):
            result = check_poc_freshness("CVE-2024-3094")
        assert "GitHub PoC repos found : 2" in result

    def test_deleted_repo_reported(self):
        with (
            patch(
                "manus_use.tools.check_poc_freshness._fetch_trickest_poc_urls",
                return_value=["https://github.com/hacker/gone-poc"],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_nvd_poc_urls",
                return_value=[],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_json",
                return_value=None,  # 404
            ),
            patch(
                "manus_use.tools.check_poc_freshness._get_commit_count",
                return_value=None,
            ),
        ):
            result = check_poc_freshness("CVE-2024-3094")
        assert "DELETED" in result or "deleted" in result

    def test_archived_repo_reported(self):
        old = (NOW - timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with (
            patch(
                "manus_use.tools.check_poc_freshness._fetch_trickest_poc_urls",
                return_value=["https://github.com/hacker/archived-poc"],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_nvd_poc_urls",
                return_value=[],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_json",
                side_effect=[
                    _make_repo_data(archived=True, pushed_at=old),
                    [],
                ],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._get_commit_count",
                return_value=3,
            ),
        ):
            result = check_poc_freshness("CVE-2024-3094")
        assert "ARCHIVED" in result

    def test_deduplicates_across_sources(self):
        """Same repo from trickest + NVD should only appear once."""
        recent = (NOW - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with (
            patch(
                "manus_use.tools.check_poc_freshness._fetch_trickest_poc_urls",
                return_value=["https://github.com/owner/shared-poc"],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_nvd_poc_urls",
                return_value=["https://github.com/owner/shared-poc"],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_json",
                side_effect=[
                    _make_repo_data(pushed_at=recent),
                    [],
                ],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._get_commit_count",
                return_value=3,
            ),
        ):
            result = check_poc_freshness("CVE-2024-3094")
        assert result.count("owner/shared-poc") == 1

    def test_custom_active_days(self):
        # With active_days=30 a 60-day-old commit should be stale
        old_for_30 = (NOW - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with (
            patch(
                "manus_use.tools.check_poc_freshness._fetch_trickest_poc_urls",
                return_value=["https://github.com/h/poc"],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_nvd_poc_urls",
                return_value=[],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_json",
                side_effect=[_make_repo_data(pushed_at=old_for_30), []],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._get_commit_count",
                return_value=3,
            ),
        ):
            result = check_poc_freshness("CVE-2024-3094", active_days=30)
        assert "Active threshold : 30 days" in result
        # Should be stale with 30-day threshold
        assert "stale" in result.lower()

    def test_non_github_urls_included(self):
        with (
            patch(
                "manus_use.tools.check_poc_freshness._fetch_trickest_poc_urls",
                return_value=[],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_nvd_poc_urls",
                return_value=["https://exploit-db.com/exploits/12345"],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_text",
                return_value=(200, "body"),
            ),
        ):
            result = check_poc_freshness("CVE-2024-3094")
        # Non-GitHub URLs should be probed and listed
        assert "exploit-db.com" in result

    def test_framework_repo_triggers_warning(self):
        recent = (NOW - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        many_contribs = [{"login": f"u{i}"} for i in range(6)]
        with (
            patch(
                "manus_use.tools.check_poc_freshness._fetch_trickest_poc_urls",
                return_value=["https://github.com/org/big-framework"],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_nvd_poc_urls",
                return_value=[],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._fetch_json",
                side_effect=[
                    _make_repo_data(pushed_at=recent, watchers=15),
                    many_contribs,
                ],
            ),
            patch(
                "manus_use.tools.check_poc_freshness._get_commit_count",
                return_value=80,
            ),
        ):
            result = check_poc_freshness("CVE-2024-3094")
        assert "ACTIVE PoC ACTIVITY" in result
        assert "framework" in result.lower()


# ---------------------------------------------------------------------------
# CLI subcommand: poc-freshness
# ---------------------------------------------------------------------------


class TestPocFreshnessCLI:
    """Test the poc-freshness CLI subcommand dispatch."""

    def _run(self, argv: list[str]) -> int:
        from manus_use.cli import _run_poc_freshness

        return _run_poc_freshness(argv)

    def test_text_output(self, capsys):
        with patch(
            "manus_use.tools.check_poc_freshness.check_poc_freshness",
            return_value="## PoC Freshness Report: CVE-2024-3094\nfoo",
        ):
            rc = self._run(["CVE-2024-3094"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "PoC Freshness Report" in out

    def test_json_output(self, capsys):
        with patch(
            "manus_use.tools.check_poc_freshness.check_poc_freshness",
            return_value="report text",
        ):
            rc = self._run(["CVE-2024-3094", "--output", "json"])
        assert rc == 0
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["cve_id"] == "CVE-2024-3094"
        assert "report" in parsed

    def test_custom_days(self, capsys):
        with patch(
            "manus_use.tools.check_poc_freshness.check_poc_freshness",
            return_value="ok",
        ) as mock_tool:
            self._run(["CVE-2024-3094", "--days", "30"])
        mock_tool.assert_called_once_with(cve_id="CVE-2024-3094", active_days=30)

    def test_cve_normalised_uppercase(self, capsys):
        with patch(
            "manus_use.tools.check_poc_freshness.check_poc_freshness",
            return_value="ok",
        ) as mock_tool:
            self._run(["cve-2024-3094"])
        mock_tool.assert_called_once_with(cve_id="CVE-2024-3094", active_days=90)

    def test_subcommand_in_subcommands_set(self):
        from manus_use.cli import _SUBCOMMANDS

        assert "poc-freshness" in _SUBCOMMANDS


# ---------------------------------------------------------------------------
# VulnerabilityIntelligenceAgent wiring
# ---------------------------------------------------------------------------


class TestVIAgentWiring:
    """Verify check_poc_freshness is wired into the VI agent tool list."""

    def test_check_poc_freshness_importable_from_vi_agent_module(self):
        """The import used inside __init__ must resolve correctly."""
        from manus_use.tools.check_poc_freshness import check_poc_freshness as cpf

        assert callable(cpf)

    def test_vi_agent_system_prompt_references_check_poc_freshness(self):
        from manus_use.agents.vi_agent import SYSTEM_PROMPT

        assert "check_poc_freshness" in SYSTEM_PROMPT

    def test_vi_agent_system_prompt_references_poc_freshness_step(self):
        from manus_use.agents.vi_agent import SYSTEM_PROMPT

        assert "PoC Freshness" in SYSTEM_PROMPT
