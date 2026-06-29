"""
Tests for src/manus_agent/tools/get_patch_diff.py and the patch-diff CLI subcommand.

All network calls are mocked — no real HTTP requests are made.
"""

from __future__ import annotations

import json
import sys
from typing import Any
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_DIFF = """\
diff --git a/src/myapp/auth.py b/src/myapp/auth.py
index abc1234..def5678 100644
--- a/src/myapp/auth.py
+++ b/src/myapp/auth.py
@@ -45,7 +45,11 @@ def check_permission(user, resource):
     if user is None:
         raise ValueError("user must not be None")
+    if not user.is_authenticated:
+        raise PermissionError("Authentication required")
+    if resource not in user.allowed_resources:
+        raise PermissionError(f"Access denied to {resource}")
     return True
"""

_FAKE_DIFF_SQL = """\
diff --git a/db/queries.py b/db/queries.py
index 111..222 100644
--- a/db/queries.py
+++ b/db/queries.py
@@ -10,5 +10,6 @@ def get_user(user_id):
-    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
+    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
+    # validate input before SQL query
     return cursor.fetchone()
"""

_FAKE_DIFF_OVERFLOW = """\
diff --git a/c/parser.c b/c/parser.c
index aaa..bbb 100644
--- a/c/parser.c
+++ b/c/parser.c
@@ -22,4 +22,7 @@ void parse(char *input, size_t len) {
-    memcpy(buf, input, len);
+    if (len > sizeof(buf)) {
+        return;
+    }
+    memcpy(buf, input, len);
 }
"""


def _make_ghsa_response(text_blob: str) -> list[dict[str, Any]]:
    return [
        {
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "summary": "Test advisory",
            "description": text_blob,
            "references": [],
            "vulnerabilities": [],
        }
    ]


def _make_nvd_response(ref_urls: list[str]) -> dict[str, Any]:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-99999",
                    "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                    "references": [{"url": u} for u in ref_urls],
                }
            }
        ]
    }


# ---------------------------------------------------------------------------
# Unit tests: _extract_commits_from_text
# ---------------------------------------------------------------------------


class TestExtractCommitsFromText:
    def test_extracts_commit_url(self):
        from manus_agent.tools.get_patch_diff import _extract_commits_from_text

        text = "Fix: https://github.com/owner/repo/commit/abc1234def5678901234"
        results = _extract_commits_from_text(text)
        assert len(results) == 1
        assert results[0]["owner"] == "owner"
        assert results[0]["repo"] == "repo"
        assert results[0]["sha"] == "abc1234def5678901234"

    def test_deduplicates_same_commit(self):
        from manus_agent.tools.get_patch_diff import _extract_commits_from_text

        url = "https://github.com/owner/repo/commit/abc1234def5678901234"
        text = f"{url}\n{url}"
        results = _extract_commits_from_text(text)
        assert len(results) == 1

    def test_multiple_commits(self):
        from manus_agent.tools.get_patch_diff import _extract_commits_from_text

        text = (
            "https://github.com/owner/repo/commit/aaaaaaaabbbbbbbbcccccccc\n"
            "https://github.com/owner/repo/commit/ddddddddeeeeeeeeffffffff\n"
        )
        results = _extract_commits_from_text(text)
        assert len(results) == 2

    def test_no_commits_returns_empty(self):
        from manus_agent.tools.get_patch_diff import _extract_commits_from_text

        results = _extract_commits_from_text("Nothing here at all.")
        assert results == []

    def test_extracts_pr_and_resolves_merge_commit(self):
        from manus_agent.tools.get_patch_diff import _extract_commits_from_text

        text = "See https://github.com/owner/repo/pull/42 for details"
        pr_data = {"merge_commit_sha": "deadbeefdeadbeef01234567"}
        with patch("manus_agent.tools.get_patch_diff._fetch_json", return_value=pr_data):
            results = _extract_commits_from_text(text)
        assert len(results) == 1
        assert results[0]["sha"] == "deadbeefdeadbeef01234567"

    def test_pr_without_merge_commit_skipped(self):
        from manus_agent.tools.get_patch_diff import _extract_commits_from_text

        text = "See https://github.com/owner/repo/pull/99 for details"
        with patch("manus_agent.tools.get_patch_diff._fetch_json", return_value={"merge_commit_sha": None}):
            results = _extract_commits_from_text(text)
        assert results == []


# ---------------------------------------------------------------------------
# Unit tests: _summarise_diff
# ---------------------------------------------------------------------------


class TestSummariseDiff:
    def test_detects_auth_bypass_class(self):
        from manus_agent.tools.get_patch_diff import _summarise_diff

        result = _summarise_diff(_FAKE_DIFF, "owner", "repo", "abc1234")
        assert "auth_bypass" in result["matched_bug_classes"]
        assert result["primary_bug_class"] == "auth_bypass"

    def test_detects_sql_injection_class(self):
        from manus_agent.tools.get_patch_diff import _summarise_diff

        result = _summarise_diff(_FAKE_DIFF_SQL, "owner", "repo", "abc1234")
        assert "sql_injection" in result["matched_bug_classes"]

    def test_detects_buffer_overflow_class(self):
        from manus_agent.tools.get_patch_diff import _summarise_diff

        result = _summarise_diff(_FAKE_DIFF_OVERFLOW, "owner", "repo", "abc1234")
        assert "buffer_overflow" in result["matched_bug_classes"]

    def test_files_changed_extracted(self):
        from manus_agent.tools.get_patch_diff import _summarise_diff

        result = _summarise_diff(_FAKE_DIFF, "owner", "repo", "abc1234")
        assert "src/myapp/auth.py" in result["files_changed"]

    def test_functions_touched_extracted(self):
        from manus_agent.tools.get_patch_diff import _summarise_diff

        result = _summarise_diff(_FAKE_DIFF, "owner", "repo", "abc1234")
        # The hunk header contains "check_permission"
        assert any("check_permission" in f for f in result["functions_touched"])

    def test_line_counts(self):
        from manus_agent.tools.get_patch_diff import _summarise_diff

        result = _summarise_diff(_FAKE_DIFF, "owner", "repo", "abc1234")
        assert result["added_lines"] > 0
        assert result["removed_lines"] == 0  # only additions in _FAKE_DIFF

    def test_sha_truncated_to_12(self):
        from manus_agent.tools.get_patch_diff import _summarise_diff

        result = _summarise_diff(_FAKE_DIFF, "owner", "repo", "abc1234def567890")
        assert result["sha"] == "abc1234def56"

    def test_commit_url_constructed(self):
        from manus_agent.tools.get_patch_diff import _summarise_diff

        result = _summarise_diff(_FAKE_DIFF, "myowner", "myrepo", "abc1234")
        assert result["commit_url"] == "https://github.com/myowner/myrepo/commit/abc1234"

    def test_reproduction_hints_extracted(self):
        from manus_agent.tools.get_patch_diff import _summarise_diff

        result = _summarise_diff(_FAKE_DIFF, "owner", "repo", "abc1234")
        # Lines with 'authentication', 'allowed' should be picked up as hints
        hints = result["reproduction_condition_hints"]
        assert len(hints) >= 1
        assert any("authenticated" in h or "allowed" in h for h in hints)

    def test_unknown_bug_class_for_empty_diff(self):
        from manus_agent.tools.get_patch_diff import _summarise_diff

        empty_diff = (
            "diff --git a/foo.py b/foo.py\n"
            "index 111..222 100644\n"
            "--- a/foo.py\n"
            "+++ b/foo.py\n"
            "@@ -1 +1 @@\n"
            "-x = 1\n"
            "+x = 2\n"
        )
        result = _summarise_diff(empty_diff, "owner", "repo", "abc1234")
        assert result["primary_bug_class"] == "unknown"
        assert result["matched_bug_classes"] == []

    def test_files_changed_capped_at_20(self):
        from manus_agent.tools.get_patch_diff import _summarise_diff

        many_files_diff = "\n".join(f"diff --git a/file{i}.py b/file{i}.py\nindex 000..111 100644\n" for i in range(25))
        result = _summarise_diff(many_files_diff, "owner", "repo", "abc1234")
        assert len(result["files_changed"]) <= 20


# ---------------------------------------------------------------------------
# Unit tests: fetch_and_summarise (top-level, with mocks)
# ---------------------------------------------------------------------------


class TestFetchAndSummarise:
    def _mock_chain(self, diff_text: str = _FAKE_DIFF):
        """Return a context manager that stubs network calls for a successful flow."""
        commit_url = "https://github.com/owner/repo/commit/abc1234def5678901234"
        ghsa = _make_ghsa_response(commit_url)

        def fake_fetch_json(url: str, timeout: int = 15):
            if "api.github.com/advisories" in url:
                return ghsa
            return None

        def fake_fetch_text(url: str, timeout: int = 20):
            return None  # not used in this path

        def fake_fetch_diff(owner, repo, sha):
            return diff_text

        return (fake_fetch_json, fake_fetch_diff)

    def test_returns_commit_summary_on_success(self):
        from manus_agent.tools.get_patch_diff import fetch_and_summarise

        fake_fetch_json, fake_fetch_diff = self._mock_chain()
        with (
            patch("manus_agent.tools.get_patch_diff._fetch_json", side_effect=fake_fetch_json),
            patch("manus_agent.tools.get_patch_diff._fetch_diff", side_effect=fake_fetch_diff),
        ):
            result = fetch_and_summarise("CVE-2024-99999")

        assert result["not_found"] is False
        assert len(result["commit_summaries"]) == 1
        assert result["commit_summaries"][0]["primary_bug_class"] == "auth_bypass"

    def test_uppercases_cve_id(self):
        from manus_agent.tools.get_patch_diff import fetch_and_summarise

        fake_fetch_json, fake_fetch_diff = self._mock_chain()
        with (
            patch("manus_agent.tools.get_patch_diff._fetch_json", side_effect=fake_fetch_json),
            patch("manus_agent.tools.get_patch_diff._fetch_diff", side_effect=fake_fetch_diff),
        ):
            result = fetch_and_summarise("cve-2024-99999")  # lowercase input

        assert result["cve_id"] == "CVE-2024-99999"

    def test_falls_back_to_nvd_when_ghsa_empty(self):
        from manus_agent.tools.get_patch_diff import fetch_and_summarise

        commit_url = "https://github.com/owner/repo/commit/abc1234def5678901234"
        nvd_resp = _make_nvd_response([commit_url])

        def fake_fetch_json(url: str, timeout: int = 15):
            if "api.github.com/advisories" in url:
                return []  # no GHSA results
            if "nvd.nist.gov" in url:
                return nvd_resp
            return None

        with (
            patch("manus_agent.tools.get_patch_diff._fetch_json", side_effect=fake_fetch_json),
            patch("manus_agent.tools.get_patch_diff._fetch_diff", return_value=_FAKE_DIFF),
        ):
            result = fetch_and_summarise("CVE-2024-99999")

        assert result["not_found"] is False
        assert len(result["commit_summaries"]) >= 1

    def test_not_found_when_no_commit_references(self):
        from manus_agent.tools.get_patch_diff import fetch_and_summarise

        def fake_fetch_json(url: str, timeout: int = 15):
            if "api.github.com/advisories" in url:
                return []
            if "nvd.nist.gov" in url:
                return _make_nvd_response([])
            return None

        with patch("manus_agent.tools.get_patch_diff._fetch_json", side_effect=fake_fetch_json):
            result = fetch_and_summarise("CVE-2024-99999")

        assert result["not_found"] is True
        assert result["commit_summaries"] == []
        assert "CVE-2024-99999" in result["message"]

    def test_not_found_when_diff_unavailable(self):
        from manus_agent.tools.get_patch_diff import fetch_and_summarise

        commit_url = "https://github.com/owner/repo/commit/abc1234def5678901234"
        ghsa = _make_ghsa_response(commit_url)

        def fake_fetch_json(url: str, timeout: int = 15):
            if "api.github.com/advisories" in url:
                return ghsa
            return None

        with (
            patch("manus_agent.tools.get_patch_diff._fetch_json", side_effect=fake_fetch_json),
            patch("manus_agent.tools.get_patch_diff._fetch_diff", return_value=None),
        ):
            result = fetch_and_summarise("CVE-2024-99999")

        assert result["not_found"] is True

    def test_analyses_at_most_3_commits(self):
        from manus_agent.tools.get_patch_diff import fetch_and_summarise

        # Advisory has 5 commit URLs
        many_urls = " ".join(
            f"https://github.com/owner/repo/commit/{sha}"
            for sha in [
                "aaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbb",
                "cccccccccccccccc",
                "dddddddddddddddd",
                "eeeeeeeeeeeeeeee",
            ]
        )
        ghsa = _make_ghsa_response(many_urls)

        def fake_fetch_json(url: str, timeout: int = 15):
            if "api.github.com/advisories" in url:
                return ghsa
            return None

        with (
            patch("manus_agent.tools.get_patch_diff._fetch_json", side_effect=fake_fetch_json),
            patch("manus_agent.tools.get_patch_diff._fetch_diff", return_value=_FAKE_DIFF),
        ):
            result = fetch_and_summarise("CVE-2024-99999")

        assert len(result["commit_summaries"]) <= 3


# ---------------------------------------------------------------------------
# Unit tests: Strands ToolResult (get_patch_diff handler)
# ---------------------------------------------------------------------------


class TestGetPatchDiffTool:
    def _make_tool_use(self, cve_id: str) -> dict:
        return {"toolUseId": "test-id-001", "input": {"cve_id": cve_id}}

    def test_invalid_cve_returns_error(self):
        from manus_agent.tools.get_patch_diff import get_patch_diff

        tool_use = self._make_tool_use("NOT-A-CVE")
        result = get_patch_diff(tool_use)
        assert result["status"] == "error"
        assert "Invalid CVE ID" in result["content"][0]["text"]

    def test_empty_cve_returns_error(self):
        from manus_agent.tools.get_patch_diff import get_patch_diff

        tool_use = self._make_tool_use("")
        result = get_patch_diff(tool_use)
        assert result["status"] == "error"

    def test_success_returns_success_status(self):
        from manus_agent.tools.get_patch_diff import get_patch_diff

        tool_use = self._make_tool_use("CVE-2024-99999")

        commit_url = "https://github.com/owner/repo/commit/abc1234def5678901234"
        ghsa = _make_ghsa_response(commit_url)

        def fake_fetch_json(url: str, timeout: int = 15):
            if "api.github.com/advisories" in url:
                return ghsa
            return None

        with (
            patch("manus_agent.tools.get_patch_diff._fetch_json", side_effect=fake_fetch_json),
            patch("manus_agent.tools.get_patch_diff._fetch_diff", return_value=_FAKE_DIFF),
        ):
            result = get_patch_diff(tool_use)

        assert result["status"] == "success"
        assert result["toolUseId"] == "test-id-001"
        # Should have text and json blocks
        content_types = {list(c.keys())[0] for c in result["content"]}
        assert "text" in content_types
        assert "json" in content_types

    def test_not_found_returns_success_with_message(self):
        from manus_agent.tools.get_patch_diff import get_patch_diff

        tool_use = self._make_tool_use("CVE-2024-99999")

        def fake_fetch_json(url: str, timeout: int = 15):
            if "api.github.com/advisories" in url:
                return []
            if "nvd.nist.gov" in url:
                return _make_nvd_response([])
            return None

        with patch("manus_agent.tools.get_patch_diff._fetch_json", side_effect=fake_fetch_json):
            result = get_patch_diff(tool_use)

        assert result["status"] == "success"
        json_block = next(c["json"] for c in result["content"] if "json" in c)
        assert json_block["not_found"] is True

    def test_tool_use_id_echoed(self):
        from manus_agent.tools.get_patch_diff import get_patch_diff

        tool_use = self._make_tool_use("NOT-A-CVE")
        result = get_patch_diff(tool_use)
        assert result["toolUseId"] == "test-id-001"


# ---------------------------------------------------------------------------
# Unit tests: CLI subcommand (patch-diff)
# ---------------------------------------------------------------------------


class TestPatchDiffCLI:
    def test_patch_diff_registered_in_subcommands(self):
        from manus_agent.cli import _SUBCOMMANDS

        assert "patch-diff" in _SUBCOMMANDS

    def test_build_patch_diff_parser_exists(self):
        from manus_agent.cli import _build_patch_diff_parser

        p = _build_patch_diff_parser()
        assert p is not None

    def test_patch_diff_requires_cve_arg(self):
        from manus_agent.cli import _build_patch_diff_parser

        p = _build_patch_diff_parser()
        with pytest.raises(SystemExit):
            p.parse_args([])

    def test_patch_diff_default_output_text(self):
        from manus_agent.cli import _build_patch_diff_parser

        args = _build_patch_diff_parser().parse_args(["CVE-2024-3094"])
        assert args.output == "text"

    def test_patch_diff_output_json(self):
        from manus_agent.cli import _build_patch_diff_parser

        args = _build_patch_diff_parser().parse_args(["CVE-2024-3094", "--output", "json"])
        assert args.output == "json"

    def test_run_patch_diff_text_output(self, capsys):
        from manus_agent.cli import _run_patch_diff

        payload = {
            "cve_id": "CVE-2024-99999",
            "not_found": False,
            "message": "Found 1 fixing commit(s) for CVE-2024-99999.",
            "commit_summaries": [
                {
                    "owner": "owner",
                    "repo": "repo",
                    "sha": "abc1234",
                    "commit_url": "https://github.com/owner/repo/commit/abc1234",
                    "files_changed": ["src/auth.py"],
                    "functions_touched": ["check_permission"],
                    "added_lines": 4,
                    "removed_lines": 0,
                    "matched_bug_classes": ["auth_bypass"],
                    "primary_bug_class": "auth_bypass",
                    "reproduction_condition_hints": ["if not user.is_authenticated:"],
                }
            ],
        }

        with patch("manus_agent.tools.get_patch_diff.fetch_and_summarise", return_value=payload):
            rc = _run_patch_diff(["CVE-2024-99999"])

        assert rc == 0
        captured = capsys.readouterr()
        assert "CVE-2024-99999" in captured.out
        assert "auth_bypass" in captured.out
        assert "check_permission" in captured.out

    def test_run_patch_diff_json_output(self, capsys):
        from manus_agent.cli import _run_patch_diff

        payload = {
            "cve_id": "CVE-2024-99999",
            "not_found": True,
            "message": "No GitHub fixing-commit references found for CVE-2024-99999.",
            "commit_summaries": [],
        }

        with patch("manus_agent.tools.get_patch_diff.fetch_and_summarise", return_value=payload):
            rc = _run_patch_diff(["CVE-2024-99999", "--output", "json"])

        assert rc == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["cve_id"] == "CVE-2024-99999"
        assert parsed["not_found"] is True

    def test_run_patch_diff_not_found_exits_zero(self, capsys):
        from manus_agent.cli import _run_patch_diff

        payload = {
            "cve_id": "CVE-2024-99999",
            "not_found": True,
            "message": "No references found.",
            "commit_summaries": [],
        }

        with patch("manus_agent.tools.get_patch_diff.fetch_and_summarise", return_value=payload):
            rc = _run_patch_diff(["CVE-2024-99999"])

        assert rc == 0

    def test_run_patch_diff_missing_import_exits_one(self, capsys):
        from manus_agent.cli import _run_patch_diff

        with patch.dict(sys.modules, {"manus_agent.tools.get_patch_diff": None}):
            rc = _run_patch_diff(["CVE-2024-99999"])

        assert rc == 1

    def test_main_dispatches_patch_diff(self):
        """main() should dispatch 'patch-diff' to _run_patch_diff."""
        from manus_agent import cli

        payload = {
            "cve_id": "CVE-2024-99999",
            "not_found": True,
            "message": "Not found.",
            "commit_summaries": [],
        }

        with (
            patch("manus_agent.tools.get_patch_diff.fetch_and_summarise", return_value=payload),
            patch("sys.argv", ["manus-agent", "patch-diff", "CVE-2024-99999"]),
            pytest.raises(SystemExit) as exc,
        ):
            cli.main()

        assert exc.value.code == 0


# ---------------------------------------------------------------------------
# Unit tests: vi_agent integration (tool list includes get_patch_diff)
# ---------------------------------------------------------------------------


class TestVIAgentIncludesPatchDiff:
    def test_vi_agent_imports_get_patch_diff(self):
        """VulnerabilityIntelligenceAgent should import get_patch_diff without error."""
        # Just verify the import path resolves
        from manus_agent.tools.get_patch_diff import get_patch_diff  # noqa: F401

        assert callable(get_patch_diff)

    def test_get_patch_diff_in_vi_agent_source(self):
        """vi_agent.py source must reference get_patch_diff."""
        import inspect

        from manus_agent.agents import vi_agent

        src = inspect.getsource(vi_agent)
        assert "get_patch_diff" in src


# ---------------------------------------------------------------------------
# Unit tests: README documents patch-diff
# ---------------------------------------------------------------------------


class TestReadmeDocsPatchDiff:
    def _get_readme(self) -> str:
        from pathlib import Path

        repo_root = Path(__file__).resolve().parents[1]
        return (repo_root / "README.md").read_text()

    def test_readme_has_patch_diff_section(self):
        assert "patch-diff" in self._get_readme()

    def test_readme_documents_patch_diff_output_flag(self):
        readme = self._get_readme()
        assert "--output" in readme and "patch-diff" in readme

    def test_readme_has_patch_diff_example(self):
        readme = self._get_readme()
        assert "manus-agent patch-diff CVE" in readme
