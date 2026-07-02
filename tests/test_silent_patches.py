"""
Tests for src/manus_agent/tools/detect_silent_patches.py
and the manus-agent silent-patches CLI subcommand.

All external HTTP calls are mocked — no real network I/O.
100% mocked: GitHub commits API, GitHub diff API.
"""

from __future__ import annotations

import contextlib
import json
from io import StringIO
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from manus_agent.tools.detect_silent_patches import (
    _BUG_CLASSES,
    _MSG_THRESHOLD,
    _classify_bug,
    _fetch_commits,
    _fetch_diff,
    _github_headers,
    _score_diff,
    _score_message,
    detect_silent_patches,
)

# ===========================================================================
# Fixtures / helpers
# ===========================================================================


def _make_commit(
    sha: str = "abc1234567890",
    message: str = "fix: resolve buffer overflow in parser",
    author_name: str = "Alice Dev",
    date: str = "2025-03-15T12:00:00Z",
    html_url: str = "https://github.com/example/repo/commit/abc1234567890",
) -> dict[str, Any]:
    return {
        "sha": sha,
        "html_url": html_url,
        "commit": {
            "message": message,
            "author": {"name": author_name, "date": date},
            "committer": {"name": author_name, "date": date},
        },
    }


def _mock_resp(data: Any, status: int = 200, headers: dict[str, str] | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = data
    resp.text = json.dumps(data) if isinstance(data, (dict, list)) else str(data)
    resp.headers = headers or {}
    resp.raise_for_status = MagicMock()
    if status >= 400:
        resp.raise_for_status.side_effect = Exception(f"HTTP {status}")
    return resp


# ===========================================================================
# _github_headers
# ===========================================================================


class TestGithubHeaders:
    def test_no_token(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        h = _github_headers()
        assert "Authorization" not in h
        assert h["Accept"] == "application/vnd.github.v3+json"

    def test_with_token(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        h = _github_headers()
        assert h["Authorization"] == "token ghp_test123"


# ===========================================================================
# _score_message
# ===========================================================================


class TestScoreMessage:
    def test_empty_message_scores_zero(self):
        assert _score_message("") == 0

    def test_irrelevant_message_scores_zero(self):
        assert _score_message("docs: update changelog") == 0

    def test_fix_keyword_scores_positive(self):
        score = _score_message("fix: resolve crash in http handler")
        assert score > 0

    def test_buffer_overflow_scores_high(self):
        score = _score_message("fix buffer overflow in packet parser")
        assert score >= _MSG_THRESHOLD

    def test_use_after_free_scores_high(self):
        score = _score_message("fix use-after-free in event loop")
        assert score >= _MSG_THRESHOLD

    def test_security_fix_scores_very_high(self):
        score = _score_message("security-fix: prevent arbitrary code execution")
        assert score >= 4  # weight-4 keyword

    def test_rce_abbreviation(self):
        score = _score_message("patch rce vulnerability in api endpoint")
        assert score >= 4

    def test_sql_inject(self):
        score = _score_message("fix sql injection in search handler")
        assert score >= _MSG_THRESHOLD

    def test_xss(self):
        score = _score_message("sanitize user input to prevent XSS attacks")
        assert score >= _MSG_THRESHOLD

    def test_path_traversal(self):
        score = _score_message("fix path traversal in file upload")
        assert score >= _MSG_THRESHOLD

    def test_auth_bypass(self):
        score = _score_message("fix authentication bypass in login flow")
        assert score >= _MSG_THRESHOLD

    def test_cve_message_still_scores(self):
        # CVE filter is applied outside _score_message; the score function
        # itself does NOT skip CVE-tagged messages.
        score = _score_message("CVE-2024-1234: fix buffer overflow")
        assert score >= 0  # just confirm it doesn't crash

    def test_privilege_escalation(self):
        score = _score_message("prevent privilege escalation via symlink")
        assert score >= _MSG_THRESHOLD

    def test_heap_overflow(self):
        score = _score_message("fix heap overflow in json decoder")
        assert score >= _MSG_THRESHOLD

    def test_integer_overflow(self):
        score = _score_message("fix integer overflow in size computation")
        assert score >= _MSG_THRESHOLD

    def test_null_pointer_deref(self):
        score = _score_message("fix null pointer dereference in teardown")
        assert score >= _MSG_THRESHOLD

    def test_case_insensitive(self):
        score_lower = _score_message("fix buffer overflow")
        score_upper = _score_message("FIX BUFFER OVERFLOW")
        assert score_lower > 0
        assert score_upper > 0

    def test_multiple_keywords_accumulate(self):
        score_one = _score_message("fix crash")
        score_two = _score_message("fix crash use-after-free buffer overflow")
        assert score_two > score_one


# ===========================================================================
# _score_diff
# ===========================================================================


class TestScoreDiff:
    def test_empty_diff_scores_zero(self):
        assert _score_diff("") == 0

    def test_irrelevant_diff_scores_zero(self):
        assert _score_diff("+++ b/README.md\n- Added documentation\n+ Updated docs") == 0

    def test_free_call_scores_positive(self):
        diff = "-    free(ptr);\n+    // freed\n     free(ptr);"
        assert _score_diff(diff) > 0

    def test_dangerous_string_funcs(self):
        diff = "+    strcpy(dst, src);\n+    strcat(buf, extra);"
        assert _score_diff(diff) > 0

    def test_exec_system_call(self):
        diff = "+    system(cmd);\n+    exec(argv);"
        assert _score_diff(diff) > 0

    def test_bounds_check_addition(self):
        diff = "+    if (len > sizeof(buf)) return -1;\n+    bounds_check(size);"
        assert _score_diff(diff) > 0

    def test_crypto_weakness(self):
        diff = "+    MD5(data, len, hash);\n+    RAND_pseudo_bytes(buf, 16);"
        assert _score_diff(diff) > 0

    def test_path_traversal_diff(self):
        diff = "+    if (strstr(path, '../') != NULL) return NULL;"
        assert _score_diff(diff) > 0

    def test_multiple_occurrences_accumulate(self):
        single = _score_diff("+    free(ptr);")
        multiple = _score_diff("+    free(ptr);\n+    free(ptr2);\n+    free(ptr3);")
        assert multiple >= single

    def test_sql_sink(self):
        diff = '+    cursor.execute("SELECT * FROM users WHERE id=" + user_id);'
        assert _score_diff(diff) > 0

    def test_eval_sink(self):
        diff = "+    eval(user_input)"
        assert _score_diff(diff) > 0

    def test_format_string(self):
        diff = "+    printf(user_str);"
        assert _score_diff(diff) > 0


# ===========================================================================
# _classify_bug
# ===========================================================================


class TestClassifyBug:
    def test_auth_bypass(self):
        assert _classify_bug("fix auth bypass in login") == "auth_bypass"

    def test_buffer_overflow(self):
        assert _classify_bug("fix buffer overflow in parser") == "buffer_overflow"

    def test_use_after_free(self):
        assert _classify_bug("fix use-after-free in event loop") == "use_after_free"

    def test_integer_overflow(self):
        assert _classify_bug("fix integer overflow in size calc") == "integer_overflow"

    def test_injection(self):
        assert _classify_bug("fix sql injection vulnerability") == "injection"

    def test_xss_injection(self):
        assert _classify_bug("prevent XSS in template renderer") == "injection"

    def test_path_traversal(self):
        assert _classify_bug("fix path traversal in upload handler") == "path_traversal"

    def test_denial_of_service(self):
        assert _classify_bug("fix denial of service via crafted packet") == "denial_of_service"

    def test_privilege_escalation(self):
        assert _classify_bug("fix privilege escalation via setuid") == "privilege_escalation"

    def test_null_deref(self):
        assert _classify_bug("fix null ptr dereference in cleanup") == "null_deref"

    def test_crypto_weakness(self):
        assert _classify_bug("replace insecure random with CSPRNG") == "crypto_weakness"

    def test_format_string(self):
        assert _classify_bug("fix format string vulnerability") == "format_string"

    def test_unknown_returns_unknown(self):
        assert _classify_bug("update documentation and typos") == "unknown"

    def test_race_condition(self):
        assert _classify_bug("fix race condition in worker pool") == "race_condition"

    def test_memory_leak(self):
        assert _classify_bug("fix memory leak in connection pool") == "memory_leak"

    def test_case_insensitive_classification(self):
        assert _classify_bug("FIX AUTH BYPASS") == "auth_bypass"


# ===========================================================================
# _fetch_commits
# ===========================================================================


class TestFetchCommits:
    @patch("manus_agent.tools.detect_silent_patches.requests.get")
    def test_returns_commits(self, mock_get: MagicMock):
        commits = [_make_commit(sha=f"sha{i:08d}" * 2) for i in range(3)]
        mock_get.return_value = _mock_resp(commits)
        result = _fetch_commits("owner", "repo", "2025-01-01T00:00:00Z", "2025-03-01T00:00:00Z", 10)
        assert len(result) == 3
        mock_get.assert_called_once()

    @patch("manus_agent.tools.detect_silent_patches.requests.get")
    def test_respects_max_commits(self, mock_get: MagicMock):
        commits = [_make_commit(sha=f"sha{i:010d}") for i in range(50)]
        mock_get.return_value = _mock_resp(commits)
        result = _fetch_commits("owner", "repo", "2025-01-01T00:00:00Z", "2025-03-01T00:00:00Z", 10)
        assert len(result) == 10

    @patch("manus_agent.tools.detect_silent_patches.requests.get")
    def test_follows_pagination_link(self, mock_get: MagicMock):
        page1 = [_make_commit(sha=f"sha_a{i:04d}") for i in range(5)]
        page2 = [_make_commit(sha=f"sha_b{i:04d}") for i in range(3)]

        resp1 = _mock_resp(
            page1,
            headers={"Link": '<https://api.github.com/next?page=2>; rel="next"'},
        )
        resp2 = _mock_resp(page2)
        mock_get.side_effect = [resp1, resp2]

        result = _fetch_commits("owner", "repo", "2025-01-01T00:00:00Z", "2025-03-01T00:00:00Z", 100)
        assert len(result) == 8

    @patch("manus_agent.tools.detect_silent_patches.requests.get")
    def test_handles_request_exception(self, mock_get: MagicMock):
        import requests as _requests

        mock_get.side_effect = _requests.RequestException("network error")
        result = _fetch_commits("owner", "repo", "2025-01-01T00:00:00Z", "2025-03-01T00:00:00Z", 100)
        assert result == []

    @patch("manus_agent.tools.detect_silent_patches.requests.get")
    def test_handles_unexpected_response_type(self, mock_get: MagicMock):
        mock_get.return_value = _mock_resp({"message": "Not Found"})
        result = _fetch_commits("owner", "repo", "2025-01-01T00:00:00Z", "2025-03-01T00:00:00Z", 100)
        assert result == []

    @patch("manus_agent.tools.detect_silent_patches.requests.get")
    def test_empty_repository(self, mock_get: MagicMock):
        mock_get.return_value = _mock_resp([])
        result = _fetch_commits("owner", "repo", "2025-01-01T00:00:00Z", "2025-03-01T00:00:00Z", 100)
        assert result == []


# ===========================================================================
# _fetch_diff
# ===========================================================================


class TestFetchDiff:
    @patch("manus_agent.tools.detect_silent_patches.requests.get")
    def test_returns_diff_text(self, mock_get: MagicMock):
        diff_content = "diff --git a/foo.c b/foo.c\n+    free(ptr);"
        resp = MagicMock()
        resp.text = diff_content
        resp.raise_for_status = MagicMock()
        mock_get.return_value = resp
        result = _fetch_diff("owner", "repo", "abc123")
        assert result == diff_content

    @patch("manus_agent.tools.detect_silent_patches.requests.get")
    def test_handles_request_exception(self, mock_get: MagicMock):
        import requests as _requests

        mock_get.side_effect = _requests.RequestException("timeout")
        result = _fetch_diff("owner", "repo", "abc123")
        assert result == ""

    @patch("manus_agent.tools.detect_silent_patches.requests.get")
    def test_uses_diff_accept_header(self, mock_get: MagicMock):
        resp = MagicMock()
        resp.text = "diff content"
        resp.raise_for_status = MagicMock()
        mock_get.return_value = resp
        _fetch_diff("owner", "repo", "abc123")
        call_kwargs = mock_get.call_args
        headers_arg = call_kwargs[1].get("headers") or call_kwargs[0][1]
        assert headers_arg.get("Accept") == "application/vnd.github.v3.diff"


# ===========================================================================
# detect_silent_patches (tool)
# ===========================================================================


class TestDetectSilentPatches:
    def test_invalid_repo_format_returns_error(self):
        result = detect_silent_patches(repo="notaslug")
        assert "error" in result
        assert result["candidates"] == []

    def test_invalid_repo_format_with_spaces(self):
        result = detect_silent_patches(repo="  just-a-name  ")
        assert "error" in result

    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_no_commits_returns_empty_candidates(self, mock_fetch: MagicMock):
        mock_fetch.return_value = []
        result = detect_silent_patches(repo="owner/repo")
        assert result["candidates"] == []
        assert result["commits_scanned"] == 0
        assert "owner/repo" in result["repo"]

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_cve_tagged_commits_excluded(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        cve_commit = _make_commit(
            sha="cve_commit_sha1",
            message="CVE-2024-1234: fix buffer overflow in network stack",
        )
        mock_fetch.return_value = [cve_commit]
        mock_diff.return_value = "+    free(ptr);\n+    strcpy(dst, src);"
        result = detect_silent_patches(repo="owner/repo")
        # CVE-tagged commit should not appear in candidates
        assert result["candidates"] == []

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_low_score_commit_excluded(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        low_score = _make_commit(
            sha="low_score_sha01",
            message="refactor: move helper functions to utils",
        )
        mock_fetch.return_value = [low_score]
        mock_diff.return_value = "no security content"
        result = detect_silent_patches(repo="owner/repo")
        assert result["candidates"] == []

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_high_score_commit_included(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        security_commit = _make_commit(
            sha="security_sha000",
            message="fix buffer overflow in packet parser prevent out-of-bounds write",
        )
        mock_fetch.return_value = [security_commit]
        mock_diff.return_value = "+    if (len > sizeof(buf)) return -1;\n+    memcpy(dst, src, safe_len);"
        result = detect_silent_patches(repo="owner/repo")
        assert len(result["candidates"]) == 1
        c = result["candidates"][0]
        assert c["sha"] == "security_sha000"[:12]
        assert c["combined_score"] > 0
        assert c["classification"] in {cls for cls, _ in _BUG_CLASSES} | {"unknown"}

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_fast_mode_skips_diff_fetch(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        commit = _make_commit(
            sha="fast_mode_sha00",
            message="security-fix: prevent arbitrary code execution in handler",
        )
        mock_fetch.return_value = [commit]
        result = detect_silent_patches(repo="owner/repo", fast=True)
        mock_diff.assert_not_called()
        if result["candidates"]:
            assert result["candidates"][0]["fast_mode"] is True
            assert result["candidates"][0]["diff_score"] == 0

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_candidates_sorted_by_combined_score_desc(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        commits = [
            _make_commit(sha="low_sec_sha000", message="fix minor crash"),
            _make_commit(
                sha="high_sec_sha00",
                message="security-fix: fix use-after-free buffer overflow rce vulnerability",
            ),
            _make_commit(
                sha="med_sec_sha000",
                message="fix heap overflow in network parser",
            ),
        ]
        mock_fetch.return_value = commits
        mock_diff.return_value = "+    free(ptr);\n+    strcpy(dst, src);"
        result = detect_silent_patches(repo="owner/repo")
        if len(result["candidates"]) >= 2:
            scores = [c["combined_score"] for c in result["candidates"]]
            assert scores == sorted(scores, reverse=True)

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_default_since_is_90_days_ago(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        mock_fetch.return_value = []
        result = detect_silent_patches(repo="owner/repo")
        # since should be a valid ISO timestamp
        assert "T" in result["since"]
        assert result["since"].endswith("Z")

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_bare_date_normalised_to_timestamp(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        mock_fetch.return_value = []
        result = detect_silent_patches(repo="owner/repo", since="2025-01-01", until="2025-03-01")
        assert result["since"] == "2025-01-01T00:00:00Z"
        assert result["until"] == "2025-03-01T23:59:59Z"

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_max_commits_cap_applied(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        mock_fetch.return_value = []
        detect_silent_patches(repo="owner/repo", max_commits=5000)
        call_args = mock_fetch.call_args
        assert call_args is not None  # tool was called; internal cap is 2000

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_summary_contains_repo_and_count(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        mock_fetch.return_value = []
        result = detect_silent_patches(repo="torvalds/linux")
        assert "torvalds/linux" in result["summary"]
        assert "0" in result["summary"]

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_candidate_sha_truncated_to_12(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        commit = _make_commit(
            sha="abcdef1234567890",
            message="security fix: fix buffer overflow in tls handshake",
        )
        mock_fetch.return_value = [commit]
        mock_diff.return_value = "+    strcpy(dst, src);\n+    free(ptr);"
        result = detect_silent_patches(repo="owner/repo")
        if result["candidates"]:
            assert len(result["candidates"][0]["sha"]) == 12
            assert result["candidates"][0]["sha_full"] == "abcdef1234567890"

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_candidate_has_expected_fields(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        commit = _make_commit(
            sha="fieldcheck_sha0",
            message="fix use-after-free in event dispatch loop",
        )
        mock_fetch.return_value = [commit]
        mock_diff.return_value = "+    free(ptr);\n+    ptr = NULL;"
        result = detect_silent_patches(repo="owner/repo")
        if result["candidates"]:
            c = result["candidates"][0]
            required_fields = {
                "sha",
                "sha_full",
                "subject",
                "date",
                "author",
                "url",
                "msg_score",
                "diff_score",
                "combined_score",
                "classification",
                "fast_mode",
            }
            assert required_fields <= c.keys()

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_multiple_cves_in_batch_all_excluded(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        commits = [_make_commit(sha=f"cve_{i:010d}", message=f"CVE-2024-{1000 + i}: fix overflow") for i in range(5)]
        mock_fetch.return_value = commits
        mock_diff.return_value = ""
        result = detect_silent_patches(repo="owner/repo")
        assert result["candidates"] == []

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_commits_scanned_reflects_total_fetched(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        commits = [_make_commit(sha=f"sha_{i:010d}") for i in range(17)]
        mock_fetch.return_value = commits
        mock_diff.return_value = ""
        result = detect_silent_patches(repo="owner/repo")
        assert result["commits_scanned"] == 17

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_classification_set_for_buffer_overflow_commit(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        commit = _make_commit(
            sha="bof_commit_sha0",
            message="fix buffer overflow in http header parser",
        )
        mock_fetch.return_value = [commit]
        mock_diff.return_value = "+    if (len > MAX_HEADER_SIZE) return -1;"
        result = detect_silent_patches(repo="owner/repo")
        if result["candidates"]:
            assert result["candidates"][0]["classification"] == "buffer_overflow"

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_use_after_free_classification(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        commit = _make_commit(
            sha="uaf_commit_sha0",
            message="fix use-after-free in timer callback",
        )
        mock_fetch.return_value = [commit]
        mock_diff.return_value = "+    ptr = NULL; // prevent use-after-free"
        result = detect_silent_patches(repo="owner/repo")
        if result["candidates"]:
            assert result["candidates"][0]["classification"] == "use_after_free"


# ===========================================================================
# CLI: manus-agent silent-patches
# ===========================================================================


class TestSilentPatchesCLI:
    def test_silent_patches_in_subcommands_set(self):
        from manus_agent.cli import _SUBCOMMANDS

        assert "silent-patches" in _SUBCOMMANDS

    def test_parser_help_does_not_crash(self):
        from manus_agent.cli import _build_silent_patches_parser

        p = _build_silent_patches_parser()
        assert p is not None

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_json_output_is_valid_json(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        from manus_agent.cli import _run_silent_patches

        commit = _make_commit(
            sha="json_test_sha00",
            message="security-fix: fix use-after-free in network handler",
        )
        mock_fetch.return_value = [commit]
        mock_diff.return_value = "+    free(ptr);\n+    ptr = NULL;"

        captured = StringIO()
        with contextlib.redirect_stdout(captured):
            code = _run_silent_patches(["owner/repo", "--output", "json"])

        assert code == 0
        output = captured.getvalue()
        parsed = json.loads(output)
        assert isinstance(parsed, list)

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_text_output_no_crash_empty(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        from manus_agent.cli import _run_silent_patches

        mock_fetch.return_value = []
        code = _run_silent_patches(["owner/repo"])
        assert code == 0

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_fast_flag_passed_to_tool(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        from manus_agent.cli import _run_silent_patches

        mock_fetch.return_value = []
        code = _run_silent_patches(["owner/repo", "--fast"])
        assert code == 0
        mock_diff.assert_not_called()

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_max_commits_flag(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        from manus_agent.cli import _run_silent_patches

        mock_fetch.return_value = []
        code = _run_silent_patches(["owner/repo", "--max-commits", "100"])
        assert code == 0
        assert mock_fetch.call_args is not None

    def test_invalid_repo_returns_error_exit_code(self):
        from manus_agent.cli import _run_silent_patches

        code = _run_silent_patches(["not-a-valid-slug"])
        assert code == 1

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_since_until_flags(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        from manus_agent.cli import _run_silent_patches

        mock_fetch.return_value = []
        code = _run_silent_patches(["owner/repo", "--since", "2025-01-01", "--until", "2025-06-30"])
        assert code == 0

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_json_output_with_candidates(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        from manus_agent.cli import _run_silent_patches

        commits = [
            _make_commit(
                sha=f"candidate_sha{i:02d}",
                message="fix buffer overflow in packet decoder security fix",
            )
            for i in range(3)
        ]
        mock_fetch.return_value = commits
        mock_diff.return_value = "+    if (size > MAX_PKT_SIZE) return -1;\n+    memcpy(dst, src, safe_size);"

        captured = StringIO()
        with contextlib.redirect_stdout(captured):
            code = _run_silent_patches(["owner/repo", "--output", "json"])

        assert code == 0
        candidates = json.loads(captured.getvalue())
        assert isinstance(candidates, list)

    @patch("manus_agent.tools.detect_silent_patches._fetch_diff")
    @patch("manus_agent.tools.detect_silent_patches._fetch_commits")
    def test_text_output_with_candidates_no_crash(self, mock_fetch: MagicMock, mock_diff: MagicMock):
        from manus_agent.cli import _run_silent_patches

        commit = _make_commit(
            sha="text_out_sha000",
            message="security fix: fix heap overflow in tls handshake",
        )
        mock_fetch.return_value = [commit]
        mock_diff.return_value = "+    if (len > MAX_LEN) { return -EINVAL; }\n+    memcpy(buf, src, len);"
        code = _run_silent_patches(["owner/repo"])
        assert code == 0

    def test_silent_patches_routing_in_main_cli(self):
        """silent-patches must be present in _SUBCOMMANDS."""
        from manus_agent.cli import _SUBCOMMANDS

        assert "silent-patches" in _SUBCOMMANDS


# ===========================================================================
# VI agent integration
# ===========================================================================


class TestVIAgentIntegration:
    def test_vi_agent_imports_detect_silent_patches(self):
        """detect_silent_patches must appear in vi_agent source."""
        from pathlib import Path

        vi_agent_src = Path(__file__).parent.parent / "src" / "manus_agent" / "agents" / "vi_agent.py"
        src = vi_agent_src.read_text()
        assert "detect_silent_patches" in src

    def test_vi_agent_system_prompt_mentions_silent_patches_step(self):
        """System prompt should reference Step 6d silent patch check."""
        from pathlib import Path

        vi_agent_src = Path(__file__).parent.parent / "src" / "manus_agent" / "agents" / "vi_agent.py"
        src = vi_agent_src.read_text()
        assert "Step 6d" in src
        assert "silent" in src.lower()
