"""
Tool: detect_silent_patches

Scans a GitHub repository's commit history for security fixes that were never
assigned a CVE — the so-called "silent patches" that slip through the public
disclosure pipeline.

Two-stage heuristic:

  Stage 1 — commit message keywords
    Score each commit subject/body against a weighted keyword vocabulary.
    Commits that reach the message threshold advance to stage 2.

  Stage 2 — diff keywords  (skipped when ``fast=True``)
    Fetch the unified diff for each stage-1 candidate and score it against a
    second keyword vocabulary targeting dangerous code patterns (memory safety,
    auth bypass, injection sinks, etc.).  The combined score determines whether
    the commit is a *confirmed candidate*.

Each confirmed candidate is labelled with one of 14 bug classes:

  auth_bypass, buffer_overflow, use_after_free, integer_overflow,
  injection, path_traversal, information_disclosure, denial_of_service,
  race_condition, memory_leak, null_deref, crypto_weakness,
  privilege_escalation, format_string

Graceful degradation:
  - Works without a GITHUB_TOKEN (60 req/h unauthenticated vs 5 000 req/h
    authenticated).  A missing token only reduces throughput.
  - The ``max_commits`` cap prevents runaway pagination.

CLI: ``manus-agent silent-patches owner/repo``
     ``manus-agent silent-patches owner/repo --since 2025-01-01 --fast``
     ``manus-agent silent-patches owner/repo --output json | jq .[].classification``
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from strands import tool

__all__ = ["detect_silent_patches"]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TIMEOUT = 20
_GITHUB_API = "https://api.github.com"

# ---------------------------------------------------------------------------
# Stage 1 — commit message keyword scoring
# ---------------------------------------------------------------------------
# Each entry: (pattern, weight)  — pattern matched case-insensitively.
# A commit that reaches MSG_THRESHOLD advances to stage 2 (or is kept when
# fast=True).

_MSG_THRESHOLD = 3

_MSG_KEYWORDS: list[tuple[str, int]] = [
    # strong security signals (weight 4)
    (r"security[\s_-]?fix", 4),
    (r"fix[\s_-]?security", 4),
    (r"\bvulnerabilit", 4),
    (r"\bexploit\b", 4),
    (r"remote[\s_-]code[\s_-]exec", 4),
    (r"\brce\b", 4),
    (r"privilege[\s_-]escal", 4),
    (r"\bsandbox[\s_-]escape\b", 4),
    # memory-safety (weight 3)
    (r"use[\s_-]after[\s_-]free", 3),
    (r"\buaf\b", 3),
    (r"heap[\s_-](overflow|corrupt|spray)", 3),
    (r"stack[\s_-]overflow", 3),
    (r"buffer[\s_-]over(flow|read|write)", 3),
    (r"out[\s_-]of[\s_-]bounds", 3),
    (r"\boob\b", 3),
    (r"integer[\s_-]over(flow|wrap)", 3),
    (r"null[\s_-](ptr|pointer)[\s_-]deref", 3),
    (r"\bdouble[\s_-]free\b", 3),
    (r"memory[\s_-]corrupt", 3),
    (r"type[\s_-]confusion", 3),
    # auth / access control (weight 3)
    (r"auth(?:entic|oriz)[\w\s_-]*bypass", 3),
    (r"bypass[\s_-]auth", 3),
    (r"access[\s_-]control[\s_-]fix", 3),
    (r"unauthori[sz]ed[\s_-]access", 3),
    # injection (weight 3)
    (r"sql[\s_-]inject", 3),
    (r"command[\s_-]inject", 3),
    (r"\bxss\b", 3),
    (r"path[\s_-]trav", 3),
    (r"directory[\s_-]trav", 3),
    (r"ldap[\s_-]inject", 3),
    # crypto (weight 2)
    (r"insecure[\s_-](random|crypto|hash|cipher)", 2),
    (r"weak[\s_-](key|cipher|hash|rand)", 2),
    (r"timing[\s_-]attack", 2),
    # generic fix signals (weight 2)
    (r"fix[\s_-](crash|hang|panic|assert)", 2),
    (r"prevent[\s_-](arbitrary|code|exec|inject)", 2),
    (r"sanitize|sanitise", 2),
    (r"harden\b", 2),
    (r"mitigat", 2),
    # weak generic signals (weight 1)
    (r"\bfix\b", 1),
    (r"\bpatch\b", 1),
]

_COMPILED_MSG: list[tuple[re.Pattern[str], int]] = [(re.compile(pat, re.IGNORECASE), w) for pat, w in _MSG_KEYWORDS]

# ---------------------------------------------------------------------------
# Stage 2 — diff keyword scoring
# ---------------------------------------------------------------------------

_DIFF_THRESHOLD = 2

_DIFF_KEYWORDS: list[tuple[str, int]] = [
    # memory safety
    (r"free\(", 2),
    (r"malloc\(|calloc\(|realloc\(", 1),
    (r"memcpy\(|memmove\(|memset\(", 1),
    (r"strcpy\(|strcat\(|sprintf\(", 2),
    (r"__builtin_expect|overflow_check", 1),
    # bounds / checks added
    (r"if\s*\(.*len.*>|if\s*\(.*size.*>", 1),
    (r"bounds_check|range_check|check_len", 2),
    # auth
    (r"authenticated|authorized|privilege", 2),
    (r"capabilities|cap_\w+", 1),
    # injection sinks
    (r"exec\s*\(|system\s*\(|popen\s*\(", 2),
    (r"eval\s*\(|pickle\.loads|yaml\.load\b", 2),
    (r"cursor\.execute|raw\s*query", 2),
    (r"innerHTML|document\.write|eval\s*\(", 2),
    # crypto
    (r"RAND_pseudo_bytes|rand\(\)|srand\(", 2),
    (r"MD5|SHA1|RC4|DES\b", 1),
    # path
    (r"\.\./|%2e%2e|path\.join.*\.\.", 2),
    # format string
    (r'printf\s*\(\s*[^"\']\w', 2),
]

_COMPILED_DIFF: list[tuple[re.Pattern[str], int]] = [(re.compile(pat, re.IGNORECASE), w) for pat, w in _DIFF_KEYWORDS]

# ---------------------------------------------------------------------------
# Bug class classification (14 classes)
# ---------------------------------------------------------------------------

_BUG_CLASSES: list[tuple[str, list[str]]] = [
    ("auth_bypass", ["auth.*bypass", "bypass.*auth", "unauthori[sz]ed"]),
    ("buffer_overflow", ["buffer.*over(flow|read|write)", "heap.*overflow", "oob", "out.of.bounds"]),
    ("use_after_free", ["use.after.free", r"\buaf\b", "double.free"]),
    ("integer_overflow", ["integer.*over(flow|wrap)", "int.*overflow"]),
    ("injection", ["sql.inject", "command.inject", r"\bxss\b", "ldap.inject", "code.inject"]),
    ("path_traversal", ["path.trav", "directory.trav", r"\.\./", "%2e%2e"]),
    ("information_disclosure", ["info.*leak", "data.*leak", "disclosure", "info.*expos"]),
    ("denial_of_service", [r"\bdos\b", "denial.of.service", "crash", "hang", "infinite.loop"]),
    ("race_condition", ["race.condition", "data.race", "toctou", "use.after"]),
    ("memory_leak", ["memory.leak", "resource.leak", "leak"]),
    ("null_deref", ["null.ptr", "null.pointer", "deref", "null.deref"]),
    ("crypto_weakness", ["insecure.rand", "weak.cipher", "timing.attack", "weak.key", "weak.hash"]),
    ("privilege_escalation", ["privilege.escal", "privesc", "sandbox.escape", "setuid"]),
    ("format_string", ["format.string", r"printf\s*\(\s*\w", "fmt.str"]),
]

_COMPILED_CLASSES: list[tuple[str, list[re.Pattern[str]]]] = [
    (cls, [re.compile(pat, re.IGNORECASE) for pat in pats]) for cls, pats in _BUG_CLASSES
]


def _classify_bug(text: str) -> str:
    """Return the best-matching bug class for *text*, or 'unknown'."""
    for cls, patterns in _COMPILED_CLASSES:
        for pat in patterns:
            if pat.search(text):
                return cls
    return "unknown"


# ---------------------------------------------------------------------------
# GitHub helpers
# ---------------------------------------------------------------------------


def _github_headers() -> dict[str, str]:
    token = os.environ.get("GITHUB_TOKEN")
    headers: dict[str, str] = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def _fetch_commits(
    owner: str,
    repo: str,
    since: str,
    until: str,
    max_commits: int,
) -> list[dict[str, Any]]:
    """Paginate GitHub commits API up to *max_commits*."""
    headers = _github_headers()
    url = f"{_GITHUB_API}/repos/{owner}/{repo}/commits"
    params: dict[str, Any] = {"since": since, "until": until, "per_page": min(100, max_commits)}
    commits: list[dict[str, Any]] = []

    while url and len(commits) < max_commits:
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=_TIMEOUT)
            resp.raise_for_status()
        except requests.RequestException as exc:
            logger.warning("GitHub commits fetch failed: %s", exc)
            break

        batch = resp.json()
        if not isinstance(batch, list):
            logger.warning("Unexpected GitHub API response: %r", batch)
            break
        commits.extend(batch)
        params = {}  # only on first request

        # Pagination via Link header
        link = resp.headers.get("Link", "")
        next_url_match = re.search(r'<([^>]+)>;\s*rel="next"', link)
        url = next_url_match.group(1) if next_url_match else ""

    return commits[:max_commits]


def _fetch_diff(owner: str, repo: str, sha: str) -> str:
    """Return the unified diff text for a commit, or '' on failure."""
    headers = _github_headers()
    headers["Accept"] = "application/vnd.github.v3.diff"
    url = f"{_GITHUB_API}/repos/{owner}/{repo}/commits/{sha}"
    try:
        resp = requests.get(url, headers=headers, timeout=_TIMEOUT)
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as exc:
        logger.warning("Diff fetch failed for %s: %s", sha, exc)
        return ""


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------


def _score_message(message: str) -> int:
    """Return the cumulative keyword score for a commit message."""
    score = 0
    for pat, weight in _COMPILED_MSG:
        if pat.search(message):
            score += weight
    return score


def _score_diff(diff_text: str) -> int:
    """Return the cumulative keyword score for a diff."""
    score = 0
    for pat, weight in _COMPILED_DIFF:
        # Count occurrences rather than just presence for diff signals
        matches = pat.findall(diff_text)
        if matches:
            score += weight
    return score


# ---------------------------------------------------------------------------
# Strands tool
# ---------------------------------------------------------------------------

_TOOL_DESC = (
    "Scans a GitHub repository's commit history for security fixes that were never "
    "assigned a CVE ('silent patches'). Uses a two-stage heuristic: Stage 1 scores "
    "commit messages against a weighted security keyword vocabulary; Stage 2 fetches "
    "and scores the unified diff for stage-1 candidates. Each candidate is labelled "
    "with one of 14 bug classes (auth_bypass, buffer_overflow, use_after_free, etc.). "
    "Returns a list of candidate commits ranked by combined score. "
    "Gracefully degrades without a GITHUB_TOKEN (rate-limited to 60 req/h). "
    "Set fast=true to skip Stage 2 diff scoring for faster results. "
    "Use after get_nvd_data to cross-check: if a commit already has a CVE reference "
    "in its message, it is excluded from results."
)


@tool
def detect_silent_patches(  # noqa: C901
    repo: str,
    since: str | None = None,
    until: str | None = None,
    max_commits: int = 500,
    fast: bool = False,
) -> dict[str, Any]:
    """Detect silent security patches in a GitHub repository.

    Args:
        repo: ``owner/repo`` string, e.g. ``"torvalds/linux"``.
        since: ISO 8601 start date, e.g. ``"2025-01-01"``.  Defaults to 90 days ago.
        until: ISO 8601 end date, e.g. ``"2025-06-30"``.  Defaults to today.
        max_commits: Hard cap on commits fetched.  Default 500.
        fast: Skip Stage 2 diff scoring for faster (but noisier) results.

    Returns:
        dict with keys:
          - ``repo``: repository slug
          - ``since`` / ``until``: effective date range
          - ``commits_scanned``: total commits fetched
          - ``candidates``: list of confirmed silent-patch candidates (sorted by score)
          - ``summary``: one-line text summary
    """
    # ---- Validate + defaults -------------------------------------------
    repo_stripped = repo.strip()
    if "/" not in repo_stripped:
        return {
            "error": f"Invalid repo format: {repo_stripped!r}. Expected 'owner/repo'.",
            "candidates": [],
        }

    owner, repo_name = repo_stripped.split("/", 1)

    now = datetime.now(tz=timezone.utc)
    if not since:
        since = (now - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        # Normalise bare dates to ISO 8601 timestamps
        if re.match(r"^\d{4}-\d{2}-\d{2}$", since):
            since = since + "T00:00:00Z"

    if not until:
        until = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        if re.match(r"^\d{4}-\d{2}-\d{2}$", until):
            until = until + "T23:59:59Z"

    max_commits = max(1, min(max_commits, 2000))

    # ---- Fetch commits ---------------------------------------------------
    commits = _fetch_commits(owner, repo_name, since, until, max_commits)
    total_scanned = len(commits)

    # ---- Stage 1: message scoring ----------------------------------------
    stage1: list[dict[str, Any]] = []
    for c in commits:
        commit_data = c.get("commit", {})
        message: str = commit_data.get("message", "") or ""
        subject = message.splitlines()[0] if message else ""

        # Skip commits that already mention a CVE — these are *not* silent.
        if re.search(r"\bCVE-\d{4}-\d+\b", message, re.IGNORECASE):
            continue

        msg_score = _score_message(message)
        if msg_score < _MSG_THRESHOLD:
            continue

        sha = c.get("sha", "")
        author_info = commit_data.get("author") or {}
        committer_info = commit_data.get("committer") or {}
        html_url = c.get("html_url", "")

        stage1.append(
            {
                "sha": sha,
                "subject": subject,
                "message": message,
                "msg_score": msg_score,
                "author": author_info.get("name", ""),
                "date": author_info.get("date") or committer_info.get("date", ""),
                "url": html_url,
            }
        )

    # ---- Stage 2: diff scoring (unless fast) -----------------------------
    candidates: list[dict[str, Any]] = []
    for c in stage1:
        diff_score = 0
        if not fast:
            diff_text = _fetch_diff(owner, repo_name, c["sha"])
            diff_score = _score_diff(diff_text)

        combined = c["msg_score"] + diff_score
        threshold = _MSG_THRESHOLD if fast else (_MSG_THRESHOLD + _DIFF_THRESHOLD - 1)
        if combined < threshold:
            continue

        # Bug class: classify on subject + message
        classification = _classify_bug(c["subject"] + " " + c["message"])

        candidates.append(
            {
                "sha": c["sha"][:12],
                "sha_full": c["sha"],
                "subject": c["subject"],
                "date": c["date"],
                "author": c["author"],
                "url": c["url"],
                "msg_score": c["msg_score"],
                "diff_score": diff_score,
                "combined_score": combined,
                "classification": classification,
                "fast_mode": fast,
            }
        )

    # Sort by combined score descending
    candidates.sort(key=lambda x: x["combined_score"], reverse=True)

    count = len(candidates)
    summary = (
        f"Found {count} silent-patch candidate(s) in {repo_stripped} "
        f"({total_scanned} commits scanned, {since[:10]} – {until[:10]})"
    )

    return {
        "repo": repo_stripped,
        "since": since,
        "until": until,
        "commits_scanned": total_scanned,
        "candidates": candidates,
        "summary": summary,
    }
