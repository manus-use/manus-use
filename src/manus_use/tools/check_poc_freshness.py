"""Tool: check_poc_freshness

Given a CVE ID, discovers all known public PoC repositories from
trickest/cve and NVD reference links, then checks GitHub REST API
freshness for each discovered repo.

Status categories:
  active    -- commits within last active_days days
  stale     -- no recent commits but repo exists
  archived  -- owner archived it
  deleted   -- 404 / gone
  framework -- >=5 contributors, >=50 commits, >=10 watchers
  non_github -- non-GitHub URLs
"""

from __future__ import annotations

import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from strands import tool

__all__ = ["check_poc_freshness"]

_CVE_YEAR_RE = re.compile(r"CVE-(\d{4})-\d+", re.IGNORECASE)
_TRICKEST_RAW = "https://raw.githubusercontent.com/trickest/cve/main/{year}/{cve_id}.md"
_GITHUB_REPO_RE = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git|/|$)")
_GITHUB_COMMIT_RE = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/commit/[0-9a-f]+")
_URL_RE = re.compile(r"https?://\S+")

_STATUS_ICON: dict[str, str] = {
    "active": "\U0001f7e2",
    "framework": "\U0001f534",
    "stale": "\U0001f7e1",
    "archived": "\u26aa",
    "deleted": "\u274c",
    "unknown": "\u2753",
}


def _github_token() -> str | None:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def _fetch_json(url: str) -> dict[str, Any] | list[Any] | None:
    import json

    headers: dict[str, str] = {"User-Agent": "manus-use/poc-freshness"}
    token = _github_token()
    if token and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None


def _fetch_text(url: str) -> tuple[int, str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "manus-use/poc-freshness"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except Exception as exc:  # noqa: BLE001
        return -1, str(exc)


def _fetch_trickest_poc_urls(cve_id: str) -> list[str]:
    """Return GitHub PoC repo URLs from trickest/cve."""
    match = _CVE_YEAR_RE.match(cve_id)
    if not match:
        return []
    year = match.group(1)
    url = _TRICKEST_RAW.format(year=year, cve_id=cve_id)
    status, text = _fetch_text(url)
    if status != 200:
        return []
    urls: list[str] = []
    for line in text.splitlines():
        for raw_url in _URL_RE.findall(line):
            raw_url = raw_url.rstrip(")")
            if "github.com" in raw_url and not _GITHUB_COMMIT_RE.match(raw_url):
                m = _GITHUB_REPO_RE.match(raw_url)
                if m:
                    canonical = f"https://github.com/{m.group(1)}/{m.group(2)}"
                    urls.append(canonical)
    return list(dict.fromkeys(urls))


def _fetch_nvd_poc_urls(cve_id: str) -> list[str]:
    """Return GitHub repo URLs referenced in the NVD advisory."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    data = _fetch_json(url)
    if not isinstance(data, dict):
        return []
    try:
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return []
        refs = vulns[0]["cve"].get("references", [])
    except (KeyError, IndexError):
        return []
    urls: list[str] = []
    for ref in refs:
        raw_url: str = ref.get("url", "")
        if "github.com" in raw_url and not _GITHUB_COMMIT_RE.match(raw_url):
            m = _GITHUB_REPO_RE.match(raw_url)
            if m:
                canonical = f"https://github.com/{m.group(1)}/{m.group(2)}"
                urls.append(canonical)
    return list(dict.fromkeys(urls))


def _get_commit_count(owner: str, repo: str) -> int | None:
    """Approximate commit count via GitHub API Link-header pagination."""
    import json as _json

    url = f"https://api.github.com/repos/{owner}/{repo}/commits?per_page=1"
    headers: dict[str, str] = {"User-Agent": "manus-use/poc-freshness"}
    token = _github_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            link_header = resp.getheader("Link", "")
            last_match = re.search(r'page=(\d+)>; rel="last"', link_header)
            if last_match:
                return int(last_match.group(1))
            body = _json.loads(resp.read().decode("utf-8"))
            if isinstance(body, list):
                return len(body)
    except Exception:  # noqa: BLE001
        pass
    return None


def _classify_github_repo(owner: str, repo: str, active_days: int, now: datetime) -> dict[str, Any]:
    """Return freshness record for a single GitHub repo."""
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    data = _fetch_json(api_url)
    record: dict[str, Any] = {
        "url": f"https://github.com/{owner}/{repo}",
        "owner": owner,
        "repo": repo,
        "status": "unknown",
        "last_commit_date": None,
        "days_since_commit": None,
        "stars": None,
        "watchers": None,
        "forks": None,
        "contributors": None,
        "commit_count": None,
        "archived": False,
        "is_framework": False,
        "note": "",
    }
    if not isinstance(data, dict):
        record["status"] = "deleted"
        record["note"] = "Repository returned 404 or network error"
        return record
    archived: bool = bool(data.get("archived", False))
    record["archived"] = archived
    record["stars"] = data.get("stargazers_count", 0)
    record["watchers"] = data.get("watchers_count", 0)
    record["forks"] = data.get("forks_count", 0)
    pushed_at: str | None = data.get("pushed_at")
    if pushed_at:
        try:
            last_push = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
            days_ago = (now - last_push).days
            record["last_commit_date"] = last_push.strftime("%Y-%m-%d")
            record["days_since_commit"] = days_ago
        except ValueError:
            pass
    contribs_url = f"https://api.github.com/repos/{owner}/{repo}/contributors?per_page=100&anon=false"
    contribs_data = _fetch_json(contribs_url)
    if isinstance(contribs_data, list):
        record["contributors"] = len(contribs_data)
    record["commit_count"] = _get_commit_count(owner, repo)
    days_since: int | None = record["days_since_commit"]
    n_contribs: int = record.get("contributors") or 0
    n_commits: int = record.get("commit_count") or 0
    n_watchers: int = record.get("watchers") or 0
    is_framework: bool = n_contribs >= 5 and n_commits >= 50 and n_watchers >= 10
    record["is_framework"] = is_framework
    if archived:
        record["status"] = "archived"
        record["note"] = "Repository was archived by its owner"
    elif is_framework:
        record["status"] = "framework"
        record["note"] = (
            "Grown into a full exploit framework "
            f"({n_contribs} contributors, {n_commits} commits, {n_watchers} watchers)"
        )
    elif days_since is None:
        record["status"] = "unknown"
        record["note"] = "Could not determine last push date"
    elif days_since <= active_days:
        record["status"] = "active"
        record["note"] = f"Last commit {days_since} day(s) ago"
    else:
        record["status"] = "stale"
        record["note"] = f"Last commit {days_since} day(s) ago (>{active_days}-day threshold)"
    return record


def _probe_non_github_url(url: str) -> dict[str, Any]:
    status, _ = _fetch_text(url)
    return {
        "url": url,
        "status": "non_github",
        "http_status": status,
        "note": "accessible" if status == 200 else f"HTTP {status}",
    }


@tool
def check_poc_freshness(cve_id: str, active_days: int = 90) -> str:
    """Check freshness of all known public PoC repos for a CVE.

    For each discovered PoC repository reports one of:
    - active     -- commits within the last active_days days
    - framework  -- grown into a full exploit framework (>=5 contributors,
                    >=50 commits, >=10 watchers)
    - stale      -- exists but no recent commits
    - archived   -- explicitly archived by owner
    - deleted    -- 404 / gone
    - non_github -- non-GitHub URLs (Exploit-DB entries, etc.)

    Sources: trickest/cve index (250k+ CVEs, fast, no rate limit)
    and NVD reference links.

    Args:
        cve_id: CVE identifier, e.g. "CVE-2024-3094".
        active_days: Days within which a last commit counts as active (default: 90).

    Returns:
        Structured text report with per-repo freshness status and summary.
    """
    cve_id = cve_id.strip().upper()
    if not _CVE_YEAR_RE.match(cve_id):
        return f"Invalid CVE ID format: {cve_id!r}. Expected: CVE-YYYY-NNNNN"

    now = datetime.now(tz=timezone.utc)
    cutoff = now - timedelta(days=active_days)

    trickest_urls = _fetch_trickest_poc_urls(cve_id)
    nvd_urls = _fetch_nvd_poc_urls(cve_id)
    all_urls = list(dict.fromkeys(trickest_urls + nvd_urls))

    github_repos: list[str] = []
    other_urls: list[str] = []
    for url in all_urls:
        m = _GITHUB_REPO_RE.match(url)
        if m:
            canonical = f"https://github.com/{m.group(1)}/{m.group(2)}"
            if canonical not in github_repos:
                github_repos.append(canonical)
        elif "github.com" not in url:
            if url not in other_urls:
                other_urls.append(url)

    if not github_repos and not other_urls:
        return (
            f"No public PoC repositories found for {cve_id}.\n\n"
            "Sources checked: trickest/cve index, NVD references.\n"
            "The CVE may be too new, not yet indexed, or have no public PoCs."
        )

    gh_records: list[dict[str, Any]] = []
    for url in github_repos:
        m = _GITHUB_REPO_RE.match(url)
        if m:
            gh_records.append(_classify_github_repo(m.group(1), m.group(2), active_days, now))

    other_records: list[dict[str, Any]] = [_probe_non_github_url(u) for u in other_urls[:10]]

    status_counts: dict[str, int] = {s: 0 for s in ("active", "stale", "archived", "deleted", "framework", "unknown")}
    for r in gh_records:
        st: str = r.get("status", "unknown")
        status_counts[st] = status_counts.get(st, 0) + 1

    lines: list[str] = [
        f"## PoC Freshness Report: {cve_id}",
        "Active threshold : {} days  (cut-off: {})".format(active_days, cutoff.strftime("%Y-%m-%d")),
        "Sources          : trickest/cve, NVD references",
        "Report generated : {}".format(now.strftime("%Y-%m-%d %H:%M UTC")),
        "",
        "### Summary",
        f"  GitHub PoC repos found : {len(gh_records)}",
        "  Active (<={}d)         : {}".format(active_days, status_counts["active"]),
        "  Stale (>{}d)           : {}".format(active_days, status_counts["stale"]),
        "  Archived               : {}".format(status_counts["archived"]),
        "  Deleted / 404          : {}".format(status_counts["deleted"]),
        "  Grown to framework     : {}".format(status_counts["framework"]),
        f"  Non-GitHub URLs        : {len(other_records)}",
        "",
    ]

    active_repos = [r for r in gh_records if r["status"] in ("active", "framework")]
    if active_repos:
        lines.append("WARNING: ACTIVE PoC ACTIVITY DETECTED -- attacker community is still investing in this bug.")
        lines.append("")

    if gh_records:
        lines.append("### GitHub PoC Repositories")
        for r in gh_records:
            icon = _STATUS_ICON.get(r["status"], "?")
            lines.append("{} [{}]  {}".format(icon, r["status"].upper(), r["url"]))
            lines.append("   {}".format(r["note"]))
            meta_parts: list[str] = []
            if r.get("last_commit_date"):
                meta_parts.append("last commit: {}".format(r["last_commit_date"]))
            if r.get("stars") is not None:
                meta_parts.append("stars: {}".format(r["stars"]))
            if r.get("forks") is not None:
                meta_parts.append("forks: {}".format(r["forks"]))
            if r.get("contributors") is not None:
                meta_parts.append("contributors: {}".format(r["contributors"]))
            if r.get("commit_count") is not None:
                meta_parts.append("commits: {}".format(r["commit_count"]))
            if meta_parts:
                lines.append("   ({})".format(", ".join(meta_parts)))
            lines.append("")

    if other_records:
        lines.append("### Non-GitHub PoC URLs")
        for r in other_records:
            ok_str = "OK" if r.get("http_status") == 200 else "DEAD"
            lines.append("[{}] {}  -- {}".format(ok_str, r["url"], r["note"]))
        lines.append("")

    return "\n".join(lines)
