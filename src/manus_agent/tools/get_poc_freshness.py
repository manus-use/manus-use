"""
Tool: get_poc_freshness

PoC freshness checker for a CVE ID.  Measures how recently proof-of-concept
activity occurred by querying multiple public signals:

  1. **GitHub PoC repos** — last-pushed date, star velocity (recently-starred repos)
  2. **Exploit-DB entries** — publication recency of matching exploits
  3. **NVD references** — presence of PoC/exploit-tagged references
  4. **EPSS trend** — recent EPSS score movement as a proxy for attacker interest

The tool computes a **freshness_score** (0–100) that combines:
  - Recency of the most recent PoC activity (40 pts)
  - Number of distinct PoC sources with recent activity (20 pts)
  - Star velocity on GitHub PoC repos (20 pts)
  - EPSS momentum (recent score increase) (20 pts)

A high freshness score means attacker interest is **ongoing** — the CVE is
being actively researched, new exploits are appearing, or repositories are
gaining traction.

CLI: ``manus-agent poc-freshness CVE-XXXX-YYYY``
"""

from __future__ import annotations

import json as _json
import logging
import math
import os
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from strands import tool

__all__ = ["get_poc_freshness"]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"^CVE-(\d{4})-\d+$", re.IGNORECASE)
_GITHUB_API = "https://api.github.com"
_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_EPSS_API = "https://api.first.org/data/v1/epss"
_REQUEST_TIMEOUT = 20  # seconds

# Freshness decay: days -> score multiplier
# Activity within 7 days = full score, decays to near-zero at 365 days.
_FRESHNESS_HALF_LIFE_DAYS = 30  # half-life for exponential decay

# Star velocity: repos pushed in last 90 days with >N stars are "hot"
_STAR_VELOCITY_WINDOW_DAYS = 90
_STAR_VELOCITY_THRESHOLD = 5  # stars to count as meaningful

# EPSS momentum: score increase over last 30 days
_EPSS_MOMENTUM_WINDOW_DAYS = 30

# Exploit-DB CSV cache (shared with search_poc_sources)
_EXPLOITDB_CACHE = "/tmp/exploitdb_cache.csv"
_EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
_EXPLOITDB_CACHE_TTL = 86_400  # 24 hours


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------


def _get(url: str, headers: dict[str, str] | None = None) -> Any:
    """Minimal HTTP GET returning parsed JSON; raises on failure."""
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
        return _json.loads(resp.read().decode())


# ---------------------------------------------------------------------------
# Date helpers
# ---------------------------------------------------------------------------


def _parse_date(date_str: str | None) -> datetime | None:
    """Parse common date formats; return None on failure."""
    if not date_str:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(date_str[:19], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _days_ago(dt: datetime | None) -> float | None:
    """Return number of days between *dt* and now; None if dt is None."""
    if dt is None:
        return None
    now = datetime.now(timezone.utc)
    return max(0.0, (now - dt).total_seconds() / 86_400)


def _decay_score(days: float | None, max_points: float) -> float:
    """Exponential decay: full points at 0 days, half at half-life."""
    if days is None:
        return 0.0
    # Clamp to [0, ∞)
    days = max(0.0, days)
    return max_points * math.exp(-math.log(2) * days / _FRESHNESS_HALF_LIFE_DAYS)


# ---------------------------------------------------------------------------
# Signal 1: GitHub PoC repositories
# ---------------------------------------------------------------------------


def _fetch_github_signals(cve_id: str) -> dict[str, Any]:
    """Query GitHub for PoC repos; return freshness signals."""
    query = urllib.parse.quote(cve_id)
    url = f"{_GITHUB_API}/search/repositories?q={query}&sort=updated&per_page=10"
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    gh_token = os.environ.get("GITHUB_TOKEN", "")
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"

    try:
        data = _get(url, headers=headers)
    except Exception as exc:
        logger.debug("GitHub search failed: %s", exc)
        return {"status": "error", "error": str(exc)}

    items = data.get("items", [])
    if not items:
        return {
            "status": "ok",
            "repo_count": 0,
            "most_recent_push": None,
            "most_recent_push_days_ago": None,
            "hot_repos": 0,
            "total_stars": 0,
            "repos": [],
        }

    now = datetime.now(timezone.utc)
    most_recent_push: datetime | None = None
    hot_repos = 0
    total_stars = 0
    repo_details: list[dict[str, Any]] = []

    for item in items:
        pushed_str = item.get("pushed_at")
        pushed_dt = _parse_date(pushed_str)
        stars = item.get("stargazers_count", 0)
        total_stars += stars

        if pushed_dt and (most_recent_push is None or pushed_dt > most_recent_push):
            most_recent_push = pushed_dt

        # "Hot" = pushed recently AND has meaningful stars
        if pushed_dt:
            days = (now - pushed_dt).total_seconds() / 86_400
            if days <= _STAR_VELOCITY_WINDOW_DAYS and stars >= _STAR_VELOCITY_THRESHOLD:
                hot_repos += 1

        repo_details.append(
            {
                "name": item.get("full_name", ""),
                "url": item.get("html_url", ""),
                "pushed_at": pushed_str,
                "stars": stars,
                "description": (item.get("description") or "")[:120],
            }
        )

    push_days = _days_ago(most_recent_push)

    return {
        "status": "ok",
        "repo_count": len(items),
        "most_recent_push": most_recent_push.isoformat() if most_recent_push else None,
        "most_recent_push_days_ago": round(push_days, 1) if push_days is not None else None,
        "hot_repos": hot_repos,
        "total_stars": total_stars,
        "repos": repo_details,
    }


# ---------------------------------------------------------------------------
# Signal 2: Exploit-DB recency
# ---------------------------------------------------------------------------


def _ensure_exploitdb_cache() -> str | None:
    """Return path to a fresh Exploit-DB CSV, downloading if needed."""
    try:
        mtime = os.path.getmtime(_EXPLOITDB_CACHE)
        if time.time() - mtime < _EXPLOITDB_CACHE_TTL:
            return _EXPLOITDB_CACHE
    except FileNotFoundError:
        pass

    try:
        req = urllib.request.Request(_EXPLOITDB_CSV_URL, headers={"User-Agent": "manus-agent"})
        with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
            data = resp.read()
        with open(_EXPLOITDB_CACHE, "wb") as fh:
            fh.write(data)
        return _EXPLOITDB_CACHE
    except Exception as exc:
        logger.debug("Exploit-DB CSV download failed: %s", exc)
        return None


def _fetch_exploitdb_signals(cve_id: str) -> dict[str, Any]:
    """Check Exploit-DB for matching entries and their recency."""
    import csv

    cache_path = _ensure_exploitdb_cache()
    if not cache_path:
        return {"status": "error", "error": "Exploit-DB CSV unavailable"}

    cve_upper = cve_id.upper()
    entries: list[dict[str, Any]] = []
    most_recent: datetime | None = None

    try:
        with open(cache_path, encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                codes = (row.get("codes") or "").upper()
                if cve_upper not in codes:
                    continue
                date_str = (row.get("date_published") or row.get("date") or "").strip()
                dt = _parse_date(date_str)
                edb_id = (row.get("id") or "").strip()
                title = (row.get("description") or row.get("title") or "").strip()
                entries.append(
                    {
                        "id": edb_id,
                        "title": title[:120],
                        "published": date_str or None,
                    }
                )
                if dt and (most_recent is None or dt > most_recent):
                    most_recent = dt
    except Exception as exc:
        logger.debug("Exploit-DB CSV parse failed: %s", exc)
        return {"status": "error", "error": str(exc)}

    push_days = _days_ago(most_recent)
    return {
        "status": "ok",
        "entry_count": len(entries),
        "most_recent_date": most_recent.strftime("%Y-%m-%d") if most_recent else None,
        "most_recent_days_ago": round(push_days, 1) if push_days is not None else None,
        "entries": entries[:10],  # cap detail output
    }


# ---------------------------------------------------------------------------
# Signal 3: NVD reference tags
# ---------------------------------------------------------------------------


def _fetch_nvd_signals(cve_id: str) -> dict[str, Any]:
    """Check NVD references for Exploit/PoC tags and their recency."""
    url = f"{_NVD_API}?cveId={urllib.parse.quote(cve_id)}"
    headers: dict[str, str] = {}
    nvd_key = os.environ.get("NVD_API_KEY", "")
    if nvd_key:
        headers["apiKey"] = nvd_key

    try:
        data = _get(url, headers=headers)
    except Exception as exc:
        logger.debug("NVD fetch failed: %s", exc)
        return {"status": "error", "error": str(exc)}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {
            "status": "ok",
            "has_poc_refs": False,
            "has_exploit_refs": False,
            "poc_ref_count": 0,
            "exploit_ref_count": 0,
            "published": None,
            "last_modified": None,
            "last_modified_days_ago": None,
        }

    cve_data = vulns[0].get("cve", {})
    published = cve_data.get("published", "")
    last_modified = cve_data.get("lastModified", "")

    poc_refs = 0
    exploit_refs = 0
    for ref in cve_data.get("references", []):
        tags = [t.lower() for t in (ref.get("tags") or [])]
        if "exploit" in tags:
            exploit_refs += 1
        if any("proof" in t or "poc" in t for t in tags):
            poc_refs += 1

    mod_dt = _parse_date(last_modified)
    mod_days = _days_ago(mod_dt)

    return {
        "status": "ok",
        "has_poc_refs": poc_refs > 0,
        "has_exploit_refs": exploit_refs > 0,
        "poc_ref_count": poc_refs,
        "exploit_ref_count": exploit_refs,
        "published": published[:10] if published else None,
        "last_modified": last_modified[:10] if last_modified else None,
        "last_modified_days_ago": (round(mod_days, 1) if mod_days is not None else None),
    }


# ---------------------------------------------------------------------------
# Signal 4: EPSS momentum
# ---------------------------------------------------------------------------


def _fetch_epss_signals(cve_id: str) -> dict[str, Any]:
    """Fetch EPSS time-series and compute momentum (score delta)."""
    url = f"{_EPSS_API}?cve={urllib.parse.quote(cve_id)}&scope=time-series"

    try:
        data = _get(url)
    except Exception as exc:
        logger.debug("EPSS fetch failed: %s", exc)
        return {"status": "error", "error": str(exc)}

    entries = data.get("data", [])
    if not entries:
        return {
            "status": "ok",
            "current_score": None,
            "score_30d_ago": None,
            "momentum": 0.0,
            "percentile": None,
        }

    # EPSS returns entries as [{cve, epss, percentile, date}, ...]
    # Sometimes nested: data[0][...] with time-series in data[0]['time-series']
    # or flat list. Handle both.
    ts_entries: list[dict[str, Any]] = []
    if isinstance(entries, list) and len(entries) > 0:
        first = entries[0]
        if isinstance(first, dict) and "time-series" in first:
            # Nested format
            ts_entries = first.get("time-series", [])
            current_score_str = first.get("epss")
            current_percentile_str = first.get("percentile")
        elif isinstance(first, dict) and "epss" in first and "date" in first:
            # Flat format — each entry has date+epss
            ts_entries = entries
            current_score_str = None
            current_percentile_str = None
        else:
            ts_entries = entries
            current_score_str = None
            current_percentile_str = None

    # Sort by date ascending
    ts_entries.sort(key=lambda e: e.get("date", ""))

    if not ts_entries:
        return {
            "status": "ok",
            "current_score": None,
            "score_30d_ago": None,
            "momentum": 0.0,
            "percentile": None,
        }

    # Current = last entry
    latest = ts_entries[-1]
    current_score = float(latest.get("epss", 0))
    current_percentile = latest.get("percentile")

    # Override with top-level if available
    if current_score_str is not None:
        try:
            current_score = float(current_score_str)
        except (TypeError, ValueError):
            pass
    if current_percentile_str is not None:
        current_percentile = current_percentile_str

    # Find score ~30 days ago
    now = datetime.now(timezone.utc)
    target_date = now.timestamp() - (_EPSS_MOMENTUM_WINDOW_DAYS * 86_400)
    score_30d_ago: float | None = None
    for entry in ts_entries:
        dt = _parse_date(entry.get("date"))
        if dt and dt.timestamp() <= target_date:
            try:
                score_30d_ago = float(entry.get("epss", 0))
            except (TypeError, ValueError):
                pass

    momentum = 0.0
    if score_30d_ago is not None:
        momentum = current_score - score_30d_ago

    return {
        "status": "ok",
        "current_score": round(current_score, 5),
        "score_30d_ago": round(score_30d_ago, 5) if score_30d_ago is not None else None,
        "momentum": round(momentum, 5),
        "percentile": current_percentile,
    }


# ---------------------------------------------------------------------------
# Freshness scoring
# ---------------------------------------------------------------------------


def compute_freshness(
    github: dict[str, Any],
    exploitdb: dict[str, Any],
    nvd: dict[str, Any],
    epss: dict[str, Any],
) -> dict[str, Any]:
    """Compute a 0-100 freshness score from the four signal sources.

    Scoring breakdown (100 total):
      - Recency of most recent PoC activity across sources: 0-40 pts
      - Breadth: number of sources showing recent activity: 0-20 pts
      - Star velocity on GitHub PoC repos: 0-20 pts
      - EPSS momentum (score increase over 30 days): 0-20 pts
    """
    # --- Recency score (40 pts) ---
    # Find the smallest "days ago" across all sources
    days_candidates: list[float] = []
    gh_days = github.get("most_recent_push_days_ago")
    if gh_days is not None:
        days_candidates.append(gh_days)
    edb_days = exploitdb.get("most_recent_days_ago")
    if edb_days is not None:
        days_candidates.append(edb_days)
    nvd_days = nvd.get("last_modified_days_ago")
    if nvd_days is not None:
        days_candidates.append(nvd_days)

    most_recent_days = min(days_candidates) if days_candidates else None
    recency_score = _decay_score(most_recent_days, 40.0)

    # --- Breadth score (20 pts) ---
    # Count sources with "recent" activity (< 90 days)
    recent_threshold = 90.0
    recent_sources = 0
    source_activity: dict[str, bool] = {}

    if gh_days is not None and gh_days <= recent_threshold:
        recent_sources += 1
        source_activity["github"] = True
    else:
        source_activity["github"] = False

    if edb_days is not None and edb_days <= recent_threshold:
        recent_sources += 1
        source_activity["exploitdb"] = True
    else:
        source_activity["exploitdb"] = False

    if nvd_days is not None and nvd_days <= recent_threshold:
        recent_sources += 1
        source_activity["nvd"] = True
    else:
        source_activity["nvd"] = False

    # EPSS positive momentum counts as a source of recent activity
    epss_momentum = epss.get("momentum", 0.0) or 0.0
    if epss_momentum > 0.01:
        recent_sources += 1
        source_activity["epss"] = True
    else:
        source_activity["epss"] = False

    # 4 possible sources -> 5 pts each
    breadth_score = min(20.0, recent_sources * 5.0)

    # --- Star velocity score (20 pts) ---
    hot_repos = github.get("hot_repos", 0) or 0
    total_stars = github.get("total_stars", 0) or 0
    # hot_repos: 0->0, 1->10, 2->15, 3+->20
    star_score = min(20.0, hot_repos * 7.0)
    # Bonus for high total stars even without "hot" repos
    if star_score < 20 and total_stars >= 50:
        star_score = min(20.0, star_score + 5.0)

    # --- EPSS momentum score (20 pts) ---
    # Momentum range: 0.0 (no change) to 0.5+ (massive spike)
    # Scale: 0.05 increase -> 10 pts, 0.10 -> 20 pts
    epss_score = 0.0
    if epss_momentum > 0:
        epss_score = min(20.0, epss_momentum * 200.0)

    total = recency_score + breadth_score + star_score + epss_score
    total = min(100.0, max(0.0, total))

    # Classification
    if total >= 75:
        classification = "critical"
        description = "Very active PoC development — high attacker interest"
    elif total >= 50:
        classification = "high"
        description = "Significant recent PoC activity — elevated risk"
    elif total >= 25:
        classification = "moderate"
        description = "Some PoC activity detected — monitor closely"
    elif total > 0:
        classification = "low"
        description = "Minimal or stale PoC activity"
    else:
        classification = "none"
        description = "No PoC activity detected"

    return {
        "freshness_score": round(total, 1),
        "classification": classification,
        "description": description,
        "breakdown": {
            "recency_points": round(recency_score, 1),
            "breadth_points": round(breadth_score, 1),
            "star_velocity_points": round(star_score, 1),
            "epss_momentum_points": round(epss_score, 1),
        },
        "most_recent_activity_days_ago": (round(most_recent_days, 1) if most_recent_days is not None else None),
        "recent_sources": source_activity,
    }


# ---------------------------------------------------------------------------
# Main aggregation
# ---------------------------------------------------------------------------


def assess_poc_freshness(cve_id: str) -> dict[str, Any]:
    """Run all four signal fetchers and compute freshness score.

    This is the primary entry point for both the Strands tool and the CLI.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    cve_id = cve_id.strip().upper()

    fetchers = {
        "github": (_fetch_github_signals, cve_id),
        "exploitdb": (_fetch_exploitdb_signals, cve_id),
        "nvd": (_fetch_nvd_signals, cve_id),
        "epss": (_fetch_epss_signals, cve_id),
    }

    results: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(fn, arg): name for name, (fn, arg) in fetchers.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                logger.debug("Fetcher %s raised: %s", name, exc)
                results[name] = {"status": "error", "error": str(exc)}

    freshness = compute_freshness(
        github=results.get("github", {}),
        exploitdb=results.get("exploitdb", {}),
        nvd=results.get("nvd", {}),
        epss=results.get("epss", {}),
    )

    return {
        "cve_id": cve_id,
        **freshness,
        "signals": {
            "github": results.get("github", {}),
            "exploitdb": results.get("exploitdb", {}),
            "nvd": results.get("nvd", {}),
            "epss": results.get("epss", {}),
        },
    }


# ---------------------------------------------------------------------------
# Strands tool entry point
# ---------------------------------------------------------------------------


@tool
def get_poc_freshness(cve_id: str) -> dict:
    """Measure PoC freshness for a CVE — how recently exploit activity occurred.

    Queries GitHub PoC repos, Exploit-DB, NVD references, and EPSS trends
    to compute a 0-100 freshness score. A high score means attacker interest
    is ongoing: new exploits are appearing, repositories are gaining traction,
    or EPSS scores are rising.

    Args:
        cve_id: CVE identifier (e.g. CVE-2024-3094).

    Returns:
        Dictionary with freshness_score (0-100), classification
        (critical/high/moderate/low/none), breakdown by signal source,
        and detailed per-source data.
    """
    cve_id = cve_id.strip()
    if not _CVE_RE.match(cve_id):
        return {
            "error": f"Invalid CVE identifier: {cve_id!r}",
            "cve_id": cve_id,
            "freshness_score": 0,
            "classification": "none",
            "description": "Invalid CVE ID",
            "breakdown": {
                "recency_points": 0,
                "breadth_points": 0,
                "star_velocity_points": 0,
                "epss_momentum_points": 0,
            },
            "most_recent_activity_days_ago": None,
            "recent_sources": {},
            "signals": {},
        }

    return assess_poc_freshness(cve_id)
