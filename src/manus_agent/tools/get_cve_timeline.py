"""
Tool for reconstructing the event timeline of a CVE.

Aggregates NVD publish date -> EPSS first-seen & peak date -> CISA KEV add date
(when present) -> patch release date (from OSV.dev), and computes time-to-patch
and time-to-exploit deltas so analysts can judge exploitation velocity at a glance.

All HTTP calls degrade gracefully -- missing data sources produce null fields
rather than failures.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import requests
from strands.types.tools import ToolResult, ToolUse

from manus_agent.tools.tool_output_logger import log_tool_output_size

TOOL_SPEC = {
    "name": "get_cve_timeline",
    "description": (
        "Reconstructs the full event timeline for a CVE: NVD publish date -> EPSS first-seen "
        "date -> EPSS peak score date -> CISA KEV add date (if exploited in the wild) -> patch "
        "release date from OSV.dev. Returns time-to-patch and time-to-kev deltas so you can "
        "judge how quickly the vulnerability was weaponised and fixed. Use after get_nvd_data "
        "to get temporal context for exploitation velocity."
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier to reconstruct the timeline for, e.g. CVE-2021-44228.",
                },
            },
            "required": ["cve_id"],
        }
    },
}

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
_EPSS_URL = "https://api.first.org/data/v1/epss"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_OSV_URL = "https://api.osv.dev/v1/query"


def _fetch_nvd_meta(cve_id: str) -> dict[str, Any]:
    """Return the NVD cve sub-object for cve_id, or empty dict on failure."""
    headers = {"apiKey": _NVD_API_KEY} if _NVD_API_KEY else {}
    try:
        resp = requests.get(
            _NVD_URL,
            params={"cveId": cve_id.upper()},
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        return vulns[0]["cve"] if vulns else {}
    except Exception:
        return {}


def _fetch_epss_series(cve_id: str) -> list[dict[str, str]]:
    """Return the full EPSS daily time-series for cve_id (oldest-first)."""
    try:
        resp = requests.get(
            _EPSS_URL,
            params={"cve": cve_id.upper(), "scope": "time-series", "limit": 365},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json().get("data", [])
        if not data:
            return []
        series = data[0].get("time-series", [])
        return sorted(series, key=lambda p: p.get("date", ""))
    except Exception:
        return []


def _analyse_epss(series: list[dict[str, str]]) -> dict[str, Any]:
    """Derive first-seen date, peak date, peak score, and current score."""
    if not series:
        return {
            "first_seen_date": None,
            "peak_date": None,
            "peak_score": None,
            "current_score": None,
        }
    first = series[0]
    peak = max(series, key=lambda p: float(p.get("epss", "0")))
    current = series[-1]
    return {
        "first_seen_date": first.get("date"),
        "peak_date": peak.get("date"),
        "peak_score": float(peak.get("epss", "0")),
        "current_score": float(current.get("epss", "0")),
    }


def _fetch_kev_entry(cve_id: str) -> dict[str, Any]:
    """Return the KEV entry for cve_id, or empty dict if absent or request fails."""
    try:
        resp = requests.get(_KEV_URL, timeout=15)
        resp.raise_for_status()
        for vuln in resp.json().get("vulnerabilities", []):
            if vuln.get("cveID") == cve_id.upper():
                return vuln
        return {}
    except Exception:
        return {}


def _fetch_osv_patch_date(cve_id: str) -> str | None:
    """
    Query OSV.dev for the earliest fixed semver event modified date.

    Returns a YYYY-MM-DD string, or None when no OSV data is available.
    """
    try:
        resp = requests.post(
            _OSV_URL,
            json={"query": {"id": cve_id}},
            timeout=15,
        )
        resp.raise_for_status()
        vulns = resp.json().get("vulns", [])
        candidate_dates: list[str] = []
        for vuln in vulns:
            has_fixed = any(
                "fixed" in event
                for affected in vuln.get("affected", [])
                for rng in affected.get("ranges", [])
                for event in rng.get("events", [])
            )
            if has_fixed and vuln.get("modified"):
                candidate_dates.append(vuln["modified"][:10])
        return min(candidate_dates) if candidate_dates else None
    except Exception:
        return None


def _days_between(date_a: str | None, date_b: str | None) -> int | None:
    """Return (date_b - date_a) in whole days, or None when either is missing."""
    if not date_a or not date_b:
        return None
    try:
        da = datetime.fromisoformat(date_a[:10]).replace(tzinfo=timezone.utc)
        db = datetime.fromisoformat(date_b[:10]).replace(tzinfo=timezone.utc)
        return (db - da).days
    except ValueError:
        return None


def _build_timeline(cve_id: str) -> dict[str, Any]:
    """Fetch all sources and assemble the timeline dict."""
    cve_upper = cve_id.upper()

    nvd = _fetch_nvd_meta(cve_upper)
    nvd_published = nvd.get("published", "")[:10] if nvd.get("published") else None
    nvd_modified = nvd.get("lastModified", "")[:10] if nvd.get("lastModified") else None
    nvd_status = nvd.get("vulnStatus")
    descriptions = nvd.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)

    cvss_score: float | None = None
    cvss_severity: str | None = None
    for mkey in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = nvd.get("metrics", {}).get(mkey, [])
        if metrics:
            cvss_score = metrics[0].get("cvssData", {}).get("baseScore")
            cvss_severity = metrics[0].get("cvssData", {}).get("baseSeverity")
            break

    series = _fetch_epss_series(cve_upper)
    epss = _analyse_epss(series)

    kev = _fetch_kev_entry(cve_upper)
    kev_added = kev.get("dateAdded") if kev else None
    kev_due = kev.get("dueDate") if kev else None
    kev_vendor = kev.get("vendorProject") if kev else None
    kev_product = kev.get("product") if kev else None
    kev_action = kev.get("requiredAction") if kev else None

    patch_date = _fetch_osv_patch_date(cve_upper)

    time_to_kev = _days_between(nvd_published, kev_added)
    time_to_patch = _days_between(nvd_published, patch_date)
    time_to_epss_peak = _days_between(nvd_published, epss.get("peak_date"))

    return {
        "cve_id": cve_upper,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "nvd_status": nvd_status,
        "timeline": {
            "nvd_published": nvd_published,
            "nvd_last_modified": nvd_modified,
            "epss_first_seen": epss.get("first_seen_date"),
            "epss_peak_date": epss.get("peak_date"),
            "epss_peak_score": epss.get("peak_score"),
            "epss_current_score": epss.get("current_score"),
            "kev_added": kev_added,
            "kev_due_date": kev_due,
            "patch_released": patch_date,
        },
        "kev_details": {
            "vendor": kev_vendor,
            "product": kev_product,
            "required_action": kev_action,
        }
        if kev
        else None,
        "deltas": {
            "days_nvd_to_kev": time_to_kev,
            "days_nvd_to_patch": time_to_patch,
            "days_nvd_to_epss_peak": time_to_epss_peak,
        },
    }


def get_cve_timeline(tool: ToolUse, **kwargs: Any) -> ToolResult:
    tool_use_id = tool["toolUseId"]
    cve_id: str = tool["input"].get("cve_id", "").strip()

    if not cve_id or not cve_id.upper().startswith("CVE-"):
        result: ToolResult = {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": "Invalid CVE ID. Must be a string like CVE-YYYY-NNNN."}],
        }
        log_tool_output_size("get_cve_timeline", result)
        return result

    try:
        timeline = _build_timeline(cve_id)
        result = {
            "toolUseId": tool_use_id,
            "status": "success",
            "content": [{"json": timeline}],
        }
        log_tool_output_size("get_cve_timeline", result)
        return result
    except Exception as exc:
        result = {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": f"Timeline reconstruction failed: {exc}"}],
        }
        log_tool_output_size("get_cve_timeline", result)
        return result
