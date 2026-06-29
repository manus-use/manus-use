"""
Tool for computing a time-aware, composite vulnerability urgency score.

Combines CVSS base severity, EPSS exploitation probability (with spike-recency
decay), CISA KEV membership, patch availability, and CVE age into a single
0-100 urgency score.  Answers the practical question:

    "Of everything I know about this CVE *right now*, how urgently should I act?"

Score bands
-----------
  CRITICAL  80-100  Act immediately.  High CVSS + actively exploited/spiking.
  HIGH      60-79   Patch/mitigate in days.  Strong exploitation signal.
  MEDIUM    40-59   Schedule for next maintenance window.
  LOW        0-39   Monitor; standard patch cycle.

Scoring formula (max 100 points)
---------------------------------
Component                      Max pts  Notes
─────────────────────────────  ───────  ──────────────────────────────────────
CVSS base score                   25    linear scale (score/10 * 25)
EPSS current score                20    linear scale (epss * 20)
EPSS spike recency                15    spike_score * decay(days_since_spike)
CISA KEV membership               20    in-KEV = 20, not-in-KEV = 0
Patch unavailability              10    no-patch/unknown = 10, patch = 0
CVE age pressure                  10    rises from 0→10 over 0-365 days
"""

from __future__ import annotations

import concurrent.futures
import math
from datetime import date, datetime, timezone
from typing import Any

import requests
from strands.types.tools import ToolResult, ToolUse

from manus_use.tools.tool_output_logger import log_tool_output_size

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

_SPIKE_THRESHOLD = 0.10  # same threshold as get_epss_trend
_SPIKE_HALF_LIFE_DAYS = 30.0  # urgency from a spike halves every 30 days
_AGE_MAX_DAYS = 365  # beyond this age, age-pressure is capped at 10
_EPSS_HISTORY_DAYS = 90  # how far back to look for spike recency


# ──────────────────────────────────────────────────────────────────────────────
# Tool spec
# ──────────────────────────────────────────────────────────────────────────────

TOOL_SPEC = {
    "name": "score_temporal_priority",
    "description": (
        "Computes a time-aware, composite urgency score (0-100) for a CVE by combining "
        "CVSS severity, current EPSS exploitation probability, EPSS spike recency (with "
        "exponential decay so a 3-day-old spike counts more than a 6-month-old one), "
        "CISA KEV membership (actively exploited in the wild), patch availability, and "
        "CVE publication age. "
        "Returns the urgency score, a CRITICAL/HIGH/MEDIUM/LOW label, and a ranked "
        "breakdown of every scoring component so analysts understand exactly what is "
        "driving the number. Use after get_nvd_data to decide *how urgently* to act. "
        "Pairs naturally with compare_cves (which CVE is worse) and "
        "score_exploit_complexity (how hard to weaponise)."
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier (e.g., 'CVE-2021-44228').",
                },
                "output": {
                    "type": "string",
                    "enum": ["text", "json"],
                    "description": "Return format.  'text' (default) returns a human-readable report; 'json' returns raw data.",
                    "default": "text",
                },
            },
            "required": ["cve_id"],
        }
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# Data-fetch helpers
# ──────────────────────────────────────────────────────────────────────────────


def _today() -> date:
    return datetime.now(tz=timezone.utc).date()


def _fetch_nvd(cve_id: str) -> dict[str, Any]:
    """Fetch NVD data for *cve_id* and return a normalised subset."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    try:
        resp = requests.get(url, params={"cveId": cve_id.upper()}, timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return {"error": str(exc)}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {"error": f"CVE {cve_id} not found in NVD"}

    cve = vulns[0].get("cve", {})
    published_str = cve.get("published", "")

    # CVSS — prefer v3.1, then v3.0, then v2
    metrics = cve.get("metrics", {})
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_version: str | None = None
    attack_vector: str | None = None

    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            m = metrics[key][0].get("cvssData", {})
            cvss_score = m.get("baseScore")
            cvss_severity = m.get("baseSeverity")
            cvss_version = m.get("version")
            attack_vector = m.get("attackVector")
            break
    if cvss_score is None and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        m = metrics["cvssMetricV2"][0].get("cvssData", {})
        cvss_score = m.get("baseScore")
        cvss_severity = metrics["cvssMetricV2"][0].get("baseSeverity")
        cvss_version = "2.0"

    # Patch availability: scan NVD references for commit / advisory / patch signals
    refs = cve.get("references", [])
    patch_signals = 0
    for ref in refs:
        url_lower = (ref.get("url") or "").lower()
        tags = [t.lower() for t in ref.get("tags", [])]
        if any(kw in url_lower for kw in ("/commit/", "/releases/tag/", "/compare/", "/advisory/", "patch", "fix")):
            patch_signals += 1
        if any(t in tags for t in ("patch", "release", "fix", "vendor-advisory")):
            patch_signals += 1

    # Parse published date
    published_date: date | None = None
    if published_str:
        try:
            published_date = datetime.fromisoformat(published_str.rstrip("Z")).date()
        except ValueError:
            pass

    return {
        "cve_id": cve_id.upper(),
        "published_date": published_date.isoformat() if published_date else None,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_version": cvss_version,
        "attack_vector": attack_vector,
        "patch_signals": patch_signals,
        "description": (cve.get("descriptions") or [{}])[0].get("value", "")[:200],
    }


def _fetch_epss(cve_id: str, days: int = _EPSS_HISTORY_DAYS) -> dict[str, Any]:
    """Fetch EPSS current score and time-series spike analysis."""
    url = "https://api.first.org/data/v1/epss"
    try:
        resp = requests.get(
            url,
            params={"cve": cve_id.upper(), "scope": "time-series", "limit": days},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return {"error": str(exc)}

    entries = data.get("data", [])
    if not entries:
        return {"error": "no EPSS data"}

    entry = entries[0]
    current_epss = float(entry.get("epss", 0))
    current_percentile = float(entry.get("percentile", 0))
    current_date_str = entry.get("date", "")

    # Merge current point into series
    series = list(entry.get("time-series", []))
    if current_date_str and not any(p.get("date") == current_date_str for p in series):
        series.insert(0, {"date": current_date_str, "epss": str(current_epss), "percentile": str(current_percentile)})

    # Find the most recent spike (7-day jump ≥ threshold)
    pts_sorted = sorted(series, key=lambda x: x["date"])
    scores = [(p["date"], float(p["epss"])) for p in pts_sorted]

    spike_date: str | None = None
    max_spike_magnitude: float = 0.0
    for i in range(len(scores) - 1):
        for j in range(i + 1, min(i + 8, len(scores))):
            delta = scores[j][1] - scores[i][1]
            if delta >= _SPIKE_THRESHOLD and delta > max_spike_magnitude:
                max_spike_magnitude = delta
                spike_date = scores[j][0]

    days_since_spike: int | None = None
    if spike_date:
        try:
            spike_dt = datetime.fromisoformat(spike_date).date()
            days_since_spike = (_today() - spike_dt).days
        except ValueError:
            pass

    return {
        "current_epss": current_epss,
        "current_percentile": current_percentile,
        "spike_detected": spike_date is not None,
        "spike_magnitude": round(max_spike_magnitude, 6),
        "spike_date": spike_date,
        "days_since_spike": days_since_spike,
    }


def _fetch_kev(cve_id: str) -> dict[str, Any]:
    """Check CISA KEV for *cve_id*."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        catalog = resp.json()
    except Exception as exc:
        return {"error": str(exc), "in_kev": False}

    target = cve_id.upper()
    for vuln in catalog.get("vulnerabilities", []):
        if vuln.get("cveID", "").upper() == target:
            return {
                "in_kev": True,
                "date_added": vuln.get("dateAdded"),
                "due_date": vuln.get("dueDate"),
                "required_action": vuln.get("requiredAction"),
                "vendor_project": vuln.get("vendorProject"),
                "product": vuln.get("product"),
            }
    return {"in_kev": False}


# ──────────────────────────────────────────────────────────────────────────────
# Scoring engine
# ──────────────────────────────────────────────────────────────────────────────


def _spike_decay(days_since: int) -> float:
    """Exponential decay: halves every *_SPIKE_HALF_LIFE_DAYS* days. Returns 0-1."""
    return math.exp(-math.log(2) * days_since / _SPIKE_HALF_LIFE_DAYS)


def _compute_score(
    nvd: dict[str, Any],
    epss: dict[str, Any],
    kev: dict[str, Any],
) -> dict[str, Any]:
    """
    Return a dict with per-component scores, totals, and explanations.

    All sub-scores are floats; urgency_score is rounded to 1 decimal place.
    """
    components: list[dict[str, Any]] = []

    # ── 1. CVSS base score (max 25) ──────────────────────────────────────────
    cvss_raw = nvd.get("cvss_score")
    if cvss_raw is not None:
        cvss_pts = round((float(cvss_raw) / 10.0) * 25.0, 2)
        sev = nvd.get("cvss_severity") or "?"
        av_note = f", attack-vector={nvd['attack_vector']}" if nvd.get("attack_vector") else ""
        components.append(
            {
                "name": "CVSS base score",
                "score": cvss_pts,
                "max": 25,
                "detail": f"CVSS {cvss_raw} ({sev}){av_note}",
            }
        )
    else:
        components.append(
            {
                "name": "CVSS base score",
                "score": 0.0,
                "max": 25,
                "detail": "Not available",
            }
        )

    # ── 2. EPSS current (max 20) ──────────────────────────────────────────────
    current_epss = epss.get("current_epss", 0.0) if not epss.get("error") else 0.0
    epss_pts = round(current_epss * 20.0, 2)
    pct = epss.get("current_percentile", 0.0) or 0.0
    components.append(
        {
            "name": "EPSS current score",
            "score": epss_pts,
            "max": 20,
            "detail": f"EPSS={current_epss:.4f} ({float(pct):.1%} percentile)"
            if not epss.get("error")
            else "Not available",
        }
    )

    # ── 3. EPSS spike recency (max 15) ────────────────────────────────────────
    spike_pts = 0.0
    spike_detail = "No significant spike detected"
    if not epss.get("error") and epss.get("spike_detected"):
        days_since = epss.get("days_since_spike")
        magnitude = epss.get("spike_magnitude", 0.0)
        if days_since is not None:
            decay = _spike_decay(days_since)
            # Raw spike score: magnitude relative to threshold, capped at 1.0
            raw = min(magnitude / _SPIKE_THRESHOLD, 2.0) / 2.0  # 0→1 scale
            spike_pts = round(raw * decay * 15.0, 2)
            spike_detail = (
                f"Spike +{magnitude:.4f} detected {days_since}d ago (decay factor {decay:.2f} → {spike_pts:.1f} pts)"
            )
        else:
            # spike date unknown; use full weight
            spike_pts = round(min(magnitude / _SPIKE_THRESHOLD, 2.0) / 2.0 * 15.0, 2)
            spike_detail = f"Spike +{magnitude:.4f} detected (date unknown)"

    components.append(
        {
            "name": "EPSS spike recency",
            "score": spike_pts,
            "max": 15,
            "detail": spike_detail,
        }
    )

    # ── 4. CISA KEV (max 20) ─────────────────────────────────────────────────
    in_kev = kev.get("in_kev", False)
    kev_pts = 20.0 if in_kev else 0.0
    if in_kev:
        kev_detail = f"In CISA KEV — added {kev.get('date_added', '?')}, due {kev.get('due_date', '?')}"
    elif kev.get("error"):
        kev_detail = f"KEV lookup failed: {kev['error']}"
    else:
        kev_detail = "Not in CISA KEV"
    components.append(
        {
            "name": "CISA KEV membership",
            "score": kev_pts,
            "max": 20,
            "detail": kev_detail,
        }
    )

    # ── 5. Patch unavailability (max 10) ─────────────────────────────────────
    patch_signals = nvd.get("patch_signals", 0)
    if patch_signals >= 2:
        patch_pts = 0.0
        patch_detail = f"Patch likely available ({patch_signals} NVD patch signals)"
    elif patch_signals == 1:
        patch_pts = 5.0
        patch_detail = "Patch status uncertain (1 NVD patch signal)"
    else:
        patch_pts = 10.0
        patch_detail = "No patch signals in NVD references"
    components.append(
        {
            "name": "Patch unavailability",
            "score": patch_pts,
            "max": 10,
            "detail": patch_detail,
        }
    )

    # ── 6. CVE age pressure (max 10) ─────────────────────────────────────────
    age_pts = 0.0
    age_detail = "Publication date unavailable"
    published_str = nvd.get("published_date")
    if published_str:
        try:
            pub_date = date.fromisoformat(published_str)
            age_days = (_today() - pub_date).days
            # Linear ramp from 0→10 over 0-365 days
            age_pts = round(min(age_days / _AGE_MAX_DAYS, 1.0) * 10.0, 2)
            age_detail = f"Published {pub_date} ({age_days}d ago)"
        except ValueError:
            pass
    components.append(
        {
            "name": "CVE age pressure",
            "score": age_pts,
            "max": 10,
            "detail": age_detail,
        }
    )

    # ── Totals ────────────────────────────────────────────────────────────────
    total = round(sum(c["score"] for c in components), 1)
    total = min(total, 100.0)

    if total >= 80:
        label = "CRITICAL"
    elif total >= 60:
        label = "HIGH"
    elif total >= 40:
        label = "MEDIUM"
    else:
        label = "LOW"

    return {
        "cve_id": nvd.get("cve_id", ""),
        "urgency_score": total,
        "label": label,
        "components": sorted(components, key=lambda c: c["score"], reverse=True),
        "description": nvd.get("description", ""),
        "cvss_score": nvd.get("cvss_score"),
        "cvss_severity": nvd.get("cvss_severity"),
        "current_epss": current_epss,
        "in_kev": in_kev,
        "spike_detected": epss.get("spike_detected", False),
        "days_since_spike": epss.get("days_since_spike"),
        "published_date": nvd.get("published_date"),
        "patch_signals": nvd.get("patch_signals", 0),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Text renderer
# ──────────────────────────────────────────────────────────────────────────────

_LABEL_ICON = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
}

_ADVICE = {
    "CRITICAL": "Act immediately — patch, isolate, or mitigate within hours.",
    "HIGH": "Prioritise patching within 1-3 days.",
    "MEDIUM": "Schedule for next maintenance window.",
    "LOW": "Monitor; patch on standard cycle.",
}


def _render_text(result: dict[str, Any]) -> str:
    cve = result["cve_id"]
    score = result["urgency_score"]
    label = result["label"]
    icon = _LABEL_ICON.get(label, "")
    advice = _ADVICE.get(label, "")

    sep = "─" * 72
    lines: list[str] = [
        "",
        sep,
        f"  Temporal Priority Score  —  {cve}",
        sep,
        f"  Urgency Score : {score:>5.1f} / 100  {icon} {label}",
        f"  Advice        : {advice}",
        "",
        f"  {'COMPONENT':<28}  {'PTS':>6}  {'MAX':>4}  DETAIL",
        f"  {'─' * 28}  {'─' * 6}  {'─' * 4}  {'─' * 28}",
    ]
    for comp in result["components"]:
        lines.append(f"  {comp['name']:<28}  {comp['score']:>6.1f}  {comp['max']:>4}  {comp['detail']}")

    lines += [
        sep,
    ]

    if result.get("description"):
        lines.append(f"\n  Description: {result['description']}")

    return "\n".join(lines) + "\n"


# ──────────────────────────────────────────────────────────────────────────────
# Strands tool entry point
# ──────────────────────────────────────────────────────────────────────────────


def score_temporal_priority(tool: ToolUse, **kwargs: Any) -> ToolResult:
    """Compute a time-aware composite urgency score for a CVE."""
    tool_use_id = tool["toolUseId"]
    tool_input = tool["input"]

    cve_id = str(tool_input.get("cve_id", "")).strip().upper()
    output_fmt = str(tool_input.get("output", "text")).lower()

    if not cve_id.startswith("CVE-"):
        result: ToolResult = {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": f"Invalid CVE ID '{cve_id}'. Must be like 'CVE-YYYY-NNNN'."}],
        }
        log_tool_output_size("score_temporal_priority", result)
        return result

    # Fan-out: fetch all three sources in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_nvd = executor.submit(_fetch_nvd, cve_id)
        future_epss = executor.submit(_fetch_epss, cve_id)
        future_kev = executor.submit(_fetch_kev, cve_id)
        nvd = future_nvd.result()
        epss = future_epss.result()
        kev = future_kev.result()

    if nvd.get("error"):
        result = {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": f"NVD lookup failed for {cve_id}: {nvd['error']}"}],
        }
        log_tool_output_size("score_temporal_priority", result)
        return result

    scored = _compute_score(nvd, epss, kev)

    if output_fmt == "json":
        result = {
            "toolUseId": tool_use_id,
            "status": "success",
            "content": [{"json": scored}],
        }
    else:
        text_report = _render_text(scored)
        result = {
            "toolUseId": tool_use_id,
            "status": "success",
            "content": [
                {"text": text_report},
                {"json": scored},
            ],
        }

    log_tool_output_size("score_temporal_priority", result)
    return result
