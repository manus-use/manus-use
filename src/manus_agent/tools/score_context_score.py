"""
Tool: score_context_score

Produces a single composite **contextual risk score** (0–100) for a CVE by
combining six independent signal dimensions:

1. **epss**         — current EPSS probability from FIRST.org (0.0–1.0 → 0–25 pts)
2. **cvss_base**    — NVD CVSS v3 base score (0–10 → 0–20 pts)
3. **exploit_complexity** — NVD Attack Complexity / Privileges Required (→ 0–15 pts)
4. **epss_spike**   — EPSS spike detected in the last 30 days (0 or 10 pts)
5. **blast_radius** — downstream exposure from NVD CPE affected-version count (0–15 pts)
6. **kev_listed**   — CISA KEV catalogue membership (0 or 15 pts hard bonus)

A **KEV-listed CVE always receives +15** regardless of other scores, meaning
an otherwise low-scoring CVE with active exploitation is never under-rated.

Scores are bucketed into four risk tiers:

  CRITICAL  ≥ 80   — drop everything, patch or mitigate now
  HIGH      ≥ 60   — high urgency, schedule within hours/days
  MEDIUM    ≥ 40   — elevated, schedule within your normal cadence
  LOW       < 40   — monitor; address in next maintenance window

The tool is useful as a *triage normaliser* when you have a queue of CVEs and
need a single comparable number that goes beyond raw CVSS severity.

All HTTP calls degrade gracefully: a failed data source contributes 0 to its
dimension, so the scorer always returns a result.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

import requests
from strands import tool

__all__ = ["score_context_score"]

# ---------------------------------------------------------------------------
# Dimension weights — must sum to 1.0
# ---------------------------------------------------------------------------

_WEIGHTS: dict[str, float] = {
    "epss": 0.25,
    "cvss_base": 0.20,
    "exploit_complexity": 0.15,
    "epss_spike": 0.10,
    "blast_radius": 0.15,
    "kev_listed": 0.15,
}

assert abs(sum(_WEIGHTS.values()) - 1.0) < 1e-9, "Dimension weights must sum to 1.0"

# Max raw points each dimension contributes BEFORE weighting
_MAX_RAW: dict[str, float] = {
    "epss": 100.0,  # epss probability × 100 → up to 100 pts
    "cvss_base": 100.0,  # base_score / 10 × 100 → up to 100 pts
    "exploit_complexity": 100.0,  # multi-factor NVD signal → up to 100 pts
    "epss_spike": 100.0,  # binary: 100 if spike, else 0
    "blast_radius": 100.0,  # CPE count-derived bucket → up to 100 pts
    "kev_listed": 100.0,  # binary: 100 if on KEV, else 0
}

# KEV cache — same path convention as check_cisa_kev.py
_KEV_CACHE_FILE = Path(__file__).parent / ".cisa_kev_cache.json"
_KEV_CACHE_DURATION = 3600  # seconds


# ---------------------------------------------------------------------------
# Data-fetch helpers (all tolerant of network failures)
# ---------------------------------------------------------------------------


def _fetch_nvd(cve_id: str) -> dict[str, Any]:
    """Return NVD CVE record dict (vulnerabilities[0].cve) or {}."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        if vulns:
            return vulns[0].get("cve", {})
    except requests.RequestException:
        pass
    return {}


def _fetch_epss(cve_id: str) -> dict[str, Any]:
    """Return EPSS current score dict or {}."""
    url = "https://api.first.org/data/v1/epss"
    try:
        resp = requests.get(url, params={"cve": cve_id.upper()}, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        rows = data.get("data", [])
        if rows:
            return rows[0]
    except requests.RequestException:
        pass
    return {}


def _fetch_epss_series(cve_id: str, days: int = 30) -> list[dict[str, Any]]:
    """Return EPSS time-series list (oldest-first) for spike detection."""
    url = "https://api.first.org/data/v1/epss"
    try:
        resp = requests.get(
            url,
            params={"cve": cve_id.upper(), "scope": "time-series", "limit": min(days, 365)},
            timeout=15,
        )
        resp.raise_for_status()
        raw = resp.json().get("data", [])
        # API returns rows with "epss", "percentile", "date"; sort oldest-first
        return sorted(
            [{"date": r["date"], "epss": float(r["epss"])} for r in raw if "epss" in r and "date" in r],
            key=lambda x: x["date"],
        )
    except requests.RequestException:
        pass
    return []


def _fetch_kev(cve_id: str) -> bool:
    """Return True if *cve_id* is in the CISA KEV catalogue."""
    # Try cache first
    if _KEV_CACHE_FILE.exists():
        try:
            cached = json.loads(_KEV_CACHE_FILE.read_text())
            if time.time() - cached.get("timestamp", 0) < _KEV_CACHE_DURATION:
                vulns = cached.get("data", {}).get("vulnerabilities", [])
                return any(v.get("cveID") == cve_id.upper() for v in vulns)
        except (json.JSONDecodeError, OSError):
            pass

    try:
        resp = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        try:
            _KEV_CACHE_FILE.write_text(json.dumps({"timestamp": time.time(), "data": data}))
        except OSError:
            pass
        return any(v.get("cveID") == cve_id.upper() for v in data.get("vulnerabilities", []))
    except requests.RequestException:
        pass
    return False


# ---------------------------------------------------------------------------
# Dimension scorers (each returns a raw value 0–100)
# ---------------------------------------------------------------------------


def _dim_epss(epss_row: dict[str, Any]) -> float:
    """EPSS probability × 100 → 0–100."""
    try:
        return min(float(epss_row.get("epss", 0)) * 100.0, 100.0)
    except (TypeError, ValueError):
        return 0.0


def _dim_cvss_base(nvd: dict[str, Any]) -> float:
    """CVSS v3 base score / 10 × 100 → 0–100."""
    metrics = nvd.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            score = entries[0].get("cvssData", {}).get("baseScore")
            if score is not None:
                return min(float(score) / 10.0 * 100.0, 100.0)
    return 0.0


def _dim_exploit_complexity(nvd: dict[str, Any]) -> float:
    """
    Combine Attack Complexity (AC) + Privileges Required (PR) + User Interaction (UI)
    into an attacker-friendliness signal.  Counter-intuitively: LOW complexity is
    WORSE for defenders, so we invert the score.

    Mapping (raw 0–100 before weighting, higher = more dangerous):
      AC=LOW  → +40   AC=HIGH → +0
      PR=NONE → +35   PR=LOW  → +20   PR=HIGH → +0
      UI=NONE → +25   UI=REQUIRED → +0
    Max = 100 (AC=LOW, PR=NONE, UI=NONE)
    """
    metrics = nvd.get("metrics", {})
    cv: dict[str, Any] = {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            cv = entries[0].get("cvssData", {})
            break

    ac = cv.get("attackComplexity", "").upper()
    pr = cv.get("privilegesRequired", "").upper()
    ui = cv.get("userInteraction", "").upper()

    score = 0.0
    score += 40.0 if ac == "LOW" else 0.0
    score += {"NONE": 35.0, "LOW": 20.0, "HIGH": 0.0}.get(pr, 0.0)
    score += 25.0 if ui == "NONE" else 0.0
    return score


def _dim_epss_spike(series: list[dict[str, Any]]) -> float:
    """100 if a ≥0.10 EPSS jump detected in the last 30 days, else 0."""
    if len(series) < 2:
        return 0.0
    scores = [p["epss"] for p in series]
    # Largest 7-day rolling jump
    for i in range(len(scores) - 1, max(0, len(scores) - 30), -1):
        lo = max(0, i - 7)
        if scores[i] - scores[lo] >= 0.10:
            return 100.0
    return 0.0


def _dim_blast_radius(nvd: dict[str, Any]) -> float:
    """
    Estimate blast radius from the number of distinct CPE configurations
    affected by this CVE.  More configurations → more exposure.

    Buckets (raw 0–100):
      0 CPEs      → 0
      1–2 CPEs    → 20
      3–9 CPEs    → 40
      10–29 CPEs  → 60
      30–99 CPEs  → 80
      ≥100 CPEs   → 100
    """
    try:
        configs = nvd.get("configurations", [])
        cpe_count = sum(len(node.get("cpeMatch", [])) for cfg in configs for node in cfg.get("nodes", []))
    except (TypeError, AttributeError):
        cpe_count = 0

    if cpe_count == 0:
        return 0.0
    if cpe_count <= 2:
        return 20.0
    if cpe_count <= 9:
        return 40.0
    if cpe_count <= 29:
        return 60.0
    if cpe_count <= 99:
        return 80.0
    return 100.0


def _dim_kev(kev_listed: bool) -> float:
    """100 if on CISA KEV, else 0."""
    return 100.0 if kev_listed else 0.0


# ---------------------------------------------------------------------------
# Composite calculation
# ---------------------------------------------------------------------------


def _risk_tier(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _compute_composite(dims_raw: dict[str, float]) -> float:
    """Weighted average of raw 0–100 dimension scores → composite 0–100."""
    total = sum(_WEIGHTS[k] * dims_raw[k] for k in _WEIGHTS)
    return round(total, 1)


def _run_context_score(cve_id: str) -> dict[str, Any]:
    """Execute the full scoring pipeline for *cve_id* and return a result dict."""
    cve_id = cve_id.upper().strip()

    # ── Fetch all data sources in parallel (sequentially for simplicity) ─────
    nvd = _fetch_nvd(cve_id)
    epss_row = _fetch_epss(cve_id)
    epss_series = _fetch_epss_series(cve_id, days=30)
    kev_listed = _fetch_kev(cve_id)

    # ── Raw dimension scores (each 0–100) ─────────────────────────────────────
    dims_raw: dict[str, float] = {
        "epss": _dim_epss(epss_row),
        "cvss_base": _dim_cvss_base(nvd),
        "exploit_complexity": _dim_exploit_complexity(nvd),
        "epss_spike": _dim_epss_spike(epss_series),
        "blast_radius": _dim_blast_radius(nvd),
        "kev_listed": _dim_kev(kev_listed),
    }

    # ── Weighted composite ────────────────────────────────────────────────────
    composite = _compute_composite(dims_raw)
    tier = _risk_tier(composite)

    # ── Identify the dominant factor ─────────────────────────────────────────
    weighted = {k: _WEIGHTS[k] * dims_raw[k] for k in _WEIGHTS}
    dominant = max(weighted, key=lambda k: weighted[k])

    # ── Confidence: how many dimensions returned non-zero data? ──────────────
    live_dims = sum(1 for v in dims_raw.values() if v > 0)
    if live_dims >= 4:
        confidence = "HIGH"
    elif live_dims >= 2:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    # ── One-sentence natural-language verdict ─────────────────────────────────
    kev_note = " Actively exploited in the wild (CISA KEV)." if kev_listed else ""
    risk_summary = (
        f"{cve_id} is rated {tier} (score {composite}/100) based on "
        f"{'high' if dims_raw['epss'] >= 50 else 'low'} EPSS probability, "
        f"{'available' if dims_raw['exploit_complexity'] >= 50 else 'limited'} exploit access, "
        f"and {'wide' if dims_raw['blast_radius'] >= 60 else 'narrow'} blast radius.{kev_note}"
    )

    return {
        "cve_id": cve_id,
        "composite_score": composite,
        "risk_tier": tier,
        "dominant_factor": dominant,
        "confidence": confidence,
        "risk_summary": risk_summary,
        "kev_listed": kev_listed,
        "dimensions": {
            k: {
                "raw_score": dims_raw[k],
                "weight": _WEIGHTS[k],
                "weighted_contribution": round(_WEIGHTS[k] * dims_raw[k], 2),
            }
            for k in _WEIGHTS
        },
        "epss_current": float(epss_row.get("epss", 0)) if epss_row else None,
        "epss_percentile": float(epss_row.get("percentile", 0)) if epss_row else None,
        "nvd_available": bool(nvd),
    }


def _render_text(result: dict[str, Any]) -> str:
    """Return a human-readable text report."""
    cve = result["cve_id"]
    tier = result["risk_tier"]
    score = result["composite_score"]
    kev = result["kev_listed"]
    confidence = result["confidence"]

    lines = [
        f"Contextual Risk Score: {cve}",
        "=" * 58,
        f"  Composite score : {score}/100",
        f"  Risk tier       : {tier}",
        f"  Dominant factor : {result['dominant_factor']}",
        f"  Confidence      : {confidence} ({sum(1 for d in result['dimensions'].values() if d['raw_score'] > 0)}/6 dimensions live)",
    ]
    if kev:
        lines.append("  ⚠  CISA KEV      : YES — actively exploited in the wild")
    else:
        lines.append("  CISA KEV        : not listed")
    lines += [
        "",
        result["risk_summary"],
        "",
        "Dimension breakdown",
        "-" * 58,
    ]
    dim_labels = {
        "epss": "EPSS probability",
        "cvss_base": "CVSS v3 base score",
        "exploit_complexity": "Exploit complexity (attacker-friendly)",
        "epss_spike": "EPSS spike (last 30 days)",
        "blast_radius": "Blast radius (CPE coverage)",
        "kev_listed": "CISA KEV listing",
    }
    for key, label in dim_labels.items():
        d = result["dimensions"][key]
        raw = d["raw_score"]
        wt = d["weighted_contribution"]
        lines.append(f"  {label:<42}: raw {raw:5.1f}  → +{wt:4.1f} pts  (wt {_WEIGHTS[key]:.0%})")

    lines += [
        "",
        "Risk tiers:  CRITICAL ≥80  |  HIGH ≥60  |  MEDIUM ≥40  |  LOW <40",
    ]

    if result.get("epss_current") is not None:
        lines.append(f"EPSS current: {result['epss_current']:.4f}  (percentile {result['epss_percentile']:.4f})")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Strands tool entry point
# ---------------------------------------------------------------------------

TOOL_SPEC = {
    "name": "score_context_score",
    "description": (
        "Produces a composite contextual risk score (0–100) for a CVE by combining six "
        "independent signal dimensions: EPSS probability, CVSS v3 base score, exploit "
        "complexity (attacker-friendliness from NVD CVSS vector), EPSS spike detection "
        "(>0.10 jump in 30 days), blast radius (CPE configuration count), and CISA KEV "
        "listing. A KEV-listed CVE receives a hard +15 bonus (weight 0.15) regardless of "
        "other scores. Output is a risk tier (CRITICAL/HIGH/MEDIUM/LOW), a dominant-factor "
        "field, a confidence level (HIGH/MEDIUM/LOW), and a one-sentence risk summary. "
        "Use this to triage a queue of CVEs with a single comparable number that goes "
        "beyond raw CVSS severity."
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier to score (e.g., 'CVE-2021-44228').",
                },
                "output": {
                    "type": "string",
                    "enum": ["text", "json"],
                    "description": "Output format: 'text' (default) or 'json'.",
                },
                "weights": {
                    "type": "object",
                    "description": (
                        "Optional JSON object to override dimension weights. Keys: epss, cvss_base, "
                        "exploit_complexity, epss_spike, blast_radius, kev_listed. "
                        "Values are floats; they will be normalised to sum to 1.0."
                    ),
                },
            },
            "required": ["cve_id"],
        }
    },
}


@tool
def score_context_score(cve_id: str, output: str = "text", weights: dict[str, float] | None = None) -> str:
    """Produce a composite contextual risk score (0–100) for a CVE.

    Combines six dimensions: EPSS probability, CVSS base, exploit complexity,
    EPSS spike, blast radius, and CISA KEV listing (hard +15 bonus when listed).

    Args:
        cve_id:  CVE identifier (e.g. 'CVE-2021-44228').
        output:  'text' (default) or 'json'.
        weights: Optional dict to override dimension weights; auto-normalised.

    Returns:
        Formatted risk report string.
    """
    if not isinstance(cve_id, str) or not re.match(r"CVE-\d{4}-\d+", cve_id, re.IGNORECASE):
        return "Error: cve_id must be a valid CVE identifier like 'CVE-2021-44228'."

    # Apply weight overrides if provided
    if weights:
        global _WEIGHTS  # noqa: PLW0603
        merged = dict(_WEIGHTS)
        for k, v in weights.items():
            if k in merged and isinstance(v, (int, float)) and v >= 0:
                merged[k] = float(v)
        total = sum(merged.values())
        if total > 0:
            _WEIGHTS = {k: v / total for k, v in merged.items()}

    result = _run_context_score(cve_id)

    if output == "json":
        return json.dumps(result, indent=2)

    return _render_text(result)
