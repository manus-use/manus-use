"""
Tool: score_context_score

Composite risk meta-scorer that aggregates multiple independent signals into a
single 0–100 contextual risk score for a CVE.

Dimensions (configurable weights, must sum to 1.0):

1. **exploit_complexity** (weight 0.30) — how hard is it for an attacker to
   weaponise this?  Derived from ``score_exploit_complexity``.
   Score is *inverted*: low complexity = high risk contribution.

2. **epss_momentum** (weight 0.25) — how aggressively is exploitation
   probability rising?  Derived from ``get_epss_trend``'s current EPSS score
   and spike/trend signals.

3. **blast_radius** (weight 0.25) — how many downstream packages/projects are
   exposed?  Derived from ``get_dependency_blast_radius``.

4. **attack_surface** (weight 0.10) — how exposed is the component in a
   typical deployment?  Uses ``score_attack_surface`` when available (PR #82);
   falls back to NVD CVSS Attack Vector.

5. **patch_lag** (weight 0.10) — has a patch been shipped?  How quickly?
   Uses ``get_patch_status`` when available (PR #81); degrades gracefully.

Output:
  - ``context_score`` — float 0–100 (higher = more urgent)
  - ``risk_label``    — CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
  - ``dimensions``    — per-dimension contribution (0–100 each, + weight + source)
  - ``dominant_factor`` — name of the highest-contributing dimension
  - ``risk_summary``  — one-sentence natural-language verdict
  - ``confidence``    — HIGH / MEDIUM / LOW (how many dimensions had live data)

All HTTP calls are mockable — no side effects in unit tests.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import requests
from strands import tool

__all__ = ["score_context_score"]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default dimension weights — must sum to 1.0
# ---------------------------------------------------------------------------

_DEFAULT_WEIGHTS: dict[str, float] = {
    "exploit_complexity": 0.30,
    "epss_momentum": 0.25,
    "blast_radius": 0.25,
    "attack_surface": 0.10,
    "patch_lag": 0.10,
}

# Risk label thresholds (0–100 scale)
_RISK_THRESHOLDS: list[tuple[float, str]] = [
    (80.0, "CRITICAL"),
    (60.0, "HIGH"),
    (40.0, "MEDIUM"),
    (20.0, "LOW"),
    (0.0, "INFORMATIONAL"),
]

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
_TIMEOUT = 20

# NVD endpoint (reuse same URL pattern as other tools)
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_EPSS_URL = "https://api.first.org/data/v1/epss"
_OSV_QUERY_URL = "https://api.osv.dev/v1/query"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


def _risk_label(score: float) -> str:
    for threshold, label in _RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "INFORMATIONAL"


def _validate_weights(weights: dict[str, float]) -> dict[str, float]:
    """Return a normalised copy of *weights* that sums to 1.0."""
    total = sum(weights.values())
    if total <= 0:
        return _DEFAULT_WEIGHTS.copy()
    return {k: v / total for k, v in weights.items()}


# ---------------------------------------------------------------------------
# Dimension 1 — Exploit Complexity (inverted: lower complexity = higher risk)
# ---------------------------------------------------------------------------


def _fetch_nvd_cvss(cve_id: str) -> dict[str, Any]:
    """Return CVSS data dict from NVD, or empty dict on failure."""
    try:
        r = requests.get(_NVD_URL, params={"cveId": cve_id.upper()}, timeout=_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {}
        cve = vulns[0].get("cve", {})
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                return entries[0].get("cvssData", {})
        return {}
    except Exception as exc:
        logger.debug("NVD CVSS fetch failed for %s: %s", cve_id, exc)
        return {}


def _score_exploit_complexity_dimension(cve_id: str) -> dict[str, Any]:
    """
    Return a 0–100 contribution for exploit complexity.

    Tries to import and call ``_run_scoring`` from the sibling tool.
    Falls back to a pure NVD CVSS heuristic if that import fails or errors.
    """
    try:
        from manus_agent.tools.score_exploit_complexity import _run_scoring

        result = _run_scoring(cve_id)
        raw_score = result.get("complexity_score", 3.0)  # 1–5
        # Invert: complexity 1 (trivial) → risk 100; complexity 5 (hard) → risk 0
        risk_contribution = _clamp((5.0 - raw_score) / 4.0 * 100)
        return {
            "score": round(risk_contribution, 1),
            "raw": round(raw_score, 2),
            "label": result.get("complexity_label", "unknown"),
            "attacker_friendly": result.get("attacker_friendly", False),
            "poc_found": result.get("poc_found", False),
            "source": "score_exploit_complexity",
            "available": True,
        }
    except Exception as exc:
        logger.debug("score_exploit_complexity unavailable: %s", exc)

    # Fallback: CVSS AV / PR heuristic
    cvss = _fetch_nvd_cvss(cve_id)
    if cvss:
        av = cvss.get("attackVector", "NETWORK")
        pr = cvss.get("privilegesRequired", "NONE")
        av_score = {"NETWORK": 80, "ADJACENT": 55, "LOCAL": 35, "PHYSICAL": 15}.get(av, 50)
        pr_bump = {"NONE": 15, "LOW": 5, "HIGH": -10}.get(pr, 0)
        risk_contribution = _clamp(av_score + pr_bump)
        return {
            "score": round(risk_contribution, 1),
            "raw": None,
            "label": "heuristic",
            "attacker_friendly": risk_contribution >= 70,
            "poc_found": False,
            "source": "nvd_cvss_heuristic",
            "available": True,
        }

    return {
        "score": 50.0,
        "raw": None,
        "label": "unknown",
        "attacker_friendly": None,
        "poc_found": False,
        "source": "default_fallback",
        "available": False,
    }


# ---------------------------------------------------------------------------
# Dimension 2 — EPSS Momentum
# ---------------------------------------------------------------------------


def _fetch_epss_current(cve_id: str) -> dict[str, Any]:
    """Return current EPSS score + trend for *cve_id*."""
    try:
        # Current score
        r = requests.get(_EPSS_URL, params={"cve": cve_id.upper()}, timeout=_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        items = data.get("data", [])
        if not items:
            return {}
        item = items[0]
        return {
            "epss": float(item.get("epss", 0)),
            "percentile": float(item.get("percentile", 0)),
        }
    except Exception as exc:
        logger.debug("EPSS current fetch failed for %s: %s", cve_id, exc)
        return {}


def _fetch_epss_series(cve_id: str, days: int = 30) -> dict[str, Any]:
    """Return trend/spike info from EPSS time-series.  Uses internal helper."""
    try:
        from manus_agent.tools.get_epss_trend import _analyse_series, _fetch_epss_time_series

        raw = _fetch_epss_time_series(cve_id, days)
        series = raw.get("data", [])
        if not series:
            return {}
        return _analyse_series(series)
    except Exception as exc:
        logger.debug("EPSS trend fetch failed for %s: %s", cve_id, exc)
        return {}


def _score_epss_momentum_dimension(cve_id: str) -> dict[str, Any]:
    """
    0–100 contribution based on EPSS score + momentum signals.

    Formula:
      base    = current_epss * 80        (EPSS 0→0, EPSS 1→80)
      spike   = +15 if spike_detected
      rising  = +10 if trend == "rising", -5 if "falling"
      cap at 100
    """
    current = _fetch_epss_current(cve_id)
    trend_data = _fetch_epss_series(cve_id)

    epss_val = current.get("epss", 0.0)
    percentile = current.get("percentile", 0.0)
    spike_detected = trend_data.get("spike_detected", False)
    trend = trend_data.get("trend", "unknown")
    max_7d_jump = trend_data.get("max_7d_jump", 0.0)

    base = _clamp(epss_val * 80)
    spike_bonus = 15.0 if spike_detected else 0.0
    trend_adj = 10.0 if trend == "rising" else (-5.0 if trend == "falling" else 0.0)
    risk_contribution = _clamp(base + spike_bonus + trend_adj)

    available = bool(current)
    return {
        "score": round(risk_contribution, 1),
        "epss": round(epss_val, 6),
        "percentile": round(percentile, 4),
        "spike_detected": spike_detected,
        "trend": trend,
        "max_7d_jump": round(max_7d_jump, 6),
        "source": "get_epss_trend" if trend_data else "epss_current_only",
        "available": available,
    }


# ---------------------------------------------------------------------------
# Dimension 3 — Blast Radius
# ---------------------------------------------------------------------------

# Qualitative label → 0–100 score mapping
_BLAST_LABEL_SCORE: dict[str, float] = {
    "CRITICAL": 100.0,
    "HIGH": 75.0,
    "MEDIUM": 50.0,
    "LOW": 25.0,
    "UNKNOWN": 20.0,  # unknown is not zero — we simply lack data
}


def _score_blast_radius_dimension(cve_id: str) -> dict[str, Any]:
    """0–100 contribution based on dependency blast radius label."""
    try:
        from manus_agent.tools.get_dependency_blast_radius import (
            _blast_score,
            _enrich_package,
            _fetch_ghsa_affected,
            _fetch_nvd_affected,
            _fetch_osv_affected,
        )

        # Gather affected packages (same logic as the main tool)
        nvd_pkgs = _fetch_nvd_affected(cve_id)
        osv_pkgs = _fetch_osv_affected(cve_id)
        ghsa_pkgs = _fetch_ghsa_affected(cve_id)

        seen: dict[tuple, dict] = {}
        for pkg in osv_pkgs + ghsa_pkgs + nvd_pkgs:
            key = (pkg["name"].lower(), (pkg.get("ecosystem") or "").lower())
            if key not in seen:
                seen[key] = pkg
        packages = list(seen.values())

        if not packages:
            return {
                "score": 20.0,
                "blast_label": "UNKNOWN",
                "packages_found": 0,
                "source": "get_dependency_blast_radius",
                "available": True,
            }

        # Enrich first package only (fast path for scoring)
        first = packages[0]
        stats = _enrich_package(first.get("name", ""), first.get("ecosystem", ""))
        blast_label = _blast_score(stats)
        risk_contribution = _BLAST_LABEL_SCORE.get(blast_label, 20.0)

        return {
            "score": round(risk_contribution, 1),
            "blast_label": blast_label,
            "packages_found": len(packages),
            "weekly_downloads": stats.get("weekly_downloads"),
            "dependent_packages_count": stats.get("dependent_packages_count"),
            "source": "get_dependency_blast_radius",
            "available": True,
        }
    except Exception as exc:
        logger.debug("get_dependency_blast_radius unavailable: %s", exc)

    return {
        "score": 20.0,
        "blast_label": "UNKNOWN",
        "packages_found": 0,
        "source": "default_fallback",
        "available": False,
    }


# ---------------------------------------------------------------------------
# Dimension 4 — Attack Surface
# ---------------------------------------------------------------------------

# CVSS Attack Vector → 0–100 surface score
_AV_SURFACE_SCORE: dict[str, float] = {
    "NETWORK": 85.0,
    "ADJACENT": 55.0,
    "LOCAL": 30.0,
    "PHYSICAL": 10.0,
}


def _score_attack_surface_dimension(cve_id: str) -> dict[str, Any]:
    """
    0–100 contribution based on deployment exposure.

    Prefers ``score_attack_surface`` (PR #82) when available; falls back to
    NVD CVSS Attack Vector + scope heuristic.
    """
    # Try the dedicated tool first
    try:
        from manus_agent.tools.score_attack_surface import _run_scoring as _run_surface

        result = _run_surface(cve_id)
        # score_attack_surface returns 1–5; map to 0–100
        raw = result.get("exposure_score", 3.0)
        risk_contribution = _clamp((raw - 1.0) / 4.0 * 100)
        return {
            "score": round(risk_contribution, 1),
            "exposure_label": result.get("exposure_label", "unknown"),
            "archetype": result.get("archetype", "unknown"),
            "source": "score_attack_surface",
            "available": True,
        }
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("score_attack_surface error: %s", exc)

    # Fallback: NVD CVSS AV
    cvss = _fetch_nvd_cvss(cve_id)
    if cvss:
        av = cvss.get("attackVector", "NETWORK")
        scope = cvss.get("scope", "UNCHANGED")
        base = _AV_SURFACE_SCORE.get(av, 50.0)
        scope_bump = 10.0 if scope == "CHANGED" else 0.0
        risk_contribution = _clamp(base + scope_bump)
        return {
            "score": round(risk_contribution, 1),
            "exposure_label": "heuristic",
            "archetype": f"av={av}",
            "source": "nvd_cvss_heuristic",
            "available": True,
        }

    return {
        "score": 50.0,
        "exposure_label": "unknown",
        "archetype": "unknown",
        "source": "default_fallback",
        "available": False,
    }


# ---------------------------------------------------------------------------
# Dimension 5 — Patch Lag
# ---------------------------------------------------------------------------

# overall_status → inverted risk contribution (patched = lower risk)
_PATCH_STATUS_SCORE: dict[str, float] = {
    "unpatched": 90.0,
    "partially_patched": 60.0,
    "fully_patched": 15.0,
    "unknown": 50.0,
}


def _score_patch_lag_dimension(cve_id: str) -> dict[str, Any]:
    """
    0–100 contribution based on patch availability.

    Prefers ``get_patch_status`` (PR #81) when available; falls back to
    querying OSV.dev for any published fix.
    """
    # Try the dedicated tool first
    try:
        from manus_agent.tools.get_patch_status import _run_patch_status

        result = _run_patch_status(cve_id)
        overall = result.get("overall_status", "unknown")
        base = _PATCH_STATUS_SCORE.get(overall, 50.0)
        fastest_days = result.get("fastest_patch_days")
        # Speed bonus: if vendor patched in ≤7 days → −10; ≤30 → −5
        lag_adj = 0.0
        if fastest_days is not None:
            if fastest_days <= 7:
                lag_adj = -10.0
            elif fastest_days <= 30:
                lag_adj = -5.0
        risk_contribution = _clamp(base + lag_adj)
        return {
            "score": round(risk_contribution, 1),
            "overall_status": overall,
            "fastest_patch_days": fastest_days,
            "fastest_patch_vendor": result.get("fastest_patch_vendor"),
            "source": "get_patch_status",
            "available": True,
        }
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("get_patch_status error: %s", exc)

    # Fallback: OSV.dev — check if any fix has been published
    try:
        r = requests.post(
            _OSV_QUERY_URL,
            json={"cve_id": cve_id.upper()},
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        vulns = r.json().get("vulns", [])
        has_fix = any(
            any(
                any(e.get("type") == "ECOSYSTEM" for e in (rng.get("events") or [])) or "fixed" in str(rng)
                for rng in (affected.get("ranges") or [])
            )
            for vuln in vulns
            for affected in (vuln.get("affected") or [])
        )
        if vulns and has_fix:
            risk_contribution = 20.0  # Fix known to exist
            status = "fix_available"
        elif vulns:
            risk_contribution = 65.0  # Vuln tracked but no clear fix
            status = "no_fix_found"
        else:
            risk_contribution = 50.0  # No OSV data
            status = "unknown"
        return {
            "score": round(risk_contribution, 1),
            "overall_status": status,
            "fastest_patch_days": None,
            "fastest_patch_vendor": None,
            "source": "osv_fallback",
            "available": True,
        }
    except Exception as exc:
        logger.debug("OSV patch-lag fallback failed for %s: %s", cve_id, exc)

    return {
        "score": 50.0,
        "overall_status": "unknown",
        "fastest_patch_days": None,
        "fastest_patch_vendor": None,
        "source": "default_fallback",
        "available": False,
    }


# ---------------------------------------------------------------------------
# Composite computation
# ---------------------------------------------------------------------------


def _compute_composite(
    dim_scores: dict[str, dict[str, Any]],
    weights: dict[str, float],
) -> tuple[float, str, str]:
    """
    Compute the weighted composite score, dominant factor, and confidence.

    Returns (context_score, dominant_factor, confidence).
    """
    total = 0.0
    contributions: dict[str, float] = {}
    available_count = sum(1 for d in dim_scores.values() if d.get("available", False))

    for dim_name, w in weights.items():
        dim = dim_scores.get(dim_name, {})
        raw = dim.get("score", 50.0)
        contrib = raw * w
        contributions[dim_name] = contrib
        total += contrib

    context_score = _clamp(total)

    dominant_factor = max(contributions, key=lambda k: contributions[k])

    if available_count >= 4:
        confidence = "HIGH"
    elif available_count >= 2:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return round(context_score, 1), dominant_factor, confidence


def _build_risk_summary(
    cve_id: str,
    context_score: float,
    risk_label: str,
    dominant_factor: str,
    dim_scores: dict[str, dict[str, Any]],
    confidence: str,
) -> str:
    """Generate a single-sentence risk summary."""
    label_phrase = {
        "CRITICAL": "critically urgent",
        "HIGH": "high-priority",
        "MEDIUM": "moderate",
        "LOW": "low",
        "INFORMATIONAL": "informational",
    }.get(risk_label, "moderate")

    factor_phrase = {
        "exploit_complexity": "ease of weaponisation",
        "epss_momentum": "rising exploitation probability",
        "blast_radius": "wide downstream exposure",
        "attack_surface": "high deployment exposure",
        "patch_lag": "limited patch availability",
    }.get(dominant_factor, dominant_factor)

    epss = dim_scores.get("epss_momentum", {}).get("epss", 0.0)
    epss_str = f"EPSS {epss:.1%}" if epss else ""
    conf_note = f" (confidence: {confidence.lower()})" if confidence != "HIGH" else ""

    parts = [
        f"{cve_id} is {label_phrase} (score {context_score:.0f}/100){conf_note},",
        f"driven primarily by {factor_phrase}",
    ]
    if epss_str:
        parts.append(f"with {epss_str} exploitation probability")
    parts[-1] += "."
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_DIM_LABELS = {
    "exploit_complexity": "Exploit Complexity (inverted)",
    "epss_momentum": "EPSS Momentum",
    "blast_radius": "Dependency Blast Radius",
    "attack_surface": "Attack Surface Exposure",
    "patch_lag": "Patch Lag / Availability",
}

_RISK_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "INFORMATIONAL": "⚪",
}


def _render_text(result: dict[str, Any]) -> str:
    lines = [
        f"Contextual Risk Score — {result['cve_id']}",
        "=" * 50,
        f"  Overall score : {result['context_score']:.1f} / 100",
        f"  Risk label    : {_RISK_EMOJI.get(result['risk_label'], '')} {result['risk_label']}",
        f"  Confidence    : {result['confidence']}",
        f"  Dominant risk : {_DIM_LABELS.get(result['dominant_factor'], result['dominant_factor'])}",
        "",
        result["risk_summary"],
        "",
        "Dimension breakdown:",
    ]
    weights = result.get("weights", _DEFAULT_WEIGHTS)
    for dim_name, dim in result["dimensions"].items():
        label = _DIM_LABELS.get(dim_name, dim_name)
        w = weights.get(dim_name, 0.0)
        s = dim.get("score", 0.0)
        contrib = s * w
        src = dim.get("source", "unknown")
        avail = "✓" if dim.get("available") else "✗"
        lines.append(f"  [{avail}] {label:<36} {s:5.1f}/100  ×{w:.2f} = {contrib:5.1f}  [{src}]")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Internal pipeline
# ---------------------------------------------------------------------------


def _run_context_score(
    cve_id: str,
    weights: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Run the full composite scoring pipeline and return a result dict."""
    cve_id = cve_id.upper().strip()
    effective_weights = _validate_weights(weights or _DEFAULT_WEIGHTS)

    dim_scores: dict[str, dict[str, Any]] = {
        "exploit_complexity": _score_exploit_complexity_dimension(cve_id),
        "epss_momentum": _score_epss_momentum_dimension(cve_id),
        "blast_radius": _score_blast_radius_dimension(cve_id),
        "attack_surface": _score_attack_surface_dimension(cve_id),
        "patch_lag": _score_patch_lag_dimension(cve_id),
    }

    context_score, dominant_factor, confidence = _compute_composite(dim_scores, effective_weights)
    risk_label = _risk_label(context_score)
    risk_summary = _build_risk_summary(cve_id, context_score, risk_label, dominant_factor, dim_scores, confidence)

    return {
        "cve_id": cve_id,
        "context_score": context_score,
        "risk_label": risk_label,
        "dominant_factor": dominant_factor,
        "confidence": confidence,
        "risk_summary": risk_summary,
        "dimensions": dim_scores,
        "weights": effective_weights,
    }


# ---------------------------------------------------------------------------
# Public tool entry point
# ---------------------------------------------------------------------------


@tool
def score_context_score(
    cve_id: str,
    output: str = "text",
    weights: str = "",
) -> str:
    """Compute a composite 0–100 contextual risk score for a CVE.

    Aggregates five independent signals — exploit complexity, EPSS momentum,
    dependency blast radius, attack surface exposure, and patch availability —
    into a single prioritisation score.  Each dimension degrades gracefully
    when the underlying data source is unavailable.

    Args:
        cve_id:  CVE identifier (e.g. ``CVE-2021-44228``).
        output:  ``'text'`` (default) or ``'json'``.
        weights: Optional JSON object of per-dimension weight overrides, e.g.
                 ``'{"exploit_complexity": 0.4, "epss_momentum": 0.3,
                    "blast_radius": 0.2, "attack_surface": 0.05,
                    "patch_lag": 0.05}'``.
                 Values are normalised to sum to 1.0 automatically.

    Returns:
        Formatted risk report string.
    """
    if not isinstance(cve_id, str) or not _CVE_RE.match(cve_id.strip()):
        return "Error: cve_id must be a valid CVE identifier like 'CVE-2021-44228'."

    # Parse optional weight overrides
    parsed_weights: dict[str, float] | None = None
    if weights:
        try:
            parsed_weights = json.loads(weights)
            if not isinstance(parsed_weights, dict):
                return "Error: weights must be a JSON object mapping dimension names to floats."
        except json.JSONDecodeError as exc:
            return f"Error: could not parse weights JSON — {exc}"

    result = _run_context_score(cve_id, parsed_weights)

    if output == "json":
        return json.dumps(result, indent=2)

    return _render_text(result)
