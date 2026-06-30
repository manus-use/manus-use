"""
Tool: score_reachability

Assesses how *reachable* a CVE's vulnerable code path is in a typical deployment —
i.e., the likelihood that an attacker can actually trigger the vulnerability given
the nature of the affected component and real-world exploitation signals.

Reachability is distinct from *exploit complexity* (how hard to write an exploit):
a LOCAL privilege-escalation CVE may be trivially exploitable once you're on the
machine, but the reachability score captures how likely you even get to that point.

Scoring model
─────────────
Six independent dimensions, each contributing a weighted sub-score 0–20:

1. **Attack Vector** (weight 0.25)
   NETWORK=20, ADJACENT_NETWORK=12, LOCAL=6, PHYSICAL=2
   Remote exposure is the single strongest reachability predictor.

2. **Privileges Required** (weight 0.15)
   NONE=20, LOW=10, HIGH=4
   Unauthenticated attack paths are the highest-risk exposure.

3. **User Interaction** (weight 0.10)
   NONE=20, REQUIRED=8
   No-click / drive-by vulnerabilities are far more reachable.

4. **CWE reachability class** (weight 0.20)
   Classifies the CWE into HIGH/MEDIUM/LOW reachability tiers based on how
   frequently the vulnerability class is exposed in network-facing services.
   HIGH (injection, memory corruption, deserialization …): 20
   MEDIUM (auth bypass, IDOR, XXE, SSRF …): 13
   LOW (timing side-channel, physical, info-disclosure-only …): 6
   UNKNOWN: 10

5. **PoC availability** (weight 0.20)
   Checks the Trickest CVE repository for known public PoC code.
   PoC present: 20  |  absent: 0
   This dimension degrades gracefully when the Trickest request fails.

6. **EPSS score** (weight 0.10)
   Translates the current FIRST.org EPSS score (0.0–1.0) linearly to 0–20.
   EPSS encodes the community's collective assessment of exploitation likelihood.
   This dimension degrades gracefully when FIRST.org is unavailable.

Final reachability_score = sum(weight_i × sub_score_i)  ∈ [0, 20]

Reachability level:
  CRITICAL  ≥ 15
  HIGH      ≥ 10
  MEDIUM    ≥  6
  LOW        <  6
"""

from __future__ import annotations

import re
from typing import Any

import requests
from strands import tool

__all__ = ["score_reachability"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"CVE-(\d{4})-\d+", re.IGNORECASE)

# Weights for the six dimensions (must sum to 1.0)
_WEIGHTS: dict[str, float] = {
    "attack_vector": 0.25,
    "privileges_required": 0.15,
    "user_interaction": 0.10,
    "cwe_class": 0.20,
    "poc_available": 0.20,
    "epss_score": 0.10,
}

# NVD CVSS → sub-score mappings (scale 0–20)
_AV_SCORE: dict[str, float] = {
    "NETWORK": 20.0,
    "ADJACENT_NETWORK": 12.0,
    "ADJACENT": 12.0,
    "LOCAL": 6.0,
    "PHYSICAL": 2.0,
}

_PR_SCORE: dict[str, float] = {
    "NONE": 20.0,
    "LOW": 10.0,
    "HIGH": 4.0,
}

_UI_SCORE: dict[str, float] = {
    "NONE": 20.0,
    "REQUIRED": 8.0,
}

# ---------------------------------------------------------------------------
# CWE reachability tiers
# ---------------------------------------------------------------------------
# HIGH: vulnerability classes that are most commonly exposed in network-facing
#       services and are known to be triggered remotely with minimal setup.
_CWE_HIGH: frozenset[int] = frozenset(
    [
        # Injection / command execution
        77,
        78,
        79,
        80,
        87,
        88,
        89,
        90,
        91,
        93,
        94,
        95,
        96,
        97,
        98,
        99,
        # Memory corruption / overflow
        119,
        120,
        121,
        122,
        123,
        124,
        125,
        126,
        127,
        128,
        129,
        130,
        131,
        134,
        170,
        191,
        192,
        193,
        194,
        195,
        196,
        197,
        # Use-after-free / heap
        416,
        415,
        # Deserialization / type confusion
        502,
        843,
        # XXE via default parser
        611,
        # Remote code execution via template injection
        1336,
        # Integer overflow leading to buffer over-read
        190,
        191,
    ]
)

# MEDIUM: commonly exploitable but require some precondition (auth, specific
#         config, or multi-step interaction).
_CWE_MEDIUM: frozenset[int] = frozenset(
    [
        # Authentication / access control
        284,
        285,
        287,
        288,
        290,
        294,
        302,
        306,
        307,
        308,
        346,
        384,
        # Path traversal / directory traversal
        22,
        23,
        24,
        25,
        26,
        27,
        28,
        29,
        30,
        31,
        32,
        33,
        34,
        35,
        36,
        37,
        38,
        39,
        40,
        # SSRF
        918,
        # IDOR / insecure direct object reference
        639,
        # Open redirect
        601,
        # CSRF
        352,
        # XML injection (XPath, XSLT)
        643,
        # Improper input validation (generic)
        20,
        # Uncontrolled resource consumption (DoS)
        400,
        770,
        789,
        834,
        # Improper privilege management
        269,
        # Missing encryption / cleartext
        319,
        321,
        326,
        327,
        # Hardcoded credentials
        798,
    ]
)

# LOW: vulnerability classes that are hard to reach remotely, require physical
#      access, or are primarily information-disclosure / side-channel issues.
_CWE_LOW: frozenset[int] = frozenset(
    [
        # Timing side-channel
        208,
        # Cache timing
        203,
        # Physical
        1248,
        1254,
        # Information disclosure only
        200,
        201,
        202,
        209,
        213,
        215,
        # Resource exhaustion (local only)
        771,
        772,
        # Uninitialized variable (info leak)
        457,
        456,
        # Log injection
        117,
    ]
)


def _cwe_reachability_score(cwe_ids: list[int]) -> tuple[float, str]:
    """Return (sub_score, tier_label) for the highest-tier CWE in the list."""
    if not cwe_ids:
        return 10.0, "UNKNOWN"

    best: tuple[float, str] = (10.0, "UNKNOWN")
    for cid in cwe_ids:
        if cid in _CWE_HIGH:
            return 20.0, "HIGH"  # short-circuit: can't get higher
        if cid in _CWE_MEDIUM:
            best = (13.0, "MEDIUM")
        elif cid in _CWE_LOW and best[1] not in ("MEDIUM",):
            best = (6.0, "LOW")
    return best


# ---------------------------------------------------------------------------
# Reachability level
# ---------------------------------------------------------------------------


def _reachability_level(score: float) -> str:
    if score >= 15.0:
        return "CRITICAL"
    if score >= 10.0:
        return "HIGH"
    if score >= 6.0:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Data-fetching helpers
# ---------------------------------------------------------------------------

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TRICKEST_RAW = "https://raw.githubusercontent.com/trickest/cve/main/{year}/{cve_id}.md"
_EPSS_URL = "https://api.first.org/data/v1/epss"


def _fetch_nvd_cvss(cve_id: str) -> dict[str, Any]:
    """Return a dict with keys: av, pr, ui, cwe_ids (list[int]).

    Raises ``requests.RequestException`` on network failure.
    Returns empty dict keys with default values on parse failure.
    """
    resp = requests.get(_NVD_URL, params={"cveId": cve_id.upper()}, timeout=15)
    resp.raise_for_status()
    data = resp.json()

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {"av": None, "pr": None, "ui": None, "cwe_ids": []}

    cve_obj = vulns[0].get("cve", {})

    # --- CVSS v3.1 first, fall back to v3.0, then v2 ---
    av = pr = ui = None
    metrics = cve_obj.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            vector_data = entries[0].get("cvssData", {})
            av = vector_data.get("attackVector", "").upper() or None
            pr = vector_data.get("privilegesRequired", "").upper() or None
            ui = vector_data.get("userInteraction", "").upper() or None
            break

    if av is None:
        # v2 fallback
        entries = metrics.get("cvssMetricV2", [])
        if entries:
            vector_data = entries[0].get("cvssData", {})
            av = vector_data.get("accessVector", "").upper() or None
            pr_raw = vector_data.get("authentication", "").upper()
            # v2: NONE → NONE, SINGLE → LOW, MULTIPLE → HIGH
            pr_map = {"NONE": "NONE", "SINGLE": "LOW", "MULTIPLE": "HIGH"}
            pr = pr_map.get(pr_raw)
            ui = None  # v2 has no UI field; treat as NONE

    # --- CWE IDs ---
    cwe_ids: list[int] = []
    for weakness in cve_obj.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val: str = desc.get("value", "")
            m = re.match(r"CWE-(\d+)", val, re.IGNORECASE)
            if m:
                cwe_ids.append(int(m.group(1)))

    return {"av": av, "pr": pr, "ui": ui, "cwe_ids": cwe_ids}


def _fetch_poc_available(cve_id: str) -> tuple[bool, str]:
    """Return (True, reason) if a PoC is found in the Trickest CVE index.

    Never raises; returns (False, reason) on failure.
    """
    m = _CVE_RE.match(cve_id)
    if not m:
        return False, "invalid CVE format"

    year = m.group(1)
    url = _TRICKEST_RAW.format(year=year, cve_id=cve_id.upper())
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            # A non-empty Trickest page with PoC links has "## PoC" section or raw URLs
            text = resp.text
            has_poc = bool(
                re.search(r"^#+\s*poc", text, re.IGNORECASE | re.MULTILINE)
                or re.search(r"https?://github\.com/\S+/\S+", text)
            )
            if has_poc:
                return True, "Trickest CVE index lists PoC references"
            return False, "Trickest page exists but contains no PoC URLs"
        if resp.status_code == 404:
            return False, "no Trickest entry found for this CVE"
        return False, f"Trickest returned HTTP {resp.status_code}"
    except requests.RequestException as exc:
        return False, f"Trickest request failed: {exc}"


def _fetch_epss(cve_id: str) -> tuple[float | None, str]:
    """Return (epss_score, reason).  Score is None on failure."""
    try:
        resp = requests.get(_EPSS_URL, params={"cve": cve_id.upper()}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        items = data.get("data", [])
        if items:
            score = float(items[0].get("epss", 0.0))
            return score, f"EPSS={score:.4f}"
        return None, "no EPSS data available"
    except (requests.RequestException, KeyError, ValueError) as exc:
        return None, f"EPSS request failed: {exc}"


# ---------------------------------------------------------------------------
# Core scoring engine
# ---------------------------------------------------------------------------


def _run_scoring(cve_id: str) -> dict[str, Any]:  # noqa: C901
    """Fetch all signals and compute the reachability score."""
    reasons: list[str] = []
    dimension_scores: dict[str, float] = {}
    dimension_details: dict[str, str] = {}
    warnings: list[str] = []

    # 1. NVD data
    try:
        nvd = _fetch_nvd_cvss(cve_id)
    except requests.RequestException as exc:
        return {
            "cve_id": cve_id,
            "error": f"NVD request failed: {exc}",
        }

    av = nvd.get("av")
    pr = nvd.get("pr")
    ui = nvd.get("ui")
    cwe_ids = nvd.get("cwe_ids", [])

    # 2. Attack Vector
    av_score = _AV_SCORE.get(av, 10.0) if av else 10.0
    dimension_scores["attack_vector"] = av_score
    dimension_details["attack_vector"] = f"AV={av or 'UNKNOWN'} → {av_score:.0f}/20"
    if av:
        reasons.append(f"Attack Vector is {av}")

    # 3. Privileges Required
    pr_score = _PR_SCORE.get(pr, 10.0) if pr else 10.0
    dimension_scores["privileges_required"] = pr_score
    dimension_details["privileges_required"] = f"PR={pr or 'UNKNOWN'} → {pr_score:.0f}/20"

    # 4. User Interaction
    ui_score = _UI_SCORE.get(ui, 10.0) if ui else 10.0
    dimension_scores["user_interaction"] = ui_score
    dimension_details["user_interaction"] = f"UI={ui or 'UNKNOWN'} → {ui_score:.0f}/20"

    # 5. CWE reachability class
    cwe_score, cwe_tier = _cwe_reachability_score(cwe_ids)
    dimension_scores["cwe_class"] = cwe_score
    cwe_label = ", ".join(f"CWE-{c}" for c in cwe_ids) if cwe_ids else "none"
    dimension_details["cwe_class"] = f"CWE(s)={cwe_label} → tier={cwe_tier} → {cwe_score:.0f}/20"
    if cwe_tier != "UNKNOWN":
        reasons.append(f"CWE reachability tier is {cwe_tier} ({cwe_label})")

    # 6. PoC availability
    poc_available, poc_reason = _fetch_poc_available(cve_id)
    poc_score = 20.0 if poc_available else 0.0
    dimension_scores["poc_available"] = poc_score
    dimension_details["poc_available"] = f"PoC={'present' if poc_available else 'absent'}: {poc_reason}"
    if poc_available:
        reasons.append("Public PoC code is available")

    # 7. EPSS score
    epss_value, epss_reason = _fetch_epss(cve_id)
    if epss_value is not None:
        epss_score = epss_value * 20.0  # 0.0–1.0 → 0–20
        dimension_scores["epss_score"] = epss_score
        dimension_details["epss_score"] = f"EPSS={epss_value:.4f} → {epss_score:.2f}/20 ({epss_reason})"
        if epss_value >= 0.5:
            reasons.append(f"High EPSS score ({epss_value:.2%}) indicates likely real-world exploitation")
    else:
        epss_score = 10.0  # neutral fallback
        dimension_scores["epss_score"] = epss_score
        dimension_details["epss_score"] = f"EPSS unavailable ({epss_reason}), using neutral 10/20"
        warnings.append("EPSS data unavailable; neutral value used")

    # --- Final weighted score ---
    total = sum(_WEIGHTS[dim] * dimension_scores[dim] for dim in _WEIGHTS)
    level = _reachability_level(total)

    return {
        "cve_id": cve_id,
        "reachability_score": round(total, 2),
        "reachability_level": level,
        "dimension_scores": dimension_scores,
        "dimension_details": dimension_details,
        "summary_reasons": reasons,
        "warnings": warnings,
        "scoring_weights": _WEIGHTS,
    }


def _render_text(result: dict[str, Any]) -> str:
    """Render a human-readable reachability report."""
    if "error" in result:
        return f"ERROR: {result['error']}"

    cve_id = result["cve_id"]
    score = result["reachability_score"]
    level = result["reachability_level"]

    level_icons = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
    }
    icon = level_icons.get(level, "⚪")

    lines = [
        f"Reachability Report — {cve_id}",
        "=" * 44,
        f"Score:  {score:.2f} / 20.00  {icon} {level}",
        "",
        "Dimension breakdown:",
    ]

    dd = result.get("dimension_details", {})
    dim_labels = {
        "attack_vector": "Attack Vector     ",
        "privileges_required": "Privileges Req.   ",
        "user_interaction": "User Interaction  ",
        "cwe_class": "CWE Class         ",
        "poc_available": "PoC Available     ",
        "epss_score": "EPSS Score        ",
    }
    for dim, label in dim_labels.items():
        detail = dd.get(dim, "—")
        weight_pct = int(_WEIGHTS.get(dim, 0) * 100)
        lines.append(f"  {label} (w={weight_pct:2d}%)  {detail}")

    if result.get("summary_reasons"):
        lines.append("")
        lines.append("Key factors:")
        for r in result["summary_reasons"]:
            lines.append(f"  • {r}")

    if result.get("warnings"):
        lines.append("")
        lines.append("Warnings:")
        for w in result["warnings"]:
            lines.append(f"  ⚠ {w}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Strands tool entry point
# ---------------------------------------------------------------------------


@tool
def score_reachability(cve_id: str) -> dict[str, Any]:
    """
    Score how reachable a CVE's vulnerable code path is in a typical deployment.

    Reachability measures the probability that an attacker can *trigger* the
    vulnerability — it is distinct from exploit complexity (how hard to write the
    exploit) and from CVSS base score (which conflates severity with exploitability).

    Six weighted signals are combined into a score of 0–20:

    - **Attack Vector** (25%) — NETWORK exposure maximises reachability.
    - **Privileges Required** (15%) — unauthenticated attack paths score highest.
    - **User Interaction** (10%) — no-click vulnerabilities score highest.
    - **CWE Reachability Class** (20%) — injection/memory-corruption CWEs are
      classified HIGH; auth/access-control CWEs MEDIUM; side-channel/physical LOW.
    - **PoC Availability** (20%) — checks the Trickest CVE repository for public PoC
      code; presence confirms real-world reachability.
    - **EPSS Score** (10%) — translates the FIRST.org EPSS score to 0–20; encodes the
      community's assessment of exploitation likelihood.

    Final reachability level:
      CRITICAL ≥ 15 | HIGH ≥ 10 | MEDIUM ≥ 6 | LOW < 6

    Args:
        cve_id: CVE identifier, e.g. ``"CVE-2024-3094"``.

    Returns:
        A dictionary with keys:
        - ``reachability_score`` (float 0–20)
        - ``reachability_level`` (CRITICAL / HIGH / MEDIUM / LOW)
        - ``dimension_scores`` — per-dimension sub-scores
        - ``dimension_details`` — human-readable per-dimension explanation
        - ``summary_reasons`` — list of key contributing factors
        - ``warnings`` — degradation notices (e.g. EPSS unavailable)
        - ``report`` — pre-rendered text report
        - ``scoring_weights`` — weight map for transparency
    """
    if not isinstance(cve_id, str) or not re.match(r"CVE-\d{4}-\d+", cve_id, re.IGNORECASE):
        return {
            "cve_id": cve_id,
            "error": "Invalid CVE ID format. Must match CVE-YYYY-NNNN.",
        }

    result = _run_scoring(cve_id)
    result["report"] = _render_text(result)
    return result
