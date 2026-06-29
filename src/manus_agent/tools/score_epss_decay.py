"""
Tool: score_epss_decay

Detects whether a CVE's EPSS (Exploit Prediction Scoring System) score has
decayed significantly below its all-time peak — the *"attackers tried and moved
on"* signal.

Context
-------
``get_epss_trend`` already detects rising spikes (new exploitation activity).
This tool is the complementary view: given a CVE that once had a high EPSS score,
has that score since collapsed?  A significant decay suggests that exploitation
attempts peaked and then subsided — useful for de-prioritising CVEs that were
once hot but are no longer actively targeted.

Decay classification
--------------------
+---------------------+----------------------------------+---------------------------+
| Class               | Criterion                        | Interpretation            |
+=====================+==================================+===========================+
| significant_decay   | current < 40% of peak            | Attackers moved on        |
| moderate_decay      | current 40–70% of peak           | Interest waning           |
| stable              | current ≥ 70% of peak            | Still actively scored     |
| never_peaked        | peak < PEAK_BASELINE (0.15)      | Never attracted attention |
+---------------------+----------------------------------+---------------------------+

Additional signals
------------------
* ``days_since_peak`` — how many calendar days ago the peak occurred.
* ``peak_sustained_days`` — how many consecutive days the score stayed within
  10% of the peak (measures whether it was a brief spike or a sustained threat).
* ``decay_rate_per_week`` — average weekly percentage-point drop from peak to
  current (negative = declining).

Data source: FIRST.org EPSS API (free, no key required).

CLI: ``manus-agent epss-decay CVE-2024-3094``
     ``manus-agent epss-decay CVE-2024-3094 --days 365``
"""

from __future__ import annotations

import logging
from datetime import date
from typing import Any

import requests
from strands.types.tools import ToolResult, ToolUse

from manus_agent.tools.get_epss_trend import _fetch_epss_time_series
from manus_agent.tools.tool_output_logger import log_tool_output_size

logger = logging.getLogger(__name__)

# CVEs that never exceeded this EPSS score are flagged as "never_peaked".
_PEAK_BASELINE = 0.15

# Decay class thresholds (current / peak ratio).
_SIGNIFICANT_DECAY_THRESHOLD = 0.40  # current < 40% of peak
_MODERATE_DECAY_THRESHOLD = 0.70  # current 40–70% of peak

# A "sustained peak" band: days within this fraction below the peak count.
_SUSTAINED_BAND = 0.10  # within 10% of peak value

TOOL_SPEC = {
    "name": "score_epss_decay",
    "description": (
        "Analyses the EPSS score history for a CVE to detect whether it has decayed "
        "significantly below its all-time peak. A large decay signals that attacker "
        "interest peaked and has since waned ('attackers tried and moved on'). "
        "Returns a decay classification (significant_decay | moderate_decay | stable | "
        "never_peaked), the peak value and date, days since the peak, and an "
        "interpretation note. Use this alongside get_epss_trend to distinguish CVEs "
        "that are still actively targeted from those that have faded from attacker focus."
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "The CVE identifier to analyse (e.g. 'CVE-2021-44228').",
                },
                "days": {
                    "type": "integer",
                    "description": (
                        "Days of EPSS history to fetch. Defaults to 365 (maximum available). "
                        "Larger windows give a more accurate peak baseline."
                    ),
                    "default": 365,
                },
            },
            "required": ["cve_id"],
        }
    },
}


# ---------------------------------------------------------------------------
# Pure analysis helpers (no I/O — unit-testable)
# ---------------------------------------------------------------------------


def _analyse_decay(series: list[dict[str, str]]) -> dict[str, Any]:
    """Compute decay metrics from a raw time-series list.

    Parameters
    ----------
    series:
        List of ``{"date": "YYYY-MM-DD", "epss": "0.xxx", "percentile": "0.xxx"}``
        dicts in *any* order (oldest-first preferred but not required).

    Returns
    -------
    dict with keys: class, peak_epss, peak_date, current_epss, current_date,
    days_since_peak, peak_sustained_days, decay_ratio, decay_rate_per_week,
    interpretation, points.
    """
    if not series:
        return {
            "class": "unknown",
            "peak_epss": None,
            "peak_date": None,
            "current_epss": None,
            "current_date": None,
            "days_since_peak": None,
            "peak_sustained_days": 0,
            "decay_ratio": None,
            "decay_rate_per_week": None,
            "interpretation": "No EPSS data available.",
            "points": [],
        }

    # Normalise to floats; sort oldest-first.
    points = sorted(
        [
            {
                "date": pt["date"],
                "epss": float(pt["epss"]),
                "percentile": float(pt["percentile"]),
            }
            for pt in series
        ],
        key=lambda x: x["date"],
    )

    scores = [p["epss"] for p in points]
    peak_epss = max(scores)
    peak_idx = scores.index(peak_epss)
    peak_date_str = points[peak_idx]["date"]
    current_epss = scores[-1]
    current_date_str = points[-1]["date"]

    # Days since peak.
    try:
        peak_date = date.fromisoformat(peak_date_str)
        current_date = date.fromisoformat(current_date_str)
        days_since_peak = (current_date - peak_date).days
    except ValueError:
        days_since_peak = None

    # Sustained peak: how many consecutive days (from peak onwards) stayed within
    # _SUSTAINED_BAND of the peak value.
    sustained_threshold = peak_epss * (1.0 - _SUSTAINED_BAND)
    peak_sustained_days = 0
    for i in range(peak_idx, len(scores)):
        if scores[i] >= sustained_threshold:
            peak_sustained_days += 1
        else:
            break

    # Decay ratio: current vs peak.
    decay_ratio = round(current_epss / peak_epss, 4) if peak_epss > 0 else None

    # Weekly decay rate: average points per week from peak to current.
    decay_rate_per_week: float | None = None
    if days_since_peak and days_since_peak > 0:
        total_drop = peak_epss - current_epss
        weeks_elapsed = days_since_peak / 7.0
        decay_rate_per_week = round(total_drop / weeks_elapsed, 6)

    # Classify.
    if peak_epss < _PEAK_BASELINE:
        decay_class = "never_peaked"
        interpretation = (
            f"Peak EPSS of {peak_epss:.4f} never exceeded the significance baseline "
            f"({_PEAK_BASELINE:.2f}). This CVE was never widely expected to be exploited; "
            "attacker interest has always been low."
        )
    elif decay_ratio is not None and decay_ratio < _SIGNIFICANT_DECAY_THRESHOLD:
        decay_class = "significant_decay"
        interpretation = (
            f"Current EPSS ({current_epss:.4f}) is only "
            f"{decay_ratio * 100:.1f}% of the peak ({peak_epss:.4f} on {peak_date_str}, "
            f"{days_since_peak} days ago). Strong signal that attacker interest has "
            "peaked and substantially waned — 'tried and moved on'."
        )
    elif decay_ratio is not None and decay_ratio < _MODERATE_DECAY_THRESHOLD:
        decay_class = "moderate_decay"
        interpretation = (
            f"Current EPSS ({current_epss:.4f}) is "
            f"{decay_ratio * 100:.1f}% of the peak ({peak_epss:.4f} on {peak_date_str}, "
            f"{days_since_peak} days ago). Moderate decay — attacker interest is "
            "waning but still elevated relative to baseline."
        )
    else:
        decay_class = "stable"
        if days_since_peak == 0:
            interpretation = (
                f"Peak EPSS ({peak_epss:.4f}) observed today. "
                "Score is still at or near its maximum — no decay detected."
            )
        else:
            interpretation = (
                f"Current EPSS ({current_epss:.4f}) is "
                f"{decay_ratio * 100:.1f}% of the peak ({peak_epss:.4f} on {peak_date_str}, "
                f"{days_since_peak} days ago). Score remains near its peak — "
                "this CVE is still actively scored by EPSS models."
            )

    return {
        "class": decay_class,
        "peak_epss": round(peak_epss, 6),
        "peak_date": peak_date_str,
        "current_epss": round(current_epss, 6),
        "current_date": current_date_str,
        "days_since_peak": days_since_peak,
        "peak_sustained_days": peak_sustained_days,
        "decay_ratio": decay_ratio,
        "decay_rate_per_week": decay_rate_per_week,
        "interpretation": interpretation,
        "points": points,
    }


# ---------------------------------------------------------------------------
# Strands tool entrypoint
# ---------------------------------------------------------------------------


def score_epss_decay(tool: ToolUse, **kwargs: Any) -> ToolResult:
    """Analyse EPSS decay for a CVE and classify attacker interest trajectory."""
    tool_use_id = tool["toolUseId"]
    tool_input = tool["input"]
    cve_id = tool_input.get("cve_id", "")
    days = int(tool_input.get("days", 365))

    if not isinstance(cve_id, str) or not cve_id.upper().startswith("CVE-"):
        result: ToolResult = {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": "Invalid CVE ID format. Must be a string like 'CVE-YYYY-NNNN'."}],
        }
        log_tool_output_size("score_epss_decay", result)
        return result

    cve_id = cve_id.upper().strip()
    days = max(1, min(days, 365))

    try:
        raw = _fetch_epss_time_series(cve_id, days)
    except requests.exceptions.RequestException as exc:
        result = {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": f"FIRST.org EPSS API request failed: {exc}"}],
        }
        log_tool_output_size("score_epss_decay", result)
        return result

    data_list = raw.get("data", [])
    if not data_list:
        result = {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": f"No EPSS data found for {cve_id}."}],
        }
        log_tool_output_size("score_epss_decay", result)
        return result

    series = data_list[0].get("time-series", [])
    if not series:
        # Fallback: single data point (no time-series key).
        series = [
            {
                "date": data_list[0].get("date", ""),
                "epss": data_list[0].get("epss", "0"),
                "percentile": data_list[0].get("percentile", "0"),
            }
        ]

    analysis = _analyse_decay(series)

    # Build text summary (strip raw points list for readability).
    decay_class = analysis["class"]
    text_lines = [
        f"EPSS Decay Analysis  — {cve_id}",
        f"  Decay class      : {decay_class.upper()}",
        f"  Peak EPSS        : {analysis['peak_epss']:.4f}  (on {analysis['peak_date']})",
        f"  Current EPSS     : {analysis['current_epss']:.4f}  (on {analysis['current_date']})",
    ]
    if analysis["decay_ratio"] is not None:
        text_lines.append(
            f"  Decay ratio      : {analysis['decay_ratio']:.4f}  ({analysis['decay_ratio'] * 100:.1f}% of peak)"
        )
    if analysis["days_since_peak"] is not None:
        text_lines.append(f"  Days since peak  : {analysis['days_since_peak']}")
    text_lines.append(f"  Peak sustained   : {analysis['peak_sustained_days']} day(s)")
    if analysis["decay_rate_per_week"] is not None:
        text_lines.append(f"  Decay rate/week  : {analysis['decay_rate_per_week']:+.4f} EPSS pts/week")
    text_lines.append(f"\n  {analysis['interpretation']}")
    text_summary = "\n".join(text_lines)

    # JSON payload excludes verbose points list to keep it concise for agents.
    json_payload: dict[str, Any] = {
        "cve_id": cve_id,
        "days_requested": days,
        "data_points_available": len(series),
        "decay": {k: v for k, v in analysis.items() if k != "points"},
    }

    result = {
        "toolUseId": tool_use_id,
        "status": "success",
        "content": [
            {"text": text_summary},
            {"json": json_payload},
        ],
    }
    log_tool_output_size("score_epss_decay", result)
    return result
