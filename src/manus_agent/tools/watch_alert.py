"""
Tool: watch_alert

Reads the persistent EPSS watchlist (``~/.manus-agent/watchlist.jsonl``),
fetches current EPSS scores and enrichment data for every tracked CVE, and
renders a Markdown alert digest.

The digest groups CVEs into three severity bands:

- 🚨 **EPSS Spike** — current EPSS rose ≥ ``spike_threshold`` (default 0.10)
  since the last recorded score.
- ⚠️  **Elevated** — current EPSS ≥ ``epss_alert_floor`` (default 0.30) but no
  spike this cycle.
- ✅  **Stable** — everything else (shown in the digest but not highlighted).

Per-CVE enrichment (all gracefully degraded when APIs are unavailable):

- CVSS base score + severity tier (fetched from NVD)
- CISA KEV membership flag (fetched from CISA)
- EPSS score delta (vs. ``last_epss`` stored in the watchlist)
- Trend arrow: ↑ / ↓ / → based on delta magnitude

The tool also persists the refreshed EPSS scores back to the watchlist file so
the next ``watch check`` (or ``watch alert``) call starts from an up-to-date
baseline — identical behaviour to ``watch_epss check``.

Supported output formats (``output_format`` parameter):
- ``"markdown"`` (default) — Markdown report suitable for piping to a file or
  posting to a chat tool.
- ``"text"`` — Plain-text version (no Markdown headings/bold).
- ``"json"`` — Machine-readable JSON with the full per-CVE breakdown.

CLI: ``manus-agent watch alert [--threshold DELTA] [--floor EPSS]
         [--output markdown|text|json] [--watchlist PATH]``
"""

from __future__ import annotations

import json
import os
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import requests
from strands.types.tools import ToolResult, ToolUse

from manus_agent.tools.tool_output_logger import log_tool_output_size

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_WATCHLIST_PATH = Path.home() / ".manus-agent" / "watchlist.jsonl"
_DEFAULT_SPIKE_THRESHOLD = 0.10
_DEFAULT_EPSS_FLOOR = 0.30

TOOL_SPEC = {
    "name": "watch_alert",
    "description": (
        "Read the EPSS watchlist (~/.manus-agent/watchlist.jsonl), fetch current EPSS scores "
        "for every tracked CVE, enrich with CVSS base score and CISA KEV status, and render a "
        "Markdown alert digest. CVEs are grouped into: 🚨 EPSS Spike (delta ≥ spike_threshold), "
        "⚠️ Elevated (EPSS ≥ epss_alert_floor), and ✅ Stable. Updated scores are persisted back "
        "to the watchlist. Use this to generate a periodic security digest or a notification-ready "
        "summary of your tracked vulnerabilities."
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "spike_threshold": {
                    "type": "number",
                    "description": (
                        "Minimum EPSS delta (current − last) to classify a CVE as a spike. "
                        "Default: 0.10 (10 percentage points)."
                    ),
                    "default": _DEFAULT_SPIKE_THRESHOLD,
                },
                "epss_alert_floor": {
                    "type": "number",
                    "description": (
                        "CVEs with EPSS ≥ this value are highlighted as 'Elevated' even when "
                        "there is no spike. Default: 0.30."
                    ),
                    "default": _DEFAULT_EPSS_FLOOR,
                },
                "output_format": {
                    "type": "string",
                    "enum": ["markdown", "text", "json"],
                    "description": "Output format: 'markdown' (default), 'text', or 'json'.",
                    "default": "markdown",
                },
                "watchlist_path": {
                    "type": "string",
                    "description": ("Override the watchlist file path. Defaults to ~/.manus-agent/watchlist.jsonl."),
                },
            },
            "required": [],
        }
    },
}

# ---------------------------------------------------------------------------
# EPSS fetcher (same logic as watch_epss to keep the two in sync)
# ---------------------------------------------------------------------------


def _fetch_current_epss(cve_ids: list[str]) -> dict[str, float]:
    """Fetch current EPSS scores from FIRST.org.  Returns cve_id → score."""
    if not cve_ids:
        return {}
    scores: dict[str, float] = {}
    chunk_size = 50
    for i in range(0, len(cve_ids), chunk_size):
        chunk = cve_ids[i : i + chunk_size]
        params = [("cve", c.upper()) for c in chunk]
        try:
            resp = requests.get(
                "https://api.first.org/data/v1/epss",
                params=params,
                timeout=20,
            )
            resp.raise_for_status()
            for entry in resp.json().get("data", []):
                cid = entry.get("cve", "").upper()
                try:
                    scores[cid] = float(entry.get("epss", -1))
                except (TypeError, ValueError):
                    scores[cid] = -1.0
        except requests.exceptions.RequestException:
            for c in chunk:
                scores[c.upper()] = -1.0
    for c in cve_ids:
        scores.setdefault(c.upper(), -1.0)
    return scores


# ---------------------------------------------------------------------------
# NVD enrichment (CVSS base score)
# ---------------------------------------------------------------------------


def _fetch_nvd_cvss(cve_ids: list[str]) -> dict[str, dict[str, Any]]:
    """
    Fetch CVSS base score + severity for each CVE from NVD.
    Returns dict[cve_id] → {"base_score": float, "severity": str}.
    Missing / errored CVEs get {"base_score": None, "severity": "UNKNOWN"}.
    """
    results: dict[str, dict[str, Any]] = {}
    for cid in cve_ids:
        default: dict[str, Any] = {"base_score": None, "severity": "UNKNOWN"}
        try:
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cid.upper()},
                timeout=15,
            )
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities", [])
            if not vulns:
                results[cid.upper()] = default
                continue
            metrics = vulns[0].get("cve", {}).get("metrics", {})
            # Prefer CVSSv3.1, fall back to v3.0, then v2
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    cv = entries[0].get("cvssData", {})
                    score = cv.get("baseScore")
                    severity = cv.get("baseSeverity") or cv.get("baseMetricV2", {}).get("severity") or "UNKNOWN"
                    results[cid.upper()] = {
                        "base_score": float(score) if score is not None else None,
                        "severity": str(severity).upper(),
                    }
                    break
            else:
                results[cid.upper()] = default
        except requests.exceptions.RequestException:
            results[cid.upper()] = default
    return results


# ---------------------------------------------------------------------------
# CISA KEV enrichment
# ---------------------------------------------------------------------------


def _fetch_kev_set() -> set[str]:
    """Return the set of CVE IDs in the CISA KEV catalog. Empty on error."""
    try:
        resp = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=20,
        )
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        return {v.get("cveID", "").upper() for v in vulns if v.get("cveID")}
    except requests.exceptions.RequestException:
        return set()


# ---------------------------------------------------------------------------
# Watchlist I/O
# ---------------------------------------------------------------------------


def _resolve_path(override: str | None) -> Path:
    p = Path(override) if override else _DEFAULT_WATCHLIST_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _load_watchlist(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return records


def _save_watchlist(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in records) + ("\n" if records else ""),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Trend arrow helper
# ---------------------------------------------------------------------------


def _trend_arrow(delta: float | None) -> str:
    """Return ↑ / ↓ / → based on the EPSS delta."""
    if delta is None:
        return "→"
    if delta >= 0.02:
        return "↑"
    if delta <= -0.02:
        return "↓"
    return "→"


# ---------------------------------------------------------------------------
# Core alert builder
# ---------------------------------------------------------------------------


def _build_alert(
    records: list[dict[str, Any]],
    path: Path,
    spike_threshold: float,
    epss_alert_floor: float,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Fetch enrichment data, update watchlist records, and return
    (updated_records, alert_payload).

    alert_payload keys:
        generated_at  str  ISO-8601 UTC timestamp
        watchlist_size  int
        spike_threshold  float
        epss_alert_floor  float
        spikes  list[dict]
        elevated  list[dict]
        stable  list[dict]
    """
    today = date.today().isoformat()
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if not records:
        return records, {
            "generated_at": generated_at,
            "watchlist_size": 0,
            "spike_threshold": spike_threshold,
            "epss_alert_floor": epss_alert_floor,
            "spikes": [],
            "elevated": [],
            "stable": [],
        }

    cve_ids = [r["cve_id"].upper() for r in records]

    # Parallel-ish enrichment (sequential; each request is independent)
    epss_map = _fetch_current_epss(cve_ids)
    nvd_map = _fetch_nvd_cvss(cve_ids)
    kev_set = _fetch_kev_set()

    spikes: list[dict[str, Any]] = []
    elevated: list[dict[str, Any]] = []
    stable: list[dict[str, Any]] = []
    updated_records: list[dict[str, Any]] = []

    for r in records:
        cid = r["cve_id"].upper()
        new_epss = epss_map.get(cid, -1.0)
        prev_epss: float | None = r.get("last_epss")
        baseline_epss: float | None = r.get("baseline_epss")

        # Update the record
        r = dict(r)
        r["last_checked"] = today
        if new_epss >= 0:
            r["last_epss"] = new_epss
            if r.get("baseline_epss") is None:
                r["baseline_epss"] = new_epss
            baseline_epss = r["baseline_epss"]

        updated_records.append(r)

        nvd_info = nvd_map.get(cid, {"base_score": None, "severity": "UNKNOWN"})
        in_kev = cid in kev_set

        # Compute delta vs. last_epss
        delta: float | None = None
        if new_epss >= 0 and prev_epss is not None and prev_epss >= 0:
            delta = new_epss - prev_epss

        # Compute delta vs. baseline (for context)
        baseline_delta: float | None = None
        if new_epss >= 0 and baseline_epss is not None and baseline_epss >= 0:
            baseline_delta = new_epss - baseline_epss

        entry: dict[str, Any] = {
            "cve_id": cid,
            "current_epss": new_epss if new_epss >= 0 else None,
            "prev_epss": prev_epss,
            "baseline_epss": baseline_epss,
            "delta": delta,
            "baseline_delta": baseline_delta,
            "trend": _trend_arrow(delta),
            "cvss_base_score": nvd_info["base_score"],
            "cvss_severity": nvd_info["severity"],
            "in_kev": in_kev,
            "added_at": r.get("added_at"),
            "epss_unavailable": new_epss < 0,
        }

        # Classify into bucket
        if delta is not None and delta >= spike_threshold:
            spikes.append(entry)
        elif new_epss >= epss_alert_floor:
            elevated.append(entry)
        else:
            stable.append(entry)

    _save_watchlist(path, updated_records)

    # Sort spikes by delta descending, others by current_epss descending
    spikes.sort(key=lambda e: e["delta"] or 0, reverse=True)
    elevated.sort(key=lambda e: e["current_epss"] or 0, reverse=True)
    stable.sort(key=lambda e: e["current_epss"] or 0, reverse=True)

    payload: dict[str, Any] = {
        "generated_at": generated_at,
        "watchlist_size": len(records),
        "spike_threshold": spike_threshold,
        "epss_alert_floor": epss_alert_floor,
        "spikes": spikes,
        "elevated": elevated,
        "stable": stable,
    }
    return updated_records, payload


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def _fmt_epss(v: float | None) -> str:
    return f"{v:.4f}" if v is not None else "N/A"


def _fmt_delta(v: float | None) -> str:
    if v is None:
        return "N/A"
    sign = "+" if v >= 0 else ""
    return f"{sign}{v:.4f}"


def _fmt_cvss(score: float | None, severity: str) -> str:
    if score is None:
        return "N/A"
    return f"{score:.1f} ({severity})"


def _render_entry_md(e: dict[str, Any]) -> str:
    kev_badge = " 🔴 **KEV**" if e["in_kev"] else ""
    epss_str = _fmt_epss(e["current_epss"])
    delta_str = _fmt_delta(e["delta"])
    baseline_delta_str = _fmt_delta(e["baseline_delta"])
    cvss_str = _fmt_cvss(e["cvss_base_score"], e["cvss_severity"])
    arrow = e["trend"]
    unavail = " *(EPSS unavailable)*" if e["epss_unavailable"] else ""
    lines = [
        f"- **{e['cve_id']}**{kev_badge}{unavail}",
        f"  - EPSS: `{epss_str}` {arrow}  (Δ last: `{delta_str}`, Δ baseline: `{baseline_delta_str}`)",
        f"  - CVSS: `{cvss_str}`",
        f"  - Added: {e['added_at'] or 'unknown'}",
    ]
    return "\n".join(lines)


def _render_entry_text(e: dict[str, Any]) -> str:
    kev_str = " [KEV]" if e["in_kev"] else ""
    epss_str = _fmt_epss(e["current_epss"])
    delta_str = _fmt_delta(e["delta"])
    baseline_delta_str = _fmt_delta(e["baseline_delta"])
    cvss_str = _fmt_cvss(e["cvss_base_score"], e["cvss_severity"])
    arrow = e["trend"]
    unavail = " (EPSS unavailable)" if e["epss_unavailable"] else ""
    return (
        f"  {e['cve_id']}{kev_str}{unavail}\n"
        f"    EPSS: {epss_str} {arrow}  (delta-last: {delta_str}, delta-baseline: {baseline_delta_str})\n"
        f"    CVSS: {cvss_str}  |  Added: {e['added_at'] or 'unknown'}"
    )


def _render_markdown(payload: dict[str, Any]) -> str:
    today_str = payload["generated_at"][:10]
    lines: list[str] = [
        f"## EPSS Alert Digest — {today_str}",
        "",
        f"> Generated: {payload['generated_at']}  "
        f"| Watchlist: {payload['watchlist_size']} CVE(s)  "
        f"| Spike threshold: Δ≥{payload['spike_threshold']:.2f}  "
        f"| Elevated floor: ≥{payload['epss_alert_floor']:.2f}",
        "",
    ]

    spikes = payload["spikes"]
    elevated = payload["elevated"]
    stable = payload["stable"]

    if spikes:
        lines.append(f"### 🚨 EPSS Spikes ({len(spikes)})")
        lines.append("")
        for e in spikes:
            lines.append(_render_entry_md(e))
            lines.append("")
    else:
        lines.append("### 🚨 EPSS Spikes")
        lines.append("")
        lines.append("_No spikes detected this cycle._")
        lines.append("")

    if elevated:
        lines.append(f"### ⚠️  Elevated EPSS ({len(elevated)})")
        lines.append("")
        for e in elevated:
            lines.append(_render_entry_md(e))
            lines.append("")
    else:
        lines.append("### ⚠️  Elevated EPSS")
        lines.append("")
        lines.append(f"_No CVEs with EPSS ≥ {payload['epss_alert_floor']:.2f} detected._")
        lines.append("")

    if stable:
        lines.append(f"### ✅ Stable ({len(stable)})")
        lines.append("")
        for e in stable:
            lines.append(_render_entry_md(e))
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _render_text(payload: dict[str, Any]) -> str:
    today_str = payload["generated_at"][:10]
    lines: list[str] = [
        f"EPSS Alert Digest — {today_str}",
        f"Generated: {payload['generated_at']}",
        f"Watchlist: {payload['watchlist_size']} CVE(s)",
        f"Spike threshold: delta >= {payload['spike_threshold']:.2f}  |  Elevated floor: >= {payload['epss_alert_floor']:.2f}",
        "",
    ]

    spikes = payload["spikes"]
    elevated = payload["elevated"]
    stable = payload["stable"]

    lines.append(f"=== EPSS Spikes ({len(spikes)}) ===")
    if spikes:
        for e in spikes:
            lines.append(_render_entry_text(e))
            lines.append("")
    else:
        lines.append("  No spikes detected this cycle.")
    lines.append("")

    lines.append(f"=== Elevated EPSS ({len(elevated)}) ===")
    if elevated:
        for e in elevated:
            lines.append(_render_entry_text(e))
            lines.append("")
    else:
        lines.append(f"  No CVEs with EPSS >= {payload['epss_alert_floor']:.2f}.")
    lines.append("")

    lines.append(f"=== Stable ({len(stable)}) ===")
    if stable:
        for e in stable:
            lines.append(_render_entry_text(e))
            lines.append("")
    else:
        lines.append("  None.")

    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Tool entry-point
# ---------------------------------------------------------------------------


def watch_alert(tool: ToolUse, **kwargs: Any) -> ToolResult:
    """Read the EPSS watchlist and render a Markdown alert digest."""
    tool_use_id = tool["toolUseId"]
    inp = tool["input"]

    spike_threshold = float(inp.get("spike_threshold") or _DEFAULT_SPIKE_THRESHOLD)
    epss_alert_floor = float(inp.get("epss_alert_floor") or _DEFAULT_EPSS_FLOOR)
    output_format = (inp.get("output_format") or "markdown").lower().strip()
    watchlist_path_override = inp.get("watchlist_path") or os.environ.get("MANUS_WATCHLIST_PATH")

    if output_format not in {"markdown", "text", "json"}:
        output_format = "markdown"

    path = _resolve_path(watchlist_path_override)
    records = _load_watchlist(path)

    if not records:
        empty_msg = "Watchlist is empty. Use `manus-agent watch add CVE-XXXX-YYYY` to start tracking CVEs."
        result: ToolResult = {
            "toolUseId": tool_use_id,
            "status": "success",
            "content": [{"text": empty_msg}],
        }
        log_tool_output_size("watch_alert", result)
        return result

    try:
        updated_records, payload = _build_alert(records, path, spike_threshold, epss_alert_floor)
    except Exception as exc:
        result = {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": f"watch_alert failed: {exc}"}],
        }
        log_tool_output_size("watch_alert", result)
        return result

    if output_format == "json":
        rendered = json.dumps(payload, indent=2, ensure_ascii=False)
    elif output_format == "text":
        rendered = _render_text(payload)
    else:
        rendered = _render_markdown(payload)

    result = {
        "toolUseId": tool_use_id,
        "status": "success",
        "content": [
            {"text": rendered},
            {"json": payload},
        ],
    }
    log_tool_output_size("watch_alert", result)
    return result
