"""
Tool for managing a persistent EPSS watchlist.

Stores watched CVEs in ``~/.manus-agent/watchlist.jsonl`` (one JSON record per
line).  Each record has the shape::

    {
        "cve_id": "CVE-2024-3094",
        "added_at": "2026-06-30",
        "last_checked": "2026-06-30",
        "last_epss": 0.8512,
        "baseline_epss": 0.8512
    }

Supported operations (``action`` parameter):
- **add**    — append a CVE to the watchlist (no-op if already present).
- **remove** — remove a CVE from the watchlist.
- **list**   — return all watched CVEs with their stored EPSS snapshot.
- **check**  — fetch the current EPSS for every watched CVE, compare against
               ``last_epss``, flag any that spiked ≥ ``spike_threshold``
               (default 0.10), and persist the new scores.
"""

from __future__ import annotations

import json
import os
from datetime import date
from pathlib import Path
from typing import Any

import requests
from strands.types.tools import ToolResult, ToolUse

from manus_agent.tools.tool_output_logger import log_tool_output_size

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_WATCHLIST_PATH = Path.home() / ".manus-agent" / "watchlist.jsonl"
_SPIKE_THRESHOLD = 0.10
_CVE_RE_PREFIX = "CVE-"

TOOL_SPEC = {
    "name": "watch_epss",
    "description": (
        "Manage a persistent EPSS watchlist stored in ~/.manus-agent/watchlist.jsonl. "
        "Supported actions: "
        "'add' — add a CVE to the watchlist; "
        "'remove' — remove a CVE from the watchlist; "
        "'list' — show all watched CVEs with their last-recorded EPSS score; "
        "'check' — fetch current EPSS scores for all watched CVEs and report any "
        "that spiked >= spike_threshold (default 0.10) since the last check. "
        "Use this to monitor whether exploitation probability is rising for specific CVEs."
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["add", "remove", "list", "check"],
                    "description": "Operation to perform on the watchlist.",
                },
                "cve_id": {
                    "type": "string",
                    "description": (
                        "CVE identifier (e.g. 'CVE-2024-3094'). "
                        "Required for 'add' and 'remove'; ignored for 'list' and 'check'."
                    ),
                },
                "spike_threshold": {
                    "type": "number",
                    "description": (
                        "Minimum EPSS delta to flag as a spike during 'check'. Defaults to 0.10 (10 percentage points)."
                    ),
                    "default": 0.10,
                },
                "watchlist_path": {
                    "type": "string",
                    "description": ("Override the watchlist file path. Defaults to ~/.manus-agent/watchlist.jsonl."),
                },
            },
            "required": ["action"],
        }
    },
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_path(override: str | None) -> Path:
    """Return the watchlist path, creating parent dirs if needed."""
    p = Path(override) if override else _DEFAULT_WATCHLIST_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _load_watchlist(path: Path) -> list[dict[str, Any]]:
    """Load all records from the watchlist file (empty list if absent)."""
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass  # skip corrupt lines
    return records


def _save_watchlist(path: Path, records: list[dict[str, Any]]) -> None:
    """Overwrite the watchlist file with *records* (one JSON line each)."""
    path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in records) + ("\n" if records else ""),
        encoding="utf-8",
    )


def _today() -> str:
    return date.today().isoformat()


def _fetch_current_epss(cve_ids: list[str]) -> dict[str, float]:
    """
    Fetch the current EPSS score for each CVE in *cve_ids* from FIRST.org.

    Returns a dict mapping CVE-ID (uppercase) → float score.
    Missing or errored CVEs map to -1.0.
    """
    if not cve_ids:
        return {}

    scores: dict[str, float] = {}
    # FIRST.org supports up to ~100 CVEs per request via repeated ?cve= params.
    # We batch in chunks of 50 to stay well within any undocumented server limit.
    chunk_size = 50
    for i in range(0, len(cve_ids), chunk_size):
        chunk = cve_ids[i : i + chunk_size]
        params = [("cve", cid.upper()) for cid in chunk]
        try:
            resp = requests.get(
                "https://api.first.org/data/v1/epss",
                params=params,
                timeout=20,
            )
            resp.raise_for_status()
            data = resp.json()
            for entry in data.get("data", []):
                cid = entry.get("cve", "").upper()
                try:
                    scores[cid] = float(entry.get("epss", -1))
                except (TypeError, ValueError):
                    scores[cid] = -1.0
        except requests.exceptions.RequestException:
            for cid in chunk:
                scores[cid.upper()] = -1.0

    # Fill any that didn't appear in the response
    for cid in cve_ids:
        scores.setdefault(cid.upper(), -1.0)

    return scores


# ---------------------------------------------------------------------------
# Action implementations
# ---------------------------------------------------------------------------


def _action_add(
    records: list[dict[str, Any]],
    cve_id: str,
    path: Path,
) -> tuple[list[dict[str, Any]], str]:
    """Add *cve_id* to the watchlist. Returns (updated_records, message)."""
    cve_upper = cve_id.upper()
    existing = {r["cve_id"].upper() for r in records}
    if cve_upper in existing:
        return records, f"{cve_upper} is already on the watchlist."

    records.append(
        {
            "cve_id": cve_upper,
            "added_at": _today(),
            "last_checked": None,
            "last_epss": None,
            "baseline_epss": None,
        }
    )
    _save_watchlist(path, records)
    return records, f"Added {cve_upper} to the watchlist ({len(records)} total)."


def _action_remove(
    records: list[dict[str, Any]],
    cve_id: str,
    path: Path,
) -> tuple[list[dict[str, Any]], str]:
    """Remove *cve_id* from the watchlist. Returns (updated_records, message)."""
    cve_upper = cve_id.upper()
    before = len(records)
    records = [r for r in records if r["cve_id"].upper() != cve_upper]
    if len(records) == before:
        return records, f"{cve_upper} was not found on the watchlist."
    _save_watchlist(path, records)
    return records, f"Removed {cve_upper} from the watchlist ({len(records)} remaining)."


def _action_list(records: list[dict[str, Any]]) -> str:
    """Return a human-readable summary of all watched CVEs."""
    if not records:
        return "Watchlist is empty. Use 'add' to track CVEs."

    lines = [f"Watching {len(records)} CVE(s):"]
    lines.append(f"  {'CVE-ID':<20}  {'Last EPSS':>10}  {'Checked':<12}  {'Added':<12}")
    lines.append("  " + "-" * 60)
    for r in records:
        epss_str = f"{r['last_epss']:.4f}" if r["last_epss"] is not None else "  (none)"
        checked = r.get("last_checked") or "never"
        added = r.get("added_at", "unknown")
        lines.append(f"  {r['cve_id']:<20}  {epss_str:>10}  {checked:<12}  {added:<12}")
    return "\n".join(lines)


def _action_check(
    records: list[dict[str, Any]],
    path: Path,
    spike_threshold: float,
) -> tuple[list[dict[str, Any]], str]:
    """
    Fetch current EPSS for all watched CVEs, detect spikes, persist new scores.
    Returns (updated_records, report_text).
    """
    if not records:
        return records, "Watchlist is empty. Nothing to check."

    cve_ids = [r["cve_id"].upper() for r in records]
    current_scores = _fetch_current_epss(cve_ids)
    today = _today()

    spikes: list[str] = []
    errors: list[str] = []
    unchanged: list[str] = []

    updated: list[dict[str, Any]] = []
    for r in records:
        cid = r["cve_id"].upper()
        new_score = current_scores.get(cid, -1.0)
        prev_score = r.get("last_epss")

        r = dict(r)  # shallow copy — don't mutate in place
        r["last_checked"] = today

        if new_score < 0:
            errors.append(cid)
            updated.append(r)
            continue

        r["last_epss"] = new_score
        if r.get("baseline_epss") is None:
            r["baseline_epss"] = new_score

        if prev_score is not None and prev_score >= 0:
            delta = new_score - prev_score
            if delta >= spike_threshold:
                spikes.append(f"  ⚠️  {cid}: {prev_score:.4f} → {new_score:.4f}  (Δ +{delta:.4f})")
            else:
                unchanged.append(f"  ✅  {cid}: {new_score:.4f}  (Δ {delta:+.4f})")
        else:
            # First check — just record the score
            unchanged.append(f"  ✅  {cid}: {new_score:.4f}  (first check)")

        updated.append(r)

    _save_watchlist(path, updated)

    lines: list[str] = [f"EPSS watch check — {today} — {len(records)} CVE(s)"]
    lines.append(f"  Spike threshold: ≥{spike_threshold:.2f}")
    lines.append("")

    if spikes:
        lines.append(f"🚨 {len(spikes)} spike(s) detected:")
        lines.extend(spikes)
        lines.append("")

    if unchanged:
        lines.append("No significant change:")
        lines.extend(unchanged)
        lines.append("")

    if errors:
        lines.append("⚡ EPSS lookup failed (API error or unknown CVE):")
        lines.extend(f"  {cid}" for cid in errors)
        lines.append("")

    return updated, "\n".join(lines).rstrip()


# ---------------------------------------------------------------------------
# Tool entry-point
# ---------------------------------------------------------------------------


def watch_epss(tool: ToolUse, **kwargs: Any) -> ToolResult:
    """Manage a persistent EPSS watchlist (add / remove / list / check)."""
    tool_use_id = tool["toolUseId"]
    inp = tool["input"]

    action = (inp.get("action") or "").lower().strip()
    cve_id = (inp.get("cve_id") or "").strip()
    spike_threshold = float(inp.get("spike_threshold") or _SPIKE_THRESHOLD)
    watchlist_path_override = inp.get("watchlist_path") or os.environ.get("MANUS_WATCHLIST_PATH")

    # ------------------------------------------------------------------
    # Validate action
    # ------------------------------------------------------------------
    valid_actions = {"add", "remove", "list", "check"}
    if action not in valid_actions:
        result: ToolResult = {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": f"Unknown action '{action}'. Must be one of: {', '.join(sorted(valid_actions))}."}],
        }
        log_tool_output_size("watch_epss", result)
        return result

    if action in {"add", "remove"} and not cve_id.upper().startswith(_CVE_RE_PREFIX):
        result = {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": f"Invalid CVE ID '{cve_id}'. Must start with 'CVE-' (e.g. CVE-2024-3094)."}],
        }
        log_tool_output_size("watch_epss", result)
        return result

    path = _resolve_path(watchlist_path_override)
    records = _load_watchlist(path)

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------
    try:
        if action == "add":
            records, message = _action_add(records, cve_id, path)
        elif action == "remove":
            records, message = _action_remove(records, cve_id, path)
        elif action == "list":
            message = _action_list(records)
        else:  # check
            records, message = _action_check(records, path, spike_threshold)
    except Exception as exc:
        result = {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": f"watch_epss '{action}' failed: {exc}"}],
        }
        log_tool_output_size("watch_epss", result)
        return result

    result = {
        "toolUseId": tool_use_id,
        "status": "success",
        "content": [
            {"text": message},
            {
                "json": {
                    "action": action,
                    "watchlist_path": str(path),
                    "count": len(records),
                    "records": records,
                }
            },
        ],
    }
    log_tool_output_size("watch_epss", result)
    return result
