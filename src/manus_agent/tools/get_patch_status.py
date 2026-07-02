"""
Tool: get_patch_status

Given a CVE ID, reports the patch availability status for each affected package:
  - First patched version (from GitHub Advisory DB or OSV.dev)
  - CVE disclosure date (from NVD)
  - Patch release date (from the package registry: PyPI, npm, or Maven Central)
  - Patch lag in days (disclosure → patch release)
  - Patch lag label: FAST (<7 d), NORMAL (7–30 d), SLOW (>30 d), MISSING (no patch)

Data sources (all free, no API key required):
  1. NVD CVE 2.0 API  — CVE disclosure date + CVSS severity
  2. GitHub Advisory DB (api.github.com/advisories) — first_patched_version per package
  3. OSV.dev API      — cross-ecosystem fix version (fallback / cross-check)
  4. PyPI JSON API    — upload_time for the patched version
  5. npm registry API — time map for the patched version
  6. Maven Central    — release date approximation via search API

CLI: ``manus-agent patch-status CVE-2021-44228``
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

import requests
from strands import tool
from strands.types.tools import ToolResult, ToolUse

from manus_agent.tools.tool_output_logger import log_tool_output_size

__all__ = ["get_patch_status"]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
_TIMEOUT = 20

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_GHSA_API_URL = "https://api.github.com/advisories"
_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
_PYPI_JSON_URL = "https://pypi.org/pypi/{}/json"
_NPM_PKG_URL = "https://registry.npmjs.org/{}"
_MAVEN_SEARCH_URL = "https://search.maven.org/solrsearch/select"

# Patch lag thresholds (days)
_FAST_DAYS = 7
_NORMAL_DAYS = 30

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get(url: str, params: dict | None = None, headers: dict | None = None) -> Any:
    """GET with timeout; returns parsed JSON or raises."""
    r = requests.get(url, params=params or {}, headers=headers or {}, timeout=_TIMEOUT)
    r.raise_for_status()
    return r.json()


def _post(url: str, payload: dict) -> Any:
    """POST JSON with timeout; returns parsed JSON or raises."""
    r = requests.post(url, json=payload, timeout=_TIMEOUT)
    r.raise_for_status()
    return r.json()


def _github_headers() -> dict[str, str]:
    token = os.environ.get("GITHUB_TOKEN", "")
    h: dict[str, str] = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _parse_iso(dt_str: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp into a timezone-aware datetime or None."""
    if not dt_str:
        return None
    # Handle both 'Z' suffix and '+00:00'
    dt_str = dt_str.rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
        try:
            return datetime.strptime(dt_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _patch_lag_label(days: int | None) -> str:
    """Convert days-to-patch into a human-readable label."""
    if days is None:
        return "MISSING"
    if days < 0:
        # Patch released before disclosure (coordinated disclosure)
        return "FAST"
    if days <= _FAST_DAYS:
        return "FAST"
    if days <= _NORMAL_DAYS:
        return "NORMAL"
    return "SLOW"


# ---------------------------------------------------------------------------
# Data fetchers
# ---------------------------------------------------------------------------


def _fetch_nvd_cve(cve_id: str) -> dict[str, Any]:
    """Return NVD CVE record or empty dict."""
    try:
        data = _get(_NVD_URL, params={"cveId": cve_id.upper()})
        vulns = data.get("vulnerabilities", [])
        if vulns:
            return vulns[0].get("cve", {})
    except Exception as exc:
        logger.debug("NVD fetch failed for %s: %s", cve_id, exc)
    return {}


def _fetch_ghsa_vulns(cve_id: str) -> list[dict[str, Any]]:
    """
    Query GitHub Advisory DB for the CVE.
    Returns list of vulnerability records: {package, ecosystem, patched_version, advisory_id}.
    """
    results: list[dict[str, Any]] = []
    try:
        advisories = _get(_GHSA_API_URL, params={"cve_id": cve_id.upper(), "per_page": 10}, headers=_github_headers())
        if not isinstance(advisories, list):
            return results
        for adv in advisories:
            adv_id = adv.get("ghsa_id", "")
            for vuln in adv.get("vulnerabilities", []):
                pkg = vuln.get("package", {})
                patched = vuln.get("first_patched_version")
                if pkg.get("name"):
                    results.append(
                        {
                            "advisory_id": adv_id,
                            "name": pkg["name"],
                            "ecosystem": (pkg.get("ecosystem") or "").lower(),
                            "patched_version": patched,
                            "vulnerable_range": vuln.get("vulnerable_version_range", ""),
                        }
                    )
    except Exception as exc:
        logger.debug("GHSA fetch failed for %s: %s", cve_id, exc)
    return results


def _fetch_osv_vulns(cve_id: str) -> list[dict[str, Any]]:
    """
    Query OSV.dev for the CVE.
    Returns list of {name, ecosystem, patched_version} dicts.
    """
    results: list[dict[str, Any]] = []
    try:
        data = _post(_OSV_QUERY_URL, {"id": cve_id.upper()})
        for vuln in data.get("vulns", []):
            vid = vuln.get("id", "")
            try:
                full = _get(_OSV_VULN_URL.format(vid))
            except Exception:
                continue
            for affected in full.get("affected", []):
                pkg = affected.get("package", {})
                name = pkg.get("name", "")
                ecosystem = (pkg.get("ecosystem") or "").lower()
                if not name:
                    continue
                # Extract first "fixed" event from ranges
                patched_ver: str | None = None
                for rng in affected.get("ranges", []):
                    for evt in rng.get("events", []):
                        if "fixed" in evt:
                            patched_ver = evt["fixed"]
                            break
                    if patched_ver:
                        break
                results.append(
                    {"advisory_id": vid, "name": name, "ecosystem": ecosystem, "patched_version": patched_ver}
                )
    except Exception as exc:
        logger.debug("OSV fetch failed for %s: %s", cve_id, exc)
    return results


# ---------------------------------------------------------------------------
# Registry: patch release date lookup
# ---------------------------------------------------------------------------


def _pypi_release_date(package: str, version: str) -> datetime | None:
    """Return the upload_time of *version* on PyPI."""
    try:
        data = _get(_PYPI_JSON_URL.format(package))
        files = data.get("releases", {}).get(version, [])
        if files:
            return _parse_iso(files[0].get("upload_time"))
    except Exception as exc:
        logger.debug("PyPI release lookup failed %s@%s: %s", package, version, exc)
    return None


def _npm_release_date(package: str, version: str) -> datetime | None:
    """Return the publish time of *version* on npm."""
    try:
        data = _get(_NPM_PKG_URL.format(package))
        time_map = data.get("time", {})
        ts = time_map.get(version)
        return _parse_iso(ts) if ts else None
    except Exception as exc:
        logger.debug("npm release lookup failed %s@%s: %s", package, version, exc)
    return None


def _maven_release_date(package: str, version: str) -> datetime | None:
    """
    Approximate Maven release date via Maven Central search.
    Maven Central doesn't expose upload timestamps directly, so we return None
    and let the caller fall back to the advisory published date.
    """
    # Maven Central Solr search returns `timestamp` (ms epoch) for the *latest*
    # version only; for a specific version we'd need the API to be queried differently.
    # group:artifact format expected in package.
    try:
        if ":" in package:
            group_id, artifact_id = package.split(":", 1)
        else:
            artifact_id = package
            group_id = ""
        query = f"g:{group_id} AND a:{artifact_id} AND v:{version}" if group_id else f"a:{artifact_id} AND v:{version}"
        data = _get(_MAVEN_SEARCH_URL, params={"q": query, "rows": 1, "wt": "json"})
        docs = data.get("response", {}).get("docs", [])
        if docs:
            ts_ms = docs[0].get("timestamp")
            if ts_ms:
                return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
    except Exception as exc:
        logger.debug("Maven release lookup failed %s@%s: %s", package, version, exc)
    return None


def _registry_release_date(name: str, ecosystem: str, version: str) -> datetime | None:
    """Dispatch to the correct registry by ecosystem."""
    eco = ecosystem.lower()
    if eco == "pypi":
        return _pypi_release_date(name, version)
    if eco in ("npm", "node", "nodejs"):
        return _npm_release_date(name, version)
    if eco in ("maven", "java"):
        return _maven_release_date(name, version)
    # For other ecosystems (Go, Rust, Ruby, etc.) we don't have a simple
    # release-date API; fall back to None.
    return None


# ---------------------------------------------------------------------------
# Merging / deduplication
# ---------------------------------------------------------------------------


def _merge_vulns(ghsa: list[dict], osv: list[dict]) -> list[dict]:
    """
    Merge GHSA and OSV records, preferring GHSA (it has structured patched_version).
    Deduplicate by (name.lower(), ecosystem).
    """
    seen: dict[tuple[str, str], dict] = {}
    for rec in ghsa + osv:
        key = (rec["name"].lower(), rec.get("ecosystem", "").lower())
        if key not in seen:
            seen[key] = rec
        else:
            # Upgrade if the existing record has no patched_version
            if not seen[key].get("patched_version") and rec.get("patched_version"):
                seen[key] = rec
    return list(seen.values())


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def _run_patch_status(cve_id: str) -> dict[str, Any]:
    """
    Compute patch status for *cve_id*.

    Returns a dict with keys:
      cve_id, cve_published, severity, packages, summary
    where each package entry has:
      name, ecosystem, patched_version, patch_release_date,
      patch_lag_days, patch_lag_label, advisory_id
    """
    cve_id = cve_id.strip().upper()
    if not _CVE_RE.match(cve_id):
        return {"error": f"Invalid CVE ID: {cve_id!r}. Expected format: CVE-YYYY-NNNNN"}

    # 1. CVE disclosure date from NVD
    nvd = _fetch_nvd_cve(cve_id)
    cve_published_str = nvd.get("published")
    cve_published = _parse_iso(cve_published_str)
    severity = "UNKNOWN"
    if nvd.get("metrics"):
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = nvd["metrics"].get(metric_key, [])
            if metrics:
                severity = metrics[0].get("cvssData", {}).get("baseSeverity") or metrics[0].get(
                    "baseSeverity", "UNKNOWN"
                )
                break

    # 2. Affected packages + first patched version
    ghsa_vulns = _fetch_ghsa_vulns(cve_id)
    osv_vulns = _fetch_osv_vulns(cve_id)
    merged = _merge_vulns(ghsa_vulns, osv_vulns)

    if not merged:
        return {
            "cve_id": cve_id,
            "cve_published": cve_published_str or "unknown",
            "severity": severity,
            "packages": [],
            "summary": (
                f"No affected package records found for {cve_id} in the GitHub Advisory DB or OSV.dev. "
                "The CVE may be an infrastructure/OS issue (no named package), too recent to be indexed, "
                "or may use CPE-style records only."
            ),
        }

    # 3. For each package: look up the patch release date
    package_results: list[dict[str, Any]] = []
    for rec in merged:
        name = rec["name"]
        ecosystem = rec.get("ecosystem", "unknown")
        patched_ver = rec.get("patched_version")
        advisory_id = rec.get("advisory_id", "")

        patch_release_date: datetime | None = None
        patch_release_str: str | None = None
        patch_lag_days: int | None = None

        if patched_ver:
            patch_release_date = _registry_release_date(name, ecosystem, patched_ver)
            if patch_release_date:
                patch_release_str = patch_release_date.strftime("%Y-%m-%d")
                if cve_published:
                    delta = patch_release_date - cve_published
                    patch_lag_days = delta.days

        lag_label = _patch_lag_label(patch_lag_days)

        package_results.append(
            {
                "name": name,
                "ecosystem": ecosystem,
                "patched_version": patched_ver or "unknown",
                "patch_release_date": patch_release_str or "unknown",
                "patch_lag_days": patch_lag_days,
                "patch_lag_label": lag_label,
                "advisory_id": advisory_id,
            }
        )

    # 4. Build summary
    patched_count = sum(1 for p in package_results if p["patched_version"] != "unknown")
    missing_count = len(package_results) - patched_count
    labels = [p["patch_lag_label"] for p in package_results if p["patch_lag_label"] != "MISSING"]
    dominant_label = max(set(labels), key=labels.count) if labels else "MISSING"

    summary_parts = [f"{cve_id} affects {len(package_results)} package(s)."]
    if patched_count:
        summary_parts.append(f"{patched_count} patched.")
    if missing_count:
        summary_parts.append(f"{missing_count} unpatched (no fix version available).")
    summary_parts.append(f"Overall patch lag: {dominant_label}.")

    return {
        "cve_id": cve_id,
        "cve_published": cve_published_str or "unknown",
        "severity": severity,
        "packages": package_results,
        "summary": " ".join(summary_parts),
    }


# ---------------------------------------------------------------------------
# Strands tool
# ---------------------------------------------------------------------------

_TOOL_SPEC = {
    "name": "get_patch_status",
    "description": (
        "Reports patch availability and patch-lag for a CVE: first patched version "
        "per affected package (from GitHub Advisory DB and OSV.dev), the date the "
        "patched version was released to the package registry (PyPI, npm, Maven), "
        "the number of days between CVE disclosure and patch release, and a "
        "patch_lag_label — FAST (≤7 days), NORMAL (8–30 days), SLOW (>30 days), "
        "or MISSING (no patch available). Use this after get_nvd_data to understand "
        "how quickly the affected ecosystem responded to the vulnerability."
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier to check (e.g. CVE-2021-44228).",
                }
            },
            "required": ["cve_id"],
        }
    },
}


@tool
def get_patch_status(tool: ToolUse, **kwargs: Any) -> ToolResult:
    """Report patch availability, release date, and patch-lag label for a CVE."""
    params = tool.get("input", {})
    cve_id = params.get("cve_id", "").strip()

    if not cve_id:
        return {
            "toolUseId": tool["toolUseId"],
            "status": "error",
            "content": [{"text": "cve_id is required."}],
        }

    result = _run_patch_status(cve_id)

    if "error" in result:
        return {
            "toolUseId": tool["toolUseId"],
            "status": "error",
            "content": [{"text": result["error"]}],
        }

    # Format text output
    lines: list[str] = [
        f"Patch Status — {result['cve_id']}",
        "=" * 50,
        f"CVE Published : {result['cve_published']}",
        f"Severity      : {result['severity']}",
        f"Summary       : {result['summary']}",
        "",
    ]

    for pkg in result["packages"]:
        lag_str = f"{pkg['patch_lag_days']} days" if pkg["patch_lag_days"] is not None else "N/A"
        lines += [
            f"  Package   : {pkg['name']} ({pkg['ecosystem']})",
            f"  Patched   : {pkg['patched_version']}",
            f"  Released  : {pkg['patch_release_date']}",
            f"  Lag       : {lag_str}  [{pkg['patch_lag_label']}]",
            f"  Advisory  : {pkg['advisory_id']}",
            "",
        ]

    text_output = "\n".join(lines)
    log_tool_output_size("get_patch_status", text_output)

    return {
        "toolUseId": tool["toolUseId"],
        "status": "success",
        "content": [{"text": text_output}],
    }
