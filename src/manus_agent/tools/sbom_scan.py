#!/usr/bin/env python3
"""
Tool for scanning SBOM (Software Bill of Materials) files for known vulnerabilities.

Parses CycloneDX (JSON) or SPDX (JSON) SBOMs, extracts component purls or
name+version tuples, queries OSV.dev in batch for all components, enriches
each finding with EPSS score and CISA KEV membership, and ranks results by
KEV membership first then EPSS score descending.

Public APIs used (no keys required):
- POST https://api.osv.dev/v1/querybatch  — batch vulnerability query
- GET  https://api.osv.dev/v1/vulns/{id}  — individual vuln detail
- GET  https://api.first.org/data/v1/epss  — EPSS scores (bulk)
- GET  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

from __future__ import annotations

import json as _json
import os
import time
from pathlib import Path
from typing import Any

import requests
from strands.types.tools import ToolResult, ToolUse

from manus_agent.tools.tool_output_logger import log_tool_output_size

# ---------------------------------------------------------------------------
# Retry / back-off configuration
# ---------------------------------------------------------------------------
_MAX_RETRIES: int = int(os.environ.get("SBOM_SCAN_MAX_RETRIES", "3"))
_RETRY_BASE_DELAY: float = float(os.environ.get("SBOM_SCAN_RETRY_BASE_DELAY", "1.0"))
_RETRYABLE_STATUSES: frozenset[int] = frozenset({429, 500, 502, 503, 504})

_OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
_EPSS_API_URL = "https://api.first.org/data/v1/epss"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_HTTP_TIMEOUT = 20

# OSV querybatch accepts up to 1000 queries per request.
_OSV_BATCH_SIZE = 1000

# Cap on total components we scan (guards against enormous SBOMs).
_MAX_COMPONENTS = 5000

# EPSS bulk query supports comma-separated CVEs; cap per request.
_EPSS_BATCH_SIZE = 100

TOOL_SPEC = {
    "name": "sbom_scan",
    "description": (
        "Scans a CycloneDX or SPDX SBOM file for known vulnerabilities. "
        "Extracts all components, queries OSV.dev in batch, enriches each "
        "finding with EPSS score and CISA KEV status, and ranks results "
        "by KEV membership then EPSS score descending. Returns a ranked "
        "vulnerability report with critical/high/medium/low counts."
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "bom_file": {
                    "type": "string",
                    "description": ("Path to the SBOM file (CycloneDX JSON or SPDX JSON)."),
                }
            },
            "required": ["bom_file"],
        }
    },
}


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _request_with_retry(
    method: str,
    url: str,
    *,
    json_body: dict | list | None = None,
    params: dict | None = None,
    timeout: int = _HTTP_TIMEOUT,
) -> requests.Response:
    """HTTP request with exponential back-off retry on transient failures."""
    last_exc: Exception | None = None
    for attempt in range(_MAX_RETRIES):
        try:
            resp = requests.request(
                method,
                url,
                json=json_body,
                params=params,
                timeout=timeout,
            )
            if resp.status_code not in _RETRYABLE_STATUSES:
                return resp
            last_exc = requests.exceptions.HTTPError(f"HTTP {resp.status_code}", response=resp)
        except requests.exceptions.RequestException as exc:
            last_exc = exc

        if attempt < _MAX_RETRIES - 1:
            delay = _RETRY_BASE_DELAY * (2**attempt)
            time.sleep(delay)

    # Last attempt failed — raise or return the last response
    if last_exc is not None:
        raise last_exc
    # Should not reach here, but satisfy type checker
    raise RuntimeError("All retry attempts exhausted")  # pragma: no cover


# ---------------------------------------------------------------------------
# SBOM parsing
# ---------------------------------------------------------------------------


def _detect_sbom_format(data: dict) -> str:
    """Detect whether the SBOM is CycloneDX or SPDX. Returns 'cyclonedx' or 'spdx'."""
    if "bomFormat" in data:
        return "cyclonedx"
    if "spdxVersion" in data:
        return "spdx"
    # Fallback heuristics
    if "components" in data:
        return "cyclonedx"
    if "packages" in data:
        return "spdx"
    raise ValueError("Unrecognised SBOM format. Expected CycloneDX (bomFormat) or SPDX (spdxVersion).")


def _parse_purl(purl: str) -> dict[str, str]:
    """
    Minimal purl parser: extract ecosystem, name, version from
    pkg:<type>/<namespace>/<name>@<version> or pkg:<type>/<name>@<version>.
    """
    # Strip scheme
    body = purl
    if body.startswith("pkg:"):
        body = body[4:]

    # Strip qualifiers and subpath
    body = body.split("?")[0].split("#")[0]

    # Split type from rest
    slash_idx = body.find("/")
    if slash_idx < 0:
        return {}
    pkg_type = body[:slash_idx]
    rest = body[slash_idx + 1 :]

    # Split version
    version = ""
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)

    # rest is namespace/name or just name
    name = rest.replace("/", ":")  # preserve namespace as prefix

    # Map purl type to OSV ecosystem
    ecosystem_map = {
        "pypi": "PyPI",
        "npm": "npm",
        "maven": "Maven",
        "golang": "Go",
        "cargo": "crates.io",
        "nuget": "NuGet",
        "gem": "RubyGems",
        "composer": "Packagist",
        "pub": "Pub",
        "hex": "Hex",
        "hackage": "Hackage",
        "swift": "SwiftURL",
        "cocoapods": "CocoaPods",
        "cran": "CRAN",
        "deb": "Debian",
        "rpm": "Alpine",  # rough; OSV uses distro names
        "apk": "Alpine",
        "github": "GitHub Actions",
    }
    ecosystem = ecosystem_map.get(pkg_type.lower(), pkg_type)

    return {"ecosystem": ecosystem, "name": name, "version": version}


def _extract_cyclonedx_components(data: dict) -> list[dict[str, str]]:
    """Extract components from CycloneDX SBOM."""
    components = []
    for comp in data.get("components", []):
        name = comp.get("name", "")
        version = comp.get("version", "")
        purl = comp.get("purl", "")

        if purl:
            parsed = _parse_purl(purl)
            if parsed.get("name") and parsed.get("version"):
                components.append(parsed)
                continue

        # Fallback: use name + version directly
        if name and version:
            # Try to guess ecosystem from component type
            comp_type = comp.get("type", "")
            ecosystem = _guess_ecosystem_from_type(comp_type, name)
            components.append({"ecosystem": ecosystem, "name": name, "version": version})

    return components


def _extract_spdx_components(data: dict) -> list[dict[str, str]]:
    """Extract packages from SPDX SBOM."""
    components = []
    for pkg in data.get("packages", []):
        name = pkg.get("name", "")
        version = pkg.get("versionInfo", "")

        # Check for external refs with purl
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                parsed = _parse_purl(ref.get("referenceLocator", ""))
                if parsed.get("name") and parsed.get("version"):
                    components.append(parsed)
                    break
        else:
            # No purl found; use name + version
            if name and version:
                components.append({"ecosystem": "", "name": name, "version": version})

    return components


def _guess_ecosystem_from_type(comp_type: str, name: str) -> str:
    """Best-effort ecosystem guess from CycloneDX component type."""
    # CycloneDX component types: library, framework, application, etc.
    # We can't reliably determine ecosystem from these alone.
    # Return empty string to let OSV do package-name matching.
    _ = comp_type, name
    return ""


def parse_sbom(file_path: str) -> list[dict[str, str]]:
    """
    Parse an SBOM file and return a list of component dicts with keys:
    ecosystem, name, version.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"SBOM file not found: {file_path}")

    content = path.read_text(encoding="utf-8")
    try:
        data = _json.loads(content)
    except _json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in SBOM file: {exc}") from exc

    fmt = _detect_sbom_format(data)

    if fmt == "cyclonedx":
        components = _extract_cyclonedx_components(data)
    else:
        components = _extract_spdx_components(data)

    # Deduplicate by (ecosystem, name, version)
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, str]] = []
    for comp in components:
        key = (comp["ecosystem"], comp["name"], comp["version"])
        if key not in seen:
            seen.add(key)
            unique.append(comp)

    if len(unique) > _MAX_COMPONENTS:
        unique = unique[:_MAX_COMPONENTS]

    return unique


# ---------------------------------------------------------------------------
# OSV.dev batch query
# ---------------------------------------------------------------------------


def _build_osv_queries(components: list[dict[str, str]]) -> list[dict]:
    """Build OSV querybatch queries from component list."""
    queries = []
    for comp in components:
        q: dict[str, Any] = {}
        if comp.get("ecosystem") and comp.get("name") and comp.get("version"):
            q["package"] = {
                "name": comp["name"],
                "ecosystem": comp["ecosystem"],
            }
            q["version"] = comp["version"]
        elif comp.get("name") and comp.get("version"):
            # No ecosystem — query by package name only
            q["package"] = {"name": comp["name"]}
            q["version"] = comp["version"]
        else:
            continue
        queries.append(q)
    return queries


def _query_osv_batch(queries: list[dict]) -> list[list[dict]]:
    """
    Query OSV.dev /v1/querybatch in batches.
    Returns a list parallel to queries, each element being a list of vulns.
    """
    all_results: list[list[dict]] = []

    for i in range(0, len(queries), _OSV_BATCH_SIZE):
        batch = queries[i : i + _OSV_BATCH_SIZE]
        try:
            resp = _request_with_retry(
                "POST",
                _OSV_QUERYBATCH_URL,
                json_body={"queries": batch},
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", [])
            for r in results:
                all_results.append(r.get("vulns", []))
        except Exception:
            # On failure, mark all queries in this batch as having no results
            all_results.extend([] for _ in batch)

    return all_results


def _fetch_vuln_detail(vuln_id: str) -> dict:
    """Fetch full vulnerability detail from OSV.dev."""
    try:
        resp = _request_with_retry("GET", _OSV_VULN_URL.format(vuln_id=vuln_id))
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# EPSS enrichment
# ---------------------------------------------------------------------------


def _fetch_epss_bulk(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS scores for a list of CVE IDs. Returns {cve_id: score}."""
    scores: dict[str, float] = {}
    if not cve_ids:
        return scores

    for i in range(0, len(cve_ids), _EPSS_BATCH_SIZE):
        batch = cve_ids[i : i + _EPSS_BATCH_SIZE]
        try:
            resp = _request_with_retry(
                "GET",
                _EPSS_API_URL,
                params={"cve": ",".join(batch)},
            )
            resp.raise_for_status()
            data = resp.json()
            for item in data.get("data", []):
                cve = item.get("cve", "")
                epss = float(item.get("epss", 0.0))
                scores[cve] = epss
        except Exception:
            pass  # Graceful degradation — missing EPSS is not fatal

    return scores


# ---------------------------------------------------------------------------
# CISA KEV enrichment
# ---------------------------------------------------------------------------


def _fetch_kev_set() -> set[str]:
    """Fetch CISA KEV catalog and return set of CVE IDs."""
    try:
        resp = _request_with_retry("GET", _KEV_URL)
        resp.raise_for_status()
        data = resp.json()
        return {v.get("cveID", "").upper() for v in data.get("vulnerabilities", []) if v.get("cveID")}
    except Exception:
        return set()


# ---------------------------------------------------------------------------
# Core scan logic
# ---------------------------------------------------------------------------


def _extract_cve_ids(vulns: list[dict]) -> list[str]:
    """Extract CVE IDs from OSV vulnerability records."""
    cves: list[str] = []
    for v in vulns:
        vuln_id = v.get("id", "")
        if vuln_id.upper().startswith("CVE-"):
            cves.append(vuln_id.upper())
        for alias in v.get("aliases", []):
            if alias.upper().startswith("CVE-"):
                cves.append(alias.upper())
    return list(set(cves))


def _severity_label(cvss_score: float | None) -> str:
    """Map CVSS score to severity label."""
    if cvss_score is None:
        return "unknown"
    if cvss_score >= 9.0:
        return "critical"
    if cvss_score >= 7.0:
        return "high"
    if cvss_score >= 4.0:
        return "medium"
    if cvss_score > 0.0:
        return "low"
    return "none"


def _extract_cvss_score(vuln: dict) -> float | None:
    """Extract the highest CVSS score from a vulnerability record."""
    best: float | None = None
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        # OSV severity may be a CVSS vector string; try to parse score from it
        if "/" in str(score_str):
            # CVSS vector — extract base score if present as last segment or similar
            # Fall back to database_specific
            continue
        try:
            s = float(score_str)
            if best is None or s > best:
                best = s
        except (ValueError, TypeError):
            continue

    # Also check database_specific for CVSS
    db_specific = vuln.get("database_specific", {})
    if isinstance(db_specific, dict):
        for key in ("cvss_score", "severity_score", "cvss"):
            val = db_specific.get(key)
            if val is not None:
                try:
                    s = float(val)
                    if best is None or s > best:
                        best = s
                except (ValueError, TypeError):
                    pass
        # GHSA severity mapping
        ghsa_sev = db_specific.get("severity")
        if isinstance(ghsa_sev, str) and best is None:
            sev_map = {
                "CRITICAL": 9.5,
                "HIGH": 7.5,
                "MODERATE": 5.5,
                "LOW": 2.5,
            }
            mapped = sev_map.get(ghsa_sev.upper())
            if mapped is not None:
                best = mapped

    return best


def scan_sbom(file_path: str) -> dict[str, Any]:
    """
    Scan an SBOM file for vulnerabilities.

    Returns a dict with:
      - components_scanned: int
      - vulnerabilities_found: int
      - critical_count, high_count, medium_count, low_count, unknown_count: int
      - findings: list of finding dicts ranked by KEV then EPSS
      - summary: human-readable summary string
    """
    # 1. Parse SBOM
    components = parse_sbom(file_path)
    if not components:
        return {
            "components_scanned": 0,
            "vulnerabilities_found": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "unknown_count": 0,
            "findings": [],
            "summary": "No components found in SBOM file.",
        }

    # 2. Build OSV queries and run batch
    queries = _build_osv_queries(components)
    osv_results = _query_osv_batch(queries)

    # 3. Collect all unique vulns across all components
    # Map: vuln_id -> {vuln_data, affected_components}
    vuln_map: dict[str, dict[str, Any]] = {}
    for idx, vulns in enumerate(osv_results):
        comp = components[idx] if idx < len(components) else {}
        comp_label = (
            f"{comp.get('ecosystem', '')}:{comp['name']}@{comp['version']}"
            if comp.get("ecosystem")
            else f"{comp.get('name', '?')}@{comp.get('version', '?')}"
        )
        for v in vulns:
            vid = v.get("id", "")
            if vid not in vuln_map:
                vuln_map[vid] = {
                    "vuln_id": vid,
                    "aliases": v.get("aliases", []),
                    "summary": v.get("summary", ""),
                    "details": v.get("details", ""),
                    "affected_components": [],
                    "severity": v.get("severity", []),
                    "database_specific": v.get("database_specific", {}),
                    "references": v.get("references", []),
                }
            vuln_map[vid]["affected_components"].append(comp_label)

    if not vuln_map:
        return {
            "components_scanned": len(components),
            "vulnerabilities_found": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "unknown_count": 0,
            "findings": [],
            "summary": f"Scanned {len(components)} components. No known vulnerabilities found.",
        }

    # 4. Collect all CVE IDs for EPSS + KEV enrichment
    all_cves: set[str] = set()
    for entry in vuln_map.values():
        vid = entry["vuln_id"]
        if vid.upper().startswith("CVE-"):
            all_cves.add(vid.upper())
        for alias in entry.get("aliases", []):
            if alias.upper().startswith("CVE-"):
                all_cves.add(alias.upper())

    # 5. Fetch EPSS scores and KEV set
    epss_scores = _fetch_epss_bulk(sorted(all_cves))
    kev_set = _fetch_kev_set()

    # 6. Build findings with enrichment
    findings: list[dict[str, Any]] = []
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
    }

    for entry in vuln_map.values():
        vid = entry["vuln_id"]
        # Find CVE ID for this vuln
        cve_id = None
        if vid.upper().startswith("CVE-"):
            cve_id = vid.upper()
        else:
            for alias in entry.get("aliases", []):
                if alias.upper().startswith("CVE-"):
                    cve_id = alias.upper()
                    break

        epss = epss_scores.get(cve_id, 0.0) if cve_id else 0.0
        in_kev = cve_id in kev_set if cve_id else False
        cvss = _extract_cvss_score(entry)
        sev = _severity_label(cvss)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Deduplicate affected components
        affected = sorted(set(entry["affected_components"]))

        finding = {
            "vuln_id": vid,
            "cve_id": cve_id,
            "aliases": entry.get("aliases", []),
            "summary": entry.get("summary", ""),
            "cvss_score": cvss,
            "severity": sev,
            "epss_score": epss,
            "in_kev": in_kev,
            "affected_components": affected,
        }
        findings.append(finding)

    # 7. Rank: KEV first (True > False when reversed), then EPSS descending
    findings.sort(key=lambda f: (f["in_kev"], f["epss_score"]), reverse=True)

    total_vulns = len(findings)
    summary_parts = [
        f"Scanned {len(components)} components.",
        f"Found {total_vulns} known vulnerabilities.",
    ]
    if severity_counts["critical"]:
        summary_parts.append(f"  Critical: {severity_counts['critical']}")
    if severity_counts["high"]:
        summary_parts.append(f"  High: {severity_counts['high']}")
    if severity_counts["medium"]:
        summary_parts.append(f"  Medium: {severity_counts['medium']}")
    if severity_counts["low"]:
        summary_parts.append(f"  Low: {severity_counts['low']}")
    kev_count = sum(1 for f in findings if f["in_kev"])
    if kev_count:
        summary_parts.append(f"  CISA KEV: {kev_count} actively exploited")

    return {
        "components_scanned": len(components),
        "vulnerabilities_found": total_vulns,
        "critical_count": severity_counts["critical"],
        "high_count": severity_counts["high"],
        "medium_count": severity_counts["medium"],
        "low_count": severity_counts["low"],
        "unknown_count": severity_counts.get("unknown", 0),
        "findings": findings,
        "summary": "\n".join(summary_parts),
    }


# ---------------------------------------------------------------------------
# Strands tool entry point
# ---------------------------------------------------------------------------


def sbom_scan(tool: ToolUse, **kwargs: Any) -> ToolResult:
    """Strands tool: scan an SBOM for known vulnerabilities."""
    tool_use_id = tool["toolUseId"]
    tool_input = tool["input"]
    bom_file = tool_input.get("bom_file", "")

    if not isinstance(bom_file, str) or not bom_file.strip():
        result: ToolResult = {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": "bom_file is required and must be a non-empty string."}],
        }
        log_tool_output_size("sbom_scan", result)
        return result

    try:
        payload = scan_sbom(bom_file.strip())
    except FileNotFoundError as exc:
        result = {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": str(exc)}],
        }
        log_tool_output_size("sbom_scan", result)
        return result
    except ValueError as exc:
        result = {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": str(exc)}],
        }
        log_tool_output_size("sbom_scan", result)
        return result
    except Exception as exc:
        result = {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": f"Unexpected error scanning SBOM: {exc}"}],
        }
        log_tool_output_size("sbom_scan", result)
        return result

    result = {
        "toolUseId": tool_use_id,
        "status": "success",
        "content": [{"text": _json.dumps(payload, indent=2)}],
    }
    log_tool_output_size("sbom_scan", result)
    return result
