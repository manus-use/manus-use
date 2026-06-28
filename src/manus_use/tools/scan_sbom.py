"""
Tool: scan_sbom

Given a Software Bill of Materials (SBOM) file in CycloneDX (JSON or XML) or
SPDX (JSON) format, identifies which components have known CVEs and produces a
prioritised risk report.

**Supported formats:**
- CycloneDX 1.4+ JSON  (``bomFormat: "CycloneDX"``)
- CycloneDX 1.4+ XML   (``<bom>`` root element)
- SPDX 2.x JSON        (``spdxVersion`` key)

**Data sources (all free, no auth required):**

1. **OSV.dev** — batch-queries all packages against the OSV vulnerability
   database. Returns CVE/GHSA identifiers per affected package+version.
2. **NVD EPSS** (first.org) — fetches the current EPSS score for each
   discovered CVE, giving an exploitation-probability signal.
3. **CISA KEV** — a single bulk download used to flag CVEs actively exploited
   in the wild.

**Output:**
A structured ``SBOMScanResult`` dict containing:

- ``component_count`` — total components parsed from the SBOM
- ``vulnerable_count`` — components with at least one CVE
- ``findings`` — list of ``Finding`` dicts, sorted by descending EPSS score
- ``kev_hits`` — CVEs in the CISA KEV catalog found in this SBOM
- ``summary`` — human-readable summary paragraph

Each ``Finding`` contains:
  ``component`` (name@version), ``purl``, ``cve_ids``, ``epss_max``,
  ``in_kev`` (bool), ``severity_label`` (CRITICAL/HIGH/MEDIUM/LOW/INFO),
  ``osv_ids`` (raw OSV IDs).

All HTTP calls are isolated to module-level helpers and fully mockable.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any

import requests
from strands import tool

__all__ = ["scan_sbom"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_EPSS_URL = "https://api.first.org/data/v1/epss"
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# OSV API limit: 1000 queries per batch request; we use 100 to be safe
_OSV_BATCH_SIZE = 100
# EPSS API accepts up to 100 CVE IDs per request
_EPSS_BATCH_SIZE = 100

# EPSS severity thresholds
_SEVERITY_THRESHOLDS: list[tuple[float, str]] = [
    (0.5, "CRITICAL"),
    (0.1, "HIGH"),
    (0.01, "MEDIUM"),
    (0.001, "LOW"),
]

# ---------------------------------------------------------------------------
# SBOM parsing helpers
# ---------------------------------------------------------------------------


def _parse_cyclonedx_json(data: dict[str, Any]) -> list[dict[str, str]]:
    """Extract name/version/purl tuples from a CycloneDX JSON BOM."""
    components: list[dict[str, str]] = []
    for comp in data.get("components", []):
        name = comp.get("name", "")
        version = comp.get("version", "")
        purl = comp.get("purl", "")
        if name:
            components.append({"name": name, "version": version, "purl": purl})
    return components


def _parse_cyclonedx_xml(text: str) -> list[dict[str, str]]:
    """Extract name/version/purl tuples from a CycloneDX XML BOM."""
    root = ET.fromstring(text)

    # Detect namespace from root tag, e.g. "{http://cyclonedx.org/schema/bom/1.4}"
    ns_uri = ""
    m = re.match(r"\{(.+?)\}", root.tag)
    if m:
        ns_uri = m.group(1)
    ns = {"cdx": ns_uri} if ns_uri else {}

    def _find_all(parent: ET.Element, tag: str) -> list[ET.Element]:
        if ns:
            return parent.findall(f"cdx:{tag}", ns)
        return parent.findall(tag)

    def _find_text(parent: ET.Element, tag: str) -> str:
        el = parent.find(f"cdx:{tag}", ns) if ns else parent.find(tag)
        return (el.text or "").strip() if el is not None else ""

    components: list[dict[str, str]] = []
    # Components live inside a <components> wrapper
    containers = _find_all(root, "components")
    if not containers:
        containers = [root]
    for container in containers:
        for comp in _find_all(container, "component"):
            name = _find_text(comp, "name")
            version = _find_text(comp, "version")
            purl_el = comp.find("cdx:purl", ns) if ns else comp.find("purl")
            purl = (purl_el.text or "").strip() if purl_el is not None else ""
            if name:
                components.append({"name": name, "version": version, "purl": purl})
    return components


def _parse_spdx_json(data: dict[str, Any]) -> list[dict[str, str]]:
    """Extract name/version/purl tuples from an SPDX 2.x JSON document."""
    components: list[dict[str, str]] = []
    for pkg in data.get("packages", []):
        name = pkg.get("name", "")
        version = pkg.get("versionInfo", "")
        purl = ""
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                break
        if name:
            components.append({"name": name, "version": version, "purl": purl})
    return components


def _parse_sbom(content: str) -> list[dict[str, str]]:
    """Auto-detect SBOM format and return a list of component dicts."""
    stripped = content.strip()

    if stripped.startswith("{"):
        data = json.loads(stripped)
        if data.get("bomFormat", "").lower() == "cyclonedx" or "components" in data:
            return _parse_cyclonedx_json(data)
        if "spdxVersion" in data or "packages" in data:
            return _parse_spdx_json(data)
        raise ValueError("Unrecognised JSON SBOM: no bomFormat or spdxVersion key")

    if stripped.startswith("<"):
        return _parse_cyclonedx_xml(stripped)

    raise ValueError("Unrecognised SBOM format — expected JSON or XML")


# ---------------------------------------------------------------------------
# Package URL → OSV package conversion
# ---------------------------------------------------------------------------

_ECOSYSTEM_MAP: dict[str, str] = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "golang": "Go",
    "nuget": "NuGet",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "hex": "Hex",
    "composer": "Packagist",
    "cocoapods": "CocoaPods",
    "swift": "SwiftURL",
}


def _purl_to_osv_package(purl: str) -> dict[str, str] | None:
    """Convert a Package URL to an OSV package query dict, or None if unsupported."""
    if not purl:
        return None
    # Strip qualifiers and sub-path
    base = purl.split("?")[0].split("#")[0]
    m = re.match(r"pkg:([^/]+)/(.+)", base)
    if not m:
        return None
    ecosystem_raw, rest = m.group(1).lower(), m.group(2)
    # rest may be "namespace/name@version" or "name@version"
    pkg_part = rest.rsplit("@", 1)[0] if "@" in rest else rest

    ecosystem = _ECOSYSTEM_MAP.get(ecosystem_raw)
    if not ecosystem:
        return None

    # Maven uses "group:artifact" notation; PURL uses "group/artifact"
    pkg_name = pkg_part.replace("/", ":") if ecosystem == "Maven" else pkg_part
    return {"name": pkg_name, "ecosystem": ecosystem}


def _name_to_osv_guesses(name: str) -> list[dict[str, str]]:
    """Fallback: try PyPI and npm when no PURL is available."""
    return [
        {"name": name, "ecosystem": "PyPI"},
        {"name": name, "ecosystem": "npm"},
    ]


# ---------------------------------------------------------------------------
# OSV batch query
# ---------------------------------------------------------------------------


def _build_osv_queries(
    components: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], list[int]]:
    """
    Build OSV query objects and a parallel index mapping query position →
    component index. One component may emit >1 query (no-PURL fallback).
    """
    queries: list[dict[str, Any]] = []
    comp_indices: list[int] = []

    for i, comp in enumerate(components):
        version = comp.get("version", "")
        purl = comp.get("purl", "")

        if purl:
            pkg = _purl_to_osv_package(purl)
            if pkg:
                q: dict[str, Any] = {"package": pkg}
                if version:
                    q["version"] = version
                queries.append(q)
                comp_indices.append(i)
                continue

        # Fallback: guess ecosystem from bare name
        for pkg_guess in _name_to_osv_guesses(comp["name"]):
            q = {"package": pkg_guess}
            if version:
                q["version"] = version
            queries.append(q)
            comp_indices.append(i)

    return queries, comp_indices


def _fetch_osv_batch(queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """POST to OSV /v1/querybatch; returns results aligned with input queries."""
    results: list[dict[str, Any]] = []
    for start in range(0, len(queries), _OSV_BATCH_SIZE):
        chunk = queries[start : start + _OSV_BATCH_SIZE]
        resp = requests.post(_OSV_BATCH_URL, json={"queries": chunk}, timeout=30)
        resp.raise_for_status()
        batch_results = resp.json().get("results", [])
        # Pad with empty dicts if server returns fewer results than queries
        while len(batch_results) < len(chunk):
            batch_results.append({})
        results.extend(batch_results)
    return results


def _extract_cve_ids(osv_result: dict[str, Any]) -> list[str]:
    """Return CVE IDs from a single OSV result object."""
    cve_ids: list[str] = []
    for vuln in osv_result.get("vulns", []):
        candidates = [vuln.get("id", "")] + vuln.get("aliases", [])
        for cid in candidates:
            if re.match(r"CVE-\d{4}-\d+", cid):
                cve_ids.append(cid)
    return list(dict.fromkeys(cve_ids))


def _extract_osv_ids(osv_result: dict[str, Any]) -> list[str]:
    """Return raw OSV IDs (GHSA-..., PYSEC-..., etc.) from a result."""
    return [v.get("id", "") for v in osv_result.get("vulns", []) if v.get("id")]


# ---------------------------------------------------------------------------
# EPSS enrichment
# ---------------------------------------------------------------------------


def _fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS scores from api.first.org; returns CVE → float mapping."""
    scores: dict[str, float] = {}
    for start in range(0, len(cve_ids), _EPSS_BATCH_SIZE):
        chunk = cve_ids[start : start + _EPSS_BATCH_SIZE]
        params: dict[str, str] = {"cve": ",".join(chunk), "envelope": "true"}
        try:
            resp = requests.get(_EPSS_URL, params=params, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            for entry in data.get("data", []):
                cve_id = entry.get("cve", "")
                try:
                    scores[cve_id] = float(entry.get("epss", 0.0))
                except (ValueError, TypeError):
                    scores[cve_id] = 0.0
        except Exception:  # noqa: BLE001
            # Graceful degradation
            pass
    return scores


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------


def _fetch_cisa_kev() -> set[str]:
    """Download CISA KEV catalog; returns set of CVE IDs. Empty on failure."""
    try:
        resp = requests.get(_CISA_KEV_URL, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        return {v["cveID"] for v in data.get("vulnerabilities", []) if "cveID" in v}
    except Exception:  # noqa: BLE001
        return set()


# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------


def _epss_to_severity(epss: float, in_kev: bool) -> str:
    if in_kev:
        return "CRITICAL"
    for threshold, label in _SEVERITY_THRESHOLDS:
        if epss >= threshold:
            return label
    return "INFO"


# ---------------------------------------------------------------------------
# Text rendering
# ---------------------------------------------------------------------------


def _render_text(result: dict[str, Any]) -> str:
    lines: list[str] = [
        "=" * 70,
        "SBOM VULNERABILITY SCAN REPORT",
        "=" * 70,
        f"Components scanned : {result['component_count']}",
        f"Vulnerable         : {result['vulnerable_count']}",
        f"KEV hits           : {len(result['kev_hits'])}",
        "",
    ]

    if result["kev_hits"]:
        lines.append("🚨 ACTIVELY EXPLOITED (CISA KEV):")
        for cve in result["kev_hits"]:
            lines.append(f"   • {cve}")
        lines.append("")

    if not result["findings"]:
        lines.append("✅ No vulnerabilities found.")
        return "\n".join(lines)

    lines.append("FINDINGS (sorted by EPSS score):")
    lines.append("-" * 70)
    for f in result["findings"]:
        kev_flag = " 🚨 KEV" if f["in_kev"] else ""
        lines.append(f"[{f['severity_label']:<8}] {f['component']}{kev_flag}")
        lines.append(f"  PURL      : {f['purl'] or '(none)'}")
        lines.append(f"  CVEs      : {', '.join(f['cve_ids']) or '(GHSA/OSV only)'}")
        lines.append(f"  EPSS max  : {f['epss_max']:.4f}")
        if f["osv_ids"]:
            lines.append(f"  OSV IDs   : {', '.join(f['osv_ids'][:5])}")
        lines.append("")

    lines += ["-" * 70, result["summary"]]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core scan logic (exposed for testing)
# ---------------------------------------------------------------------------


def _run_scan(
    content: str,
    max_findings: int = 50,
) -> dict[str, Any]:
    """Parse SBOM, query OSV, enrich with EPSS + KEV, return SBOMScanResult."""
    components = _parse_sbom(content)
    component_count = len(components)

    if not components:
        return {
            "component_count": 0,
            "vulnerable_count": 0,
            "findings": [],
            "kev_hits": [],
            "summary": "No components found in SBOM.",
        }

    # Build and execute OSV batch queries
    queries, comp_indices = _build_osv_queries(components)
    osv_results = _fetch_osv_batch(queries) if queries else []

    # Aggregate OSV results per component index
    comp_cves: dict[int, set[str]] = {}
    comp_osv_ids: dict[int, list[str]] = {}
    for qi, ci in enumerate(comp_indices):
        if qi >= len(osv_results):
            break
        r = osv_results[qi]
        cves = set(_extract_cve_ids(r))
        osv_ids = _extract_osv_ids(r)
        if cves or osv_ids:
            comp_cves.setdefault(ci, set()).update(cves)
            comp_osv_ids.setdefault(ci, [])
            for oid in osv_ids:
                if oid not in comp_osv_ids[ci]:
                    comp_osv_ids[ci].append(oid)

    # Collect all CVE IDs → EPSS batch fetch
    all_cve_ids = sorted({cve for cves in comp_cves.values() for cve in cves})
    epss_scores = _fetch_epss_scores(all_cve_ids) if all_cve_ids else {}

    # CISA KEV
    kev_set = _fetch_cisa_kev()

    # Build findings
    findings: list[dict[str, Any]] = []
    for ci, cves in comp_cves.items():
        comp = components[ci]
        cve_list = sorted(cves)
        epss_max = max((epss_scores.get(c, 0.0) for c in cve_list), default=0.0)
        in_kev = bool(cves & kev_set)
        severity = _epss_to_severity(epss_max, in_kev)
        version = comp.get("version", "")
        label = f"{comp['name']}@{version}" if version else comp["name"]
        findings.append(
            {
                "component": label,
                "purl": comp.get("purl", ""),
                "cve_ids": cve_list,
                "epss_max": epss_max,
                "in_kev": in_kev,
                "severity_label": severity,
                "osv_ids": comp_osv_ids.get(ci, []),
            }
        )

    # Sort: KEV first, then by EPSS descending
    findings.sort(key=lambda f: (f["in_kev"], f["epss_max"]), reverse=True)
    findings = findings[:max_findings]

    kev_hits = sorted({cve for f in findings if f["in_kev"] for cve in f["cve_ids"] if cve in kev_set})
    vulnerable_count = len(comp_cves)

    critical = sum(1 for f in findings if f["severity_label"] == "CRITICAL")
    high = sum(1 for f in findings if f["severity_label"] == "HIGH")
    summary_parts = [f"Scanned {component_count} component(s): {vulnerable_count} have known CVEs."]
    if kev_hits:
        summary_parts.append(f"{len(kev_hits)} CVE(s) are actively exploited (CISA KEV).")
    if critical:
        summary_parts.append(f"{critical} finding(s) rated CRITICAL (EPSS ≥ 0.50 or KEV).")
    if high:
        summary_parts.append(f"{high} finding(s) rated HIGH (EPSS ≥ 0.10).")
    if not kev_hits and not critical and not high:
        summary_parts.append("No high-priority exploitation signals detected.")

    return {
        "component_count": component_count,
        "vulnerable_count": vulnerable_count,
        "findings": findings,
        "kev_hits": kev_hits,
        "summary": " ".join(summary_parts),
    }


# ---------------------------------------------------------------------------
# Strands tool entry point
# ---------------------------------------------------------------------------


@tool
def scan_sbom(
    sbom_content: str,
    output: str = "text",
    max_findings: int = 50,
) -> str:
    """
    Scan a Software Bill of Materials (SBOM) for known vulnerabilities.

    Parses a CycloneDX (JSON or XML) or SPDX (JSON) SBOM, queries OSV.dev
    for all components, enriches results with EPSS exploitation-probability
    scores and CISA KEV active-exploitation status, and returns a prioritised
    vulnerability report.

    Args:
        sbom_content: Full text content of the SBOM file.
        output: ``"text"`` (default) for a human-readable report, ``"json"``
            for a structured SBOMScanResult dict.
        max_findings: Maximum number of findings to return (default 50).

    Returns:
        A formatted vulnerability report (text) or JSON-serialised result.
    """
    result = _run_scan(sbom_content, max_findings=max_findings)

    if output == "json":
        return json.dumps(result, indent=2)

    return _render_text(result)
