#!/usr/bin/env python3
"""
Tool for resolving affected version ranges for a CVE.

Walks NVD CPE configurations and cross-references OSV.dev ecosystem data
(PyPI, npm, Maven, Go, RustSec, etc.) to produce structured vulnerable
version ranges, a list of affected releases, and the first patched release
for each affected package.

Strategy
--------
1. Fetch NVD data to extract CPE match criteria (vendor, product, version
   ranges expressed as ``versionStartIncluding`` / ``versionEndExcluding``).
2. Fetch OSV.dev data to get ecosystem-specific package names and precise
   ``introduced`` / ``fixed`` / ``last_affected`` version-range events.
3. When ``--ecosystem`` is specified, filter results to that ecosystem only.
4. For each affected package, query the ecosystem registry (PyPI JSON API,
   npm registry, Maven Central) to resolve the concrete list of affected
   release versions and the first patched version.

Public APIs only — no keys required (NVD API key optional for higher rate
limits).
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import requests
from strands.types.tools import ToolResult, ToolUse

from manus_agent.tools.tool_output_logger import log_tool_output_size

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TOOL_SPEC = {
    "name": "get_version_range",
    "description": (
        "Resolves affected version ranges for a given CVE by walking NVD CPE "
        "configurations and cross-referencing OSV.dev ecosystem data (PyPI, npm, "
        "Maven, Go, etc.). Returns structured vulnerable version ranges per "
        "package, the list of affected release versions, and the first patched "
        "version. Optionally filters by ecosystem. Use this to answer: 'which "
        "exact versions of package X are vulnerable to this CVE, and what "
        "version should I upgrade to?'"
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "The CVE identifier (e.g. 'CVE-2021-44228').",
                },
                "ecosystem": {
                    "type": "string",
                    "description": (
                        "Filter to a specific ecosystem: 'pypi', 'npm', 'maven', "
                        "'go', or 'auto' (default: 'auto' — return all)."
                    ),
                },
            },
            "required": ["cve_id"],
        }
    },
}

# Retry configuration (mirrors other tools in the project)
_MAX_RETRIES: int = int(os.environ.get("VERSION_RANGE_MAX_RETRIES", "3"))
_RETRY_BASE_DELAY: float = float(os.environ.get("VERSION_RANGE_RETRY_BASE_DELAY", "1.0"))
_RETRYABLE_STATUSES: frozenset[int] = frozenset({429, 500, 502, 503, 504})
_HTTP_TIMEOUT = 15

# Ecosystem registry URLs
_PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"
_NPM_REGISTRY_URL = "https://registry.npmjs.org/{package}"
_MAVEN_SEARCH_URL = "https://search.maven.org/solrsearch/select"

# NVD API
_NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

# OSV API
_OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{osv_id}"

# Ecosystem name normalisation map
_ECOSYSTEM_ALIASES: dict[str, str] = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "go": "Go",
    "crates.io": "crates.io",
    "rubygems": "RubyGems",
    "nuget": "NuGet",
    "packagist": "Packagist",
    "hex": "Hex",
    "pub": "Pub",
}

# Map NVD CPE vendor/product hints to ecosystems
_CPE_ECOSYSTEM_HINTS: dict[str, str] = {
    "python": "PyPI",
    "pypi": "PyPI",
    "pip": "PyPI",
    "node": "npm",
    "nodejs": "npm",
    "npm": "npm",
    "maven": "Maven",
    "apache": "Maven",
    "golang": "Go",
    "go": "Go",
}

# CVE-ID pattern
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# HTTP helper with retry / back-off
# ---------------------------------------------------------------------------
def _get_with_retry(url: str, *, headers: dict[str, str] | None = None) -> requests.Response:
    """GET with exponential back-off on transient errors."""
    last_exc: Exception | None = None
    for attempt in range(_MAX_RETRIES):
        try:
            resp = requests.get(
                url,
                headers=headers or {},
                timeout=_HTTP_TIMEOUT,
            )
            if resp.status_code in _RETRYABLE_STATUSES and attempt < _MAX_RETRIES - 1:
                time.sleep(_RETRY_BASE_DELAY * (2**attempt))
                continue
            return resp
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            last_exc = exc
            if attempt < _MAX_RETRIES - 1:
                time.sleep(_RETRY_BASE_DELAY * (2**attempt))
                continue
            raise
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("HTTP request failed without a specific exception")


# ---------------------------------------------------------------------------
# NVD CPE extraction
# ---------------------------------------------------------------------------
def _fetch_nvd_cpe_ranges(cve_id: str) -> list[dict[str, Any]]:
    """Extract CPE match criteria from NVD for the given CVE.

    Returns a list of dicts, each with keys:
      vendor, product, version_start, version_start_type,
      version_end, version_end_type, exact_versions
    """
    headers: dict[str, str] = {}
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key

    url = _NVD_CVE_URL.format(cve_id=cve_id.upper())
    resp = _get_with_retry(url, headers=headers)
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    data = resp.json()

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return []

    cve_data = vulns[0].get("cve", {})
    configs = cve_data.get("configurations", [])

    results: list[dict[str, Any]] = []
    for config in configs:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                # CPE 2.3 format: cpe:2.3:a:vendor:product:version:...
                vendor = parts[3] if len(parts) > 3 else ""
                product = parts[4] if len(parts) > 4 else ""
                exact_ver = parts[5] if len(parts) > 5 and parts[5] not in ("*", "-") else ""

                entry: dict[str, Any] = {
                    "vendor": vendor,
                    "product": product,
                    "version_start": match.get("versionStartIncluding", ""),
                    "version_start_type": "including" if match.get("versionStartIncluding") else "",
                    "version_end": match.get("versionEndExcluding", match.get("versionEndIncluding", "")),
                    "version_end_type": (
                        "excluding"
                        if match.get("versionEndExcluding")
                        else ("including" if match.get("versionEndIncluding") else "")
                    ),
                    "exact_versions": [exact_ver] if exact_ver else [],
                }

                # If no range bounds but an exact version from versionStartIncluding == versionEndIncluding
                if not entry["version_start"] and not entry["version_end"] and not exact_ver:
                    # Wildcard match — all versions
                    pass

                results.append(entry)

    return results


# ---------------------------------------------------------------------------
# OSV affected-package extraction
# ---------------------------------------------------------------------------
def _fetch_osv_affected(cve_id: str) -> list[dict[str, Any]]:
    """Fetch OSV.dev records and extract affected package + version ranges.

    Returns a list of dicts, each with keys:
      ecosystem, package, introduced, fixed, last_affected,
      affected_versions (concrete list from OSV)
    """
    try:
        resp = _get_with_retry(_OSV_VULN_URL.format(osv_id=cve_id.upper()))
    except Exception:
        return []

    if resp.status_code == 404:
        return []

    try:
        resp.raise_for_status()
        primary = resp.json()
    except Exception:
        return []

    # Collect records: primary + GHSA aliases (for package-level data)
    records = [primary]
    aliases = primary.get("aliases", [])

    # If primary has no affected data, follow GHSA aliases
    if not primary.get("affected"):
        ghsa_aliases = [a for a in aliases if isinstance(a, str) and a.startswith("GHSA-")]
        for alias in ghsa_aliases[:6]:
            try:
                a_resp = _get_with_retry(_OSV_VULN_URL.format(osv_id=alias))
                if a_resp.status_code == 200:
                    records.append(a_resp.json())
            except Exception:
                continue

    packages: list[dict[str, Any]] = []
    seen: set[str] = set()

    for record in records:
        for entry in record.get("affected", []) or []:
            if not isinstance(entry, dict):
                continue
            pkg = entry.get("package") or {}
            ecosystem = pkg.get("ecosystem", "") if isinstance(pkg, dict) else ""
            name = pkg.get("name", "") if isinstance(pkg, dict) else ""
            if not ecosystem and not name:
                continue

            dedup_key = f"{ecosystem}:{name}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            introduced: list[str] = []
            fixed: list[str] = []
            last_affected: list[str] = []

            for rng in entry.get("ranges", []) or []:
                if not isinstance(rng, dict):
                    continue
                for ev in rng.get("events", []) or []:
                    if not isinstance(ev, dict):
                        continue
                    if "introduced" in ev:
                        introduced.append(str(ev["introduced"]))
                    if "fixed" in ev:
                        fixed.append(str(ev["fixed"]))
                    if "last_affected" in ev:
                        last_affected.append(str(ev["last_affected"]))

            versions = [str(v) for v in (entry.get("versions", []) or []) if v is not None]

            packages.append(
                {
                    "ecosystem": ecosystem,
                    "package": name,
                    "introduced": introduced,
                    "fixed": fixed,
                    "last_affected": last_affected,
                    "affected_versions": versions,
                }
            )

    return packages


# ---------------------------------------------------------------------------
# Ecosystem registry queries — resolve concrete release lists
# ---------------------------------------------------------------------------
def _fetch_pypi_versions(package: str) -> list[str]:
    """Fetch all release versions from PyPI for a package."""
    try:
        resp = _get_with_retry(_PYPI_JSON_URL.format(package=package))
        if resp.status_code != 200:
            return []
        data = resp.json()
        return sorted(data.get("releases", {}).keys())
    except Exception:
        return []


def _fetch_npm_versions(package: str) -> list[str]:
    """Fetch all release versions from npm for a package."""
    try:
        resp = _get_with_retry(_NPM_REGISTRY_URL.format(package=package))
        if resp.status_code != 200:
            return []
        data = resp.json()
        return sorted(data.get("versions", {}).keys())
    except Exception:
        return []


def _fetch_maven_versions(package: str) -> list[str]:
    """Fetch all release versions from Maven Central for a package.

    Expects package in ``group:artifact`` format.
    """
    try:
        parts = package.split(":")
        if len(parts) != 2:
            # Try group.artifact format (dotted)
            parts = package.rsplit(".", 1)
        if len(parts) != 2:
            return []
        group_id, artifact_id = parts
        url = f"{_MAVEN_SEARCH_URL}?q=g:{group_id}+AND+a:{artifact_id}&core=gav&rows=200&wt=json"
        resp = _get_with_retry(url)
        if resp.status_code != 200:
            return []
        data = resp.json()
        docs = data.get("response", {}).get("docs", [])
        return sorted({d.get("v", "") for d in docs if d.get("v")})
    except Exception:
        return []


def _fetch_registry_versions(ecosystem: str, package: str) -> list[str]:
    """Dispatch to the appropriate registry based on ecosystem."""
    eco_lower = ecosystem.lower()
    if eco_lower == "pypi":
        return _fetch_pypi_versions(package)
    elif eco_lower == "npm":
        return _fetch_npm_versions(package)
    elif eco_lower == "maven":
        return _fetch_maven_versions(package)
    return []


# ---------------------------------------------------------------------------
# Version comparison helpers
# ---------------------------------------------------------------------------
def _parse_version_tuple(v: str) -> tuple[int | str, ...]:
    """Parse a version string into a comparable tuple.

    Handles semver-like versions (1.2.3), pre-release suffixes, and
    non-numeric components gracefully.
    """
    parts: list[int | str] = []
    for segment in re.split(r"[.\-_+]", v):
        try:
            parts.append(int(segment))
        except ValueError:
            parts.append(segment)
    return tuple(parts)


def _version_gte(v: str, threshold: str) -> bool:
    """Return True if version v >= threshold using tuple comparison."""
    try:
        return _parse_version_tuple(v) >= _parse_version_tuple(threshold)
    except TypeError:
        return v >= threshold


def _version_lt(v: str, threshold: str) -> bool:
    """Return True if version v < threshold using tuple comparison."""
    try:
        return _parse_version_tuple(v) < _parse_version_tuple(threshold)
    except TypeError:
        return v < threshold


def _version_lte(v: str, threshold: str) -> bool:
    """Return True if version v <= threshold using tuple comparison."""
    try:
        return _parse_version_tuple(v) <= _parse_version_tuple(threshold)
    except TypeError:
        return v <= threshold


def _filter_versions_by_range(
    all_versions: list[str],
    introduced: list[str],
    fixed: list[str],
    last_affected: list[str],
) -> list[str]:
    """Filter a list of versions to those within the vulnerable range.

    Uses OSV range semantics:
    - introduced: version where the vulnerability was introduced
    - fixed: first version where the vulnerability was fixed
    - last_affected: last version known to be affected
    """
    if not all_versions:
        return []

    # If we have both introduced and fixed, filter by range
    affected: list[str] = []
    for v in all_versions:
        in_range = True

        # Check introduced bounds (any introduced version qualifies)
        if introduced:
            # Version must be >= at least one introduced version
            # "0" means "all versions from the beginning"
            if not any(intro == "0" or _version_gte(v, intro) for intro in introduced):
                in_range = False

        # Check fixed bounds
        if fixed and in_range:
            # Version must be < all fixed versions to be vulnerable
            if not any(_version_lt(v, f) for f in fixed):
                in_range = False

        # Check last_affected bounds
        if last_affected and in_range and not fixed:
            if not any(_version_lte(v, la) for la in last_affected):
                in_range = False

        if in_range:
            affected.append(v)

    return affected


# ---------------------------------------------------------------------------
# Ecosystem filter normalisation
# ---------------------------------------------------------------------------
def _normalise_ecosystem(eco: str) -> str:
    """Normalise an ecosystem name to its canonical OSV form."""
    return _ECOSYSTEM_ALIASES.get(eco.lower(), eco)


def _ecosystem_matches(pkg_ecosystem: str, filter_ecosystem: str) -> bool:
    """Check if a package's ecosystem matches the requested filter."""
    if not filter_ecosystem or filter_ecosystem.lower() == "auto":
        return True
    return pkg_ecosystem.lower() == filter_ecosystem.lower() or _normalise_ecosystem(
        filter_ecosystem
    ) == _normalise_ecosystem(pkg_ecosystem)


# ---------------------------------------------------------------------------
# Main analysis function (used by both tool and CLI)
# ---------------------------------------------------------------------------
def fetch_version_range(cve_id: str, ecosystem: str = "auto") -> dict[str, Any]:
    """Resolve affected version ranges for a CVE.

    Returns a dict with keys:
      found (bool), cve_id, packages (list of per-package results),
      first_patched_version (str or None — earliest fix across all packages),
      summary (str), error (str, if applicable).
    """
    cve_id = (cve_id or "").strip().upper()
    if not cve_id or not _CVE_RE.match(cve_id):
        return {
            "found": False,
            "cve_id": cve_id,
            "packages": [],
            "first_patched_version": None,
            "summary": "Invalid CVE ID format. Must match CVE-YYYY-NNNN+.",
            "error": "Invalid CVE ID format.",
        }

    # Step 1: Fetch NVD CPE ranges
    try:
        nvd_cpes = _fetch_nvd_cpe_ranges(cve_id)
    except Exception as exc:
        nvd_cpes = []
        nvd_error = str(exc)
    else:
        nvd_error = ""

    # Step 2: Fetch OSV affected packages
    osv_packages = _fetch_osv_affected(cve_id)

    # Apply ecosystem filter
    if ecosystem and ecosystem.lower() != "auto":
        osv_packages = [p for p in osv_packages if _ecosystem_matches(p["ecosystem"], ecosystem)]
        nvd_cpes = [
            c
            for c in nvd_cpes
            if _ecosystem_matches(c.get("product", ""), ecosystem) or _ecosystem_matches(c.get("vendor", ""), ecosystem)
        ]

    # Step 3: Build combined results per package
    results: list[dict[str, Any]] = []
    seen_packages: set[str] = set()

    # Process OSV packages (primary — have ecosystem + package info)
    for pkg in osv_packages:
        eco = pkg["ecosystem"]
        name = pkg["package"]
        key = f"{eco}:{name}"
        if key in seen_packages:
            continue
        seen_packages.add(key)

        introduced = pkg.get("introduced", [])
        fixed = pkg.get("fixed", [])
        last_affected = pkg.get("last_affected", [])
        osv_affected_versions = pkg.get("affected_versions", [])

        # Try to fetch registry versions for concrete filtering
        registry_versions = _fetch_registry_versions(eco, name)

        # If OSV provides an explicit versions list, use it
        if osv_affected_versions:
            affected_versions = osv_affected_versions
        elif registry_versions:
            # Filter registry versions using OSV range events
            affected_versions = _filter_versions_by_range(registry_versions, introduced, fixed, last_affected)
        else:
            affected_versions = []

        # Build version range string
        range_str = _build_range_string(introduced, fixed, last_affected)

        # Determine first patched version
        first_patched = fixed[0] if fixed else None

        results.append(
            {
                "ecosystem": eco,
                "package": name,
                "vulnerable_range": range_str,
                "introduced": introduced,
                "fixed": fixed,
                "last_affected": last_affected,
                "first_patched_version": first_patched,
                "affected_version_count": len(affected_versions),
                "affected_versions": affected_versions[:50],  # cap output size
                "registry_version_count": len(registry_versions),
                "source": "osv",
            }
        )

    # Process NVD CPE ranges that weren't covered by OSV
    for cpe in nvd_cpes:
        vendor = cpe["vendor"]
        product = cpe["product"]
        key = f"nvd:{vendor}:{product}"
        if key in seen_packages:
            continue
        # Check if OSV already covers this product
        if any(product.lower() in (r.get("package", "").lower()) for r in results):
            continue
        seen_packages.add(key)

        range_parts: list[str] = []
        if cpe["version_start"]:
            op = ">=" if cpe["version_start_type"] == "including" else ">"
            range_parts.append(f"{op}{cpe['version_start']}")
        if cpe["version_end"]:
            op = "<" if cpe["version_end_type"] == "excluding" else "<="
            range_parts.append(f"{op}{cpe['version_end']}")
        if cpe["exact_versions"]:
            range_parts.append(f"=={cpe['exact_versions'][0]}")

        range_str = " ".join(range_parts) if range_parts else "all versions"

        fixed_ver = cpe["version_end"] if cpe["version_end_type"] == "excluding" else None

        results.append(
            {
                "ecosystem": "NVD/CPE",
                "package": f"{vendor}/{product}",
                "vulnerable_range": range_str,
                "introduced": [],
                "fixed": [fixed_ver] if fixed_ver else [],
                "last_affected": ([cpe["version_end"]] if cpe["version_end_type"] == "including" else []),
                "first_patched_version": fixed_ver,
                "affected_version_count": len(cpe.get("exact_versions", [])),
                "affected_versions": cpe.get("exact_versions", []),
                "registry_version_count": 0,
                "source": "nvd",
            }
        )

    if not results and not nvd_error:
        return {
            "found": False,
            "cve_id": cve_id,
            "packages": [],
            "first_patched_version": None,
            "summary": f"No version range data found for {cve_id}.",
            "error": None,
        }

    if not results and nvd_error:
        return {
            "found": False,
            "cve_id": cve_id,
            "packages": [],
            "first_patched_version": None,
            "summary": f"Failed to fetch version data for {cve_id}: {nvd_error}",
            "error": nvd_error,
        }

    # Determine overall first patched version (earliest fix across all)
    all_fixed: list[str] = []
    for r in results:
        all_fixed.extend(r.get("fixed", []))
    global_first_patched = all_fixed[0] if all_fixed else None

    # Build summary
    eco_set = sorted({r["ecosystem"] for r in results if r.get("ecosystem")})
    pkg_count = len(results)
    eco_str = ", ".join(eco_set) if eco_set else "unknown"
    patch_str = f" First patched: {global_first_patched}." if global_first_patched else " No patch identified."
    summary = f"{cve_id} affects {pkg_count} package(s) across {len(eco_set)} ecosystem(s): {eco_str}.{patch_str}"

    return {
        "found": True,
        "cve_id": cve_id,
        "packages": results,
        "first_patched_version": global_first_patched,
        "affected_package_count": pkg_count,
        "ecosystems": eco_set,
        "summary": summary,
    }


def _build_range_string(introduced: list[str], fixed: list[str], last_affected: list[str]) -> str:
    """Build a human-readable version range string from OSV events."""
    parts: list[str] = []

    for intro in introduced:
        if intro == "0":
            parts.append(">=0 (all versions)")
        else:
            parts.append(f">={intro}")

    for fix in fixed:
        parts.append(f"<{fix}")

    for la in last_affected:
        parts.append(f"<={la} (last affected)")

    return " ".join(parts) if parts else "all versions (unspecified range)"


# ---------------------------------------------------------------------------
# Strands tool entry point
# ---------------------------------------------------------------------------
def get_version_range(tool: ToolUse, **kwargs: Any) -> ToolResult:
    """Strands SDK tool entry point."""
    tool_use_id = tool["toolUseId"]
    tool_input = tool.get("input", {}) or {}
    cve_id = tool_input.get("cve_id")
    ecosystem = tool_input.get("ecosystem", "auto")

    if not isinstance(cve_id, str) or not cve_id.strip():
        result: ToolResult = {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": "Invalid CVE ID. Must be a non-empty string."}],
        }
        log_tool_output_size("get_version_range", result)
        return result

    payload = fetch_version_range(cve_id, ecosystem=ecosystem or "auto")
    status = "success" if payload.get("found") else "error"

    result = {
        "toolUseId": tool_use_id,
        "status": status,
        "content": [{"text": json.dumps(payload, indent=2)}],
    }
    log_tool_output_size("get_version_range", result)
    return result
