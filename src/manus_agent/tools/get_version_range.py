"""
Tool: get_version_range

Given a CVE ID, returns structured vulnerable version ranges, the first patched
version, a list of affected releases, and the ecosystem.  Cross-references:

  1. OSV.dev API       — primary source: SEMVER + ECOSYSTEM ranges with fixed events
  2. NVD CPE configs   — fallback version strings from CPE applicability statements
  3. GitHub Advisory   — patched_versions field as additional first_patched_version hint

Output keys
-----------
``cve_id``               str   — normalised CVE ID
``ecosystem``            str   — primary ecosystem (PyPI / npm / Maven / Go / …) or "unknown"
``package_name``         str   — primary package name or empty string
``vulnerable_ranges``    list  — list of range dicts::

    {
        "introduced": "1.0.0",   # inclusive lower bound (or None)
        "fixed":      "2.3.1",   # exclusive upper bound / first patched
        "range_type": "SEMVER",  # SEMVER | ECOSYSTEM | GIT | VERSION
        "source":     "osv",     # osv | nvd | ghsa
    }

``first_patched_version`` str | None — earliest ``fixed`` version found across all ranges
``affected_versions``     list[str]  — spot-checked list of known affected releases (≤20)
``all_sources``           list[str]  — source IDs that returned data
``errors``                list[str]  — non-fatal warnings / degradation messages

CLI: ``manus-agent version-range CVE-2021-44228``
     ``manus-agent version-range CVE-2021-44228 --ecosystem pypi``
     ``manus-agent version-range CVE-2021-44228 --output json | jq .first_patched_version``
"""

from __future__ import annotations

import logging
import re
from typing import Any

import requests
from strands import tool

__all__ = ["get_version_range"]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
_TIMEOUT = 20

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
_GHSA_URL = "https://api.github.com/advisories"

# Ecosystem normalisation: OSV name → canonical label
_ECOSYSTEM_NORM: dict[str, str] = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "go": "Go",
    "rubygems": "RubyGems",
    "crates.io": "crates.io",
    "nuget": "NuGet",
    "packagist": "Packagist",
    "hex": "Hex",
    "pub": "Pub",
    "bioconductor": "Bioconductor",
    "hackage": "Hackage",
    "linux": "Linux",
    "android": "Android",
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "alpine": "Alpine",
    "rocky linux": "Rocky Linux",
    "alma linux": "AlmaLinux",
    "red hat": "Red Hat",
    "github actions": "GitHub Actions",
}

_ECOSYSTEM_FILTER: dict[str, str] = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "go": "Go",
}

# Maximum affected version entries to return
_MAX_AFFECTED_VERSIONS = 20


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _get(url: str, params: dict | None = None, headers: dict | None = None) -> Any:
    resp = requests.get(url, params=params, headers=headers, timeout=_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def _post(url: str, payload: dict) -> Any:
    resp = requests.post(url, json=payload, timeout=_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Source 1: OSV.dev
# ---------------------------------------------------------------------------


def _fetch_osv(cve_id: str, ecosystem_filter: str | None = None) -> dict[str, Any]:
    """
    Query OSV.dev and return structured range data.

    Returns dict with keys:
      ranges, first_patched_version, affected_versions, package_name, ecosystem

    Raises on initial query failure so the caller can record the error.
    """
    result: dict[str, Any] = {
        "ranges": [],
        "first_patched_version": None,
        "affected_versions": [],
        "package_name": "",
        "ecosystem": "unknown",
    }

    # Raises on failure — caller catches and records the error.
    data = _post(_OSV_QUERY_URL, {"id": cve_id})

    # Walk all related OSV records (a CVE may map to multiple OSV entries across ecosystems)
    best_pkg_name = ""
    best_ecosystem = "unknown"
    ranges: list[dict] = []
    affected_versions: list[str] = []
    fixed_versions: list[str] = []

    for vuln in data.get("vulns", []):
        vuln_id = vuln.get("id", "")
        try:
            full = _post(_OSV_QUERY_URL, {"id": vuln_id})
            # OSV query by ID returns the same structure; fetch via vuln URL instead
            full = _get(_OSV_VULN_URL.format(vuln_id))
        except Exception:
            continue

        for affected in full.get("affected", []):
            pkg = affected.get("package", {})
            pkg_name = pkg.get("name", "")
            ecosystem_raw = pkg.get("ecosystem", "")
            ecosystem_norm = _ECOSYSTEM_NORM.get(ecosystem_raw.lower(), ecosystem_raw)

            # Apply ecosystem filter when requested
            if ecosystem_filter:
                canonical = _ECOSYSTEM_FILTER.get(ecosystem_filter.lower())
                if canonical and ecosystem_norm.lower() != canonical.lower():
                    continue

            # Prefer the first non-empty package name
            if not best_pkg_name and pkg_name:
                best_pkg_name = pkg_name
                best_ecosystem = ecosystem_norm

            # Parse ranges
            for rng in affected.get("ranges", []):
                rng_type = rng.get("type", "ECOSYSTEM")
                events = rng.get("events", [])
                introduced = None
                fixed = None
                for ev in events:
                    if "introduced" in ev:
                        val = ev["introduced"]
                        if val != "0":
                            introduced = val
                    if "fixed" in ev:
                        fixed = ev["fixed"]
                        fixed_versions.append(fixed)

                ranges.append(
                    {
                        "introduced": introduced,
                        "fixed": fixed,
                        "range_type": rng_type,
                        "source": "osv",
                        "package": pkg_name,
                        "ecosystem": ecosystem_norm,
                    }
                )

            # Collect spot-check versions (cap at _MAX_AFFECTED_VERSIONS total)
            for v in affected.get("versions", []):
                if v not in affected_versions and len(affected_versions) < _MAX_AFFECTED_VERSIONS:
                    affected_versions.append(v)

    # Determine the lowest fixed version (simple lexicographic fallback; semver would be better
    # but avoids the packaging dependency which may not be installed)
    first_patched = _earliest_version(fixed_versions) if fixed_versions else None

    result["ranges"] = ranges
    result["first_patched_version"] = first_patched
    result["affected_versions"] = affected_versions
    result["package_name"] = best_pkg_name
    result["ecosystem"] = best_ecosystem
    return result


# ---------------------------------------------------------------------------
# Source 2: NVD CPE configurations (fallback)
# ---------------------------------------------------------------------------


def _fetch_nvd(cve_id: str) -> dict[str, Any]:
    """
    Fetch NVD CPE configurations for the CVE and extract version information.

    NVD CPE configs don't always give semver ranges, but they do supply:
      - versionStartIncluding / versionEndExcluding (proper range)
      - versionStartExcluding / versionEndIncluding (alternative)
    """
    result: dict[str, Any] = {
        "ranges": [],
        "first_patched_version": None,
        "affected_versions": [],
        "package_name": "",
        "ecosystem": "unknown",
    }

    import os

    api_key = os.environ.get("NVD_API_KEY", "")
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key
    # Raises on failure — caller catches and records the error.
    data = _get(_NVD_URL, params={"cveId": cve_id.upper()}, headers=headers or None)

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return result

    cve_data = vulns[0].get("cve", {})
    configurations = cve_data.get("configurations", [])
    fixed_versions: list[str] = []
    ranges: list[dict] = []

    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", True):
                    continue

                cpe_uri = cpe_match.get("criteria", "")
                pkg_name = _extract_pkg_from_cpe(cpe_uri)

                ver_start_incl = cpe_match.get("versionStartIncluding")
                ver_end_excl = cpe_match.get("versionEndExcluding")
                ver_start_excl = cpe_match.get("versionStartExcluding")
                ver_end_incl = cpe_match.get("versionEndIncluding")

                introduced = ver_start_incl or (ver_start_excl if ver_start_excl else None)
                fixed = ver_end_excl  # exclusive upper bound = first patched
                if ver_end_incl and not fixed:
                    fixed = None  # inclusive upper bound — can't infer "fixed"

                if ver_end_excl:
                    fixed_versions.append(ver_end_excl)

                ranges.append(
                    {
                        "introduced": introduced,
                        "fixed": fixed,
                        "range_type": "VERSION",
                        "source": "nvd",
                        "package": pkg_name,
                        "ecosystem": "unknown",
                    }
                )

    first_patched = _earliest_version(fixed_versions) if fixed_versions else None
    result["ranges"] = ranges
    result["first_patched_version"] = first_patched
    return result


def _extract_pkg_from_cpe(cpe: str) -> str:
    """Extract product name from a CPE 2.3 URI string.

    Example: ``cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*`` → ``log4j``
    """
    parts = cpe.split(":")
    if len(parts) >= 5:
        return parts[4]  # product is field 4 (0-indexed)
    return ""


# ---------------------------------------------------------------------------
# Source 3: GitHub Advisory
# ---------------------------------------------------------------------------


def _fetch_ghsa(cve_id: str) -> dict[str, Any]:
    """Fetch the first matching GHSA advisory and extract patched_versions."""
    result: dict[str, Any] = {
        "ranges": [],
        "first_patched_version": None,
        "affected_versions": [],
        "package_name": "",
        "ecosystem": "unknown",
    }

    import os

    from manus_agent.config import Config

    try:
        config = Config.from_file()
        github_token = os.environ.get("GITHUB_TOKEN") or (config.github.api_token if config.github else None)
    except Exception:
        github_token = os.environ.get("GITHUB_TOKEN")

    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    # Raises on failure — caller catches and records the error.
    advisories = _get(_GHSA_URL, params={"cve_id": cve_id, "per_page": 5}, headers=headers)

    if not advisories:
        return result

    fixed_versions: list[str] = []
    ranges: list[dict] = []

    for advisory in advisories:
        for vuln in advisory.get("vulnerabilities", []):
            pkg_info = vuln.get("package", {})
            pkg_name = pkg_info.get("name", "")
            ecosystem_raw = pkg_info.get("ecosystem", "")
            ecosystem_norm = _ECOSYSTEM_NORM.get(ecosystem_raw.lower(), ecosystem_raw)

            if not result["package_name"] and pkg_name:
                result["package_name"] = pkg_name
                result["ecosystem"] = ecosystem_norm

            vulnerable_version_range = vuln.get("vulnerable_version_range", "")
            patched_versions = vuln.get("patched_versions", "")

            # Extract introduced / fixed from GHSA range strings like ">=1.0, <2.3.1"
            introduced = None
            fixed = None
            if vulnerable_version_range:
                m_intro = re.search(r">=\s*([^\s,]+)", vulnerable_version_range)
                m_fixed = re.search(r"<\s*([^\s,]+)", vulnerable_version_range)
                if m_intro:
                    introduced = m_intro.group(1)
                if m_fixed:
                    fixed = m_fixed.group(1)
                    fixed_versions.append(fixed)

            # Use patched_versions as first_patched hint
            if patched_versions:
                # Often ">=2.3.1" format
                m_patched = re.search(r">=\s*([^\s,]+)", patched_versions)
                if m_patched:
                    pv = m_patched.group(1)
                    fixed_versions.append(pv)
                    if not fixed:
                        fixed = pv

            ranges.append(
                {
                    "introduced": introduced,
                    "fixed": fixed,
                    "range_type": "SEMVER",
                    "source": "ghsa",
                    "package": pkg_name,
                    "ecosystem": ecosystem_norm,
                }
            )

    first_patched = _earliest_version(fixed_versions) if fixed_versions else None
    result["ranges"] = ranges
    result["first_patched_version"] = first_patched
    return result


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------


def _parse_version_tuple(v: str) -> tuple[int, ...]:
    """Parse a version string into a tuple of ints for comparison.

    Non-numeric components are treated as 0 for ordering purposes.
    Handles common semver pre-release suffixes by stripping them.
    """
    # Strip pre-release suffix (e.g. 2.3.1-rc1 → 2.3.1)
    v_clean = re.split(r"[-+]", v)[0]
    parts = v_clean.split(".")
    result_parts: list[int] = []
    for p in parts:
        try:
            result_parts.append(int(p))
        except ValueError:
            result_parts.append(0)
    return tuple(result_parts)


def _earliest_version(versions: list[str]) -> str | None:
    """Return the lexicographically/numerically earliest version from a list."""
    if not versions:
        return None
    # Deduplicate
    unique = list(dict.fromkeys(v for v in versions if v))
    if not unique:
        return None
    try:
        return min(unique, key=_parse_version_tuple)
    except Exception:
        return unique[0]


# ---------------------------------------------------------------------------
# Result merging
# ---------------------------------------------------------------------------


def _merge_results(
    osv: dict[str, Any],
    nvd: dict[str, Any],
    ghsa: dict[str, Any],
) -> dict[str, Any]:
    """Merge the three source results into a single canonical output dict."""
    all_ranges: list[dict] = []
    all_ranges.extend(osv["ranges"])
    all_ranges.extend(nvd["ranges"])
    all_ranges.extend(ghsa["ranges"])

    # Deduplicate ranges by (introduced, fixed, range_type, source)
    seen: set[tuple] = set()
    deduped: list[dict] = []
    for r in all_ranges:
        key = (r.get("introduced"), r.get("fixed"), r.get("range_type"), r.get("source"))
        if key not in seen:
            seen.add(key)
            deduped.append(r)

    # Package name: prefer OSV > GHSA > NVD CPE
    package_name = osv["package_name"] or ghsa["package_name"] or nvd["package_name"]

    # Ecosystem: prefer OSV > GHSA
    ecosystem = osv["ecosystem"]
    if ecosystem == "unknown":
        ecosystem = ghsa["ecosystem"]

    # First patched version: pick earliest across all sources
    candidates = [
        v for v in [osv["first_patched_version"], nvd["first_patched_version"], ghsa["first_patched_version"]] if v
    ]
    first_patched = _earliest_version(candidates) if candidates else None

    # Affected versions: combine and deduplicate
    seen_versions: set[str] = set()
    affected: list[str] = []
    for v in osv["affected_versions"]:
        if v not in seen_versions and len(affected) < _MAX_AFFECTED_VERSIONS:
            seen_versions.add(v)
            affected.append(v)

    # Track which sources returned data
    all_sources: list[str] = []
    if osv["ranges"]:
        all_sources.append("osv")
    if nvd["ranges"]:
        all_sources.append("nvd")
    if ghsa["ranges"]:
        all_sources.append("ghsa")

    return {
        "ranges": deduped,
        "first_patched_version": first_patched,
        "affected_versions": affected,
        "package_name": package_name,
        "ecosystem": ecosystem,
        "all_sources": all_sources,
    }


# ---------------------------------------------------------------------------
# Public Strands tool
# ---------------------------------------------------------------------------


@tool
def get_version_range(
    cve_id: str,
    ecosystem: str = "auto",
) -> dict[str, Any]:
    """
    Return structured vulnerable version ranges, the first patched version,
    and a list of affected releases for a CVE.

    Cross-references OSV.dev (primary), NVD CPE configurations (fallback),
    and the GitHub Advisory Database.  All sources degrade gracefully on
    network failure.

    Args:
        cve_id:    CVE identifier, e.g. ``"CVE-2021-44228"``.
        ecosystem: One of ``"auto"``, ``"pypi"``, ``"npm"``, ``"maven"``, or ``"go"``.
                   ``"auto"`` returns the first matching ecosystem found.

    Returns:
        A dictionary with keys:

        * ``cve_id``               — normalised CVE ID
        * ``ecosystem``            — primary ecosystem or ``"unknown"``
        * ``package_name``         — primary package name or empty string
        * ``vulnerable_ranges``    — list of range dicts, each with
          ``introduced``, ``fixed``, ``range_type``, ``source``
        * ``first_patched_version`` — earliest fixed version across all sources
        * ``affected_versions``    — up to 20 known affected release strings
        * ``all_sources``          — source IDs that returned data
        * ``errors``               — non-fatal warnings
    """
    if not cve_id or not isinstance(cve_id, str):
        return {"error": "cve_id must be a non-empty string"}

    cve_upper = cve_id.strip().upper()
    if not _CVE_RE.match(cve_upper):
        return {"error": f"Invalid CVE ID format: {cve_id!r}. Expected CVE-YYYY-NNNNN."}

    ecosystem_filter = None if (not ecosystem or ecosystem.lower() == "auto") else ecosystem.lower()

    errors: list[str] = []

    # --- Fetch from all three sources ---
    osv_data: dict[str, Any] = {
        "ranges": [],
        "first_patched_version": None,
        "affected_versions": [],
        "package_name": "",
        "ecosystem": "unknown",
    }
    nvd_data: dict[str, Any] = {
        "ranges": [],
        "first_patched_version": None,
        "affected_versions": [],
        "package_name": "",
        "ecosystem": "unknown",
    }
    ghsa_data: dict[str, Any] = {
        "ranges": [],
        "first_patched_version": None,
        "affected_versions": [],
        "package_name": "",
        "ecosystem": "unknown",
    }

    try:
        osv_data = _fetch_osv(cve_upper, ecosystem_filter)
    except Exception as exc:
        errors.append(f"OSV.dev error: {exc}")

    try:
        nvd_data = _fetch_nvd(cve_upper)
    except Exception as exc:
        errors.append(f"NVD error: {exc}")

    try:
        ghsa_data = _fetch_ghsa(cve_upper)
    except Exception as exc:
        errors.append(f"GHSA error: {exc}")

    merged = _merge_results(osv_data, nvd_data, ghsa_data)

    # Flatten ranges: drop internal package/ecosystem keys before returning
    public_ranges = [
        {
            "introduced": r.get("introduced"),
            "fixed": r.get("fixed"),
            "range_type": r.get("range_type"),
            "source": r.get("source"),
        }
        for r in merged["ranges"]
    ]

    return {
        "cve_id": cve_upper,
        "ecosystem": merged["ecosystem"],
        "package_name": merged["package_name"],
        "vulnerable_ranges": public_ranges,
        "first_patched_version": merged["first_patched_version"],
        "affected_versions": merged["affected_versions"],
        "all_sources": merged["all_sources"],
        "errors": errors,
    }
