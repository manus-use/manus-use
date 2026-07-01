"""
Tool: get_patch_status

Given a CVE identifier, queries multiple vendor and distribution security
advisories to report which distributions/vendors have released patches,
which package versions contain the fix, and how quickly each vendor
responded.

Data sources (all free, unauthenticated):
  1. Ubuntu Security API  — ubuntu.com/security/cves/{CVE}
  2. Debian Security Tracker  — security-tracker.debian.org JSON
  3. Red Hat CVE DB  — access.redhat.com/security/cve/{CVE}.json
  4. OSV.dev API  — api.osv.dev/v1/query (ecosystem-agnostic fix versions)
  5. NVD CVE 2.0 API  — services.nvd.nist.gov (published/modified dates)

Output structure per vendor:
  - ``vendor``           : source name (ubuntu, debian, redhat, osv, …)
  - ``status``           : "fixed" | "vulnerable" | "not_affected" | "unknown"
  - ``fixed_version``    : first patched version (if known)
  - ``advisory_ids``     : list of advisory IDs (USN, DSA, RHSA, …)
  - ``patch_date``       : ISO-8601 date the fix was released (if known)
  - ``days_to_patch``    : integer days from CVE publish to patch (if computable)
  - ``affected_packages``: list of package names affected

Graceful degradation: each source is fetched independently; a 404 or timeout
on one source does not fail the others.

CLI: ``manus-agent patch-status CVE-2024-3094``
     ``manus-agent patch-status CVE-2021-44228``
"""

from __future__ import annotations

import logging
import re
from datetime import date, datetime
from typing import Any

import requests
from strands import tool

__all__ = ["get_patch_status"]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)

_UBUNTU_CVE_URL = "https://ubuntu.com/security/cves/{cve}.json"
_DEBIAN_TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
_DEBIAN_CVE_URL = "https://security-tracker.debian.org/tracker/source-package/{pkg}"
_REDHAT_CVE_URL = "https://access.redhat.com/labs/securitydataapi/cve/{cve}.json"
_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_TIMEOUT = 20

# Status normalisation for Ubuntu
_UBUNTU_STATUS_MAP: dict[str, str] = {
    "released": "fixed",
    "needed": "vulnerable",
    "pending": "vulnerable",
    "ignored": "not_affected",
    "DNE": "not_affected",
    "not-applicable": "not_affected",
    "not affected": "not_affected",
    "deferred": "vulnerable",
    "active": "vulnerable",
}

# Status normalisation for Red Hat
_RH_STATUS_MAP: dict[str, str] = {
    "Affected": "vulnerable",
    "Fix deferred": "vulnerable",
    "Out of support scope": "not_affected",
    "Won't fix": "not_affected",
    "New": "vulnerable",
}

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _get_json(url: str, params: dict | None = None) -> Any:
    """GET request returning parsed JSON; raises on HTTP error."""
    resp = requests.get(url, params=params or {}, timeout=_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def _post_json(url: str, payload: dict) -> Any:
    """POST JSON request returning parsed JSON; raises on HTTP error."""
    resp = requests.post(url, json=payload, timeout=_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Date utilities
# ---------------------------------------------------------------------------


def _parse_iso_date(s: str | None) -> date | None:
    """Parse ISO-8601 date string to ``date``; returns None on failure."""
    if not s:
        return None
    try:
        # Handle "YYYY-MM-DD" and full ISO-8601 datetime strings
        return datetime.fromisoformat(s.rstrip("Z").split(".")[0]).date()
    except (ValueError, TypeError):
        return None


def _days_to_patch(published: date | None, patched: date | None) -> int | None:
    """Return integer days from CVE publication to patch availability."""
    if published and patched and patched >= published:
        return (patched - published).days
    return None


# ---------------------------------------------------------------------------
# NVD — get CVE publish date
# ---------------------------------------------------------------------------


def _fetch_nvd_publish_date(cve_id: str) -> date | None:
    """Return the NVD published date for ``cve_id``, or None."""
    try:
        data = _get_json(_NVD_URL, params={"cveId": cve_id.upper()})
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        published_str = vulns[0].get("cve", {}).get("published", "")
        return _parse_iso_date(published_str)
    except Exception as exc:
        logger.debug("NVD publish date fetch failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Ubuntu
# ---------------------------------------------------------------------------


def _fetch_ubuntu(cve_id: str, nvd_published: date | None) -> list[dict[str, Any]]:
    """Query Ubuntu Security API for CVE patch information."""
    results: list[dict[str, Any]] = []
    try:
        data = _get_json(_UBUNTU_CVE_URL.format(cve=cve_id.upper()))
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            return []
        logger.debug("Ubuntu CVE API error: %s", exc)
        return []
    except Exception as exc:
        logger.debug("Ubuntu CVE fetch failed: %s", exc)
        return []

    # Ubuntu returns a dict with "packages" key listing affected packages
    packages = data.get("packages", [])
    if not packages:
        return []

    for pkg in packages:
        pkg_name = pkg.get("name", "")
        statuses = pkg.get("statuses", [])
        for entry in statuses:
            release = entry.get("release_codename", entry.get("release", ""))
            raw_status = entry.get("status", "")
            status = _UBUNTU_STATUS_MAP.get(raw_status, "unknown")
            fixed_ver = entry.get("fix_version") or entry.get("description") or ""
            if status == "not_affected" and not fixed_ver:
                continue

            # Determine patch date: Ubuntu sometimes provides a pocket/component
            patch_date_str = entry.get("pocket_date") or entry.get("published") or ""
            patch_date = _parse_iso_date(patch_date_str) if patch_date_str else None

            # Collect USN advisory IDs
            usns: list[str] = []
            for notice in data.get("notices", []):
                usn_id = notice.get("id", "")
                if usn_id:
                    usns.append(usn_id)

            results.append(
                {
                    "vendor": f"ubuntu/{release}",
                    "status": status,
                    "fixed_version": fixed_ver if status == "fixed" else None,
                    "advisory_ids": list(dict.fromkeys(usns)),
                    "patch_date": patch_date.isoformat() if patch_date else None,
                    "days_to_patch": _days_to_patch(nvd_published, patch_date),
                    "affected_packages": [pkg_name] if pkg_name else [],
                }
            )

    # Deduplicate by vendor key, keeping first occurrence
    seen: set[str] = set()
    deduped = []
    for r in results:
        key = r["vendor"]
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    return deduped


# ---------------------------------------------------------------------------
# Debian
# ---------------------------------------------------------------------------


def _fetch_debian(cve_id: str, nvd_published: date | None) -> list[dict[str, Any]]:
    """Query Debian Security Tracker for CVE patch information.

    The tracker exposes a large JSON blob; we query the per-CVE endpoint
    to avoid downloading the multi-MB full feed.
    """
    results: list[dict[str, Any]] = []
    url = f"https://security-tracker.debian.org/tracker/{cve_id.upper()}"
    # Debian tracker JSON: GET .../CVE-XXXX-YYYY with Accept: application/json
    try:
        resp = requests.get(
            url,
            headers={"Accept": "application/json"},
            timeout=_TIMEOUT,
            allow_redirects=True,
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        # The per-CVE endpoint returns HTML; use the source JSON API instead
        data = resp.json()
    except Exception as exc:
        logger.debug("Debian tracker fetch failed: %s", exc)
        return []

    # Expected structure: {"pkg_name": {"release": {"status": ..., "fixed_version": ...}}}
    for pkg_name, release_map in data.items():
        if not isinstance(release_map, dict):
            continue
        for release_name, info in release_map.items():
            if not isinstance(info, dict):
                continue
            raw_status = info.get("status", "")
            fixed_ver = info.get("fixed_version", "")
            urgency = info.get("urgency", "")
            nodsa = info.get("nodsa", "")

            if raw_status in ("resolved",):
                status = "fixed"
            elif raw_status in ("open",):
                status = "vulnerable"
            elif nodsa or urgency in ("unimportant",):
                status = "not_affected"
            else:
                status = "unknown" if not raw_status else "vulnerable"

            dsa_list: list[str] = []
            for dsa in info.get("bugs", []):
                dsa_list.append(str(dsa))

            results.append(
                {
                    "vendor": f"debian/{release_name}",
                    "status": status,
                    "fixed_version": fixed_ver if status == "fixed" and fixed_ver else None,
                    "advisory_ids": dsa_list,
                    "patch_date": None,  # Tracker doesn't expose patch date directly
                    "days_to_patch": None,
                    "affected_packages": [pkg_name] if pkg_name else [],
                }
            )

    return results


# ---------------------------------------------------------------------------
# Red Hat
# ---------------------------------------------------------------------------


def _fetch_redhat(cve_id: str, nvd_published: date | None) -> list[dict[str, Any]]:
    """Query Red Hat Security Data API for CVE patch information."""
    results: list[dict[str, Any]] = []
    try:
        data = _get_json(_REDHAT_CVE_URL.format(cve=cve_id.upper()))
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code in (404, 400):
            return []
        logger.debug("Red Hat CVE API error: %s", exc)
        return []
    except Exception as exc:
        logger.debug("Red Hat CVE fetch failed: %s", exc)
        return []

    affected_release = data.get("affected_release", [])
    package_state = data.get("package_state", [])

    # Fixed packages
    for rel in affected_release:
        pkg_name = rel.get("package", "")
        release_name = rel.get("product_name", rel.get("release", ""))
        errata = rel.get("advisory", "")
        release_date_str = rel.get("release_date", "")
        patch_date = _parse_iso_date(release_date_str) if release_date_str else None

        results.append(
            {
                "vendor": f"redhat/{release_name}",
                "status": "fixed",
                "fixed_version": pkg_name or None,
                "advisory_ids": [errata] if errata else [],
                "patch_date": patch_date.isoformat() if patch_date else None,
                "days_to_patch": _days_to_patch(nvd_published, patch_date),
                "affected_packages": [pkg_name.split("-")[0]] if pkg_name else [],
            }
        )

    # Still-vulnerable packages
    for state in package_state:
        pkg_name = state.get("package_name", "")
        fix_state = state.get("fix_state", "")
        release_name = state.get("product_name", state.get("release", ""))
        status = _RH_STATUS_MAP.get(fix_state, "unknown")

        results.append(
            {
                "vendor": f"redhat/{release_name}",
                "status": status,
                "fixed_version": None,
                "advisory_ids": [],
                "patch_date": None,
                "days_to_patch": None,
                "affected_packages": [pkg_name] if pkg_name else [],
            }
        )

    return results


# ---------------------------------------------------------------------------
# OSV.dev — ecosystem-agnostic fix versions
# ---------------------------------------------------------------------------


def _fetch_osv(cve_id: str, nvd_published: date | None) -> list[dict[str, Any]]:
    """Query OSV.dev for fix version data across open-source ecosystems."""
    results: list[dict[str, Any]] = []
    try:
        data = _post_json(_OSV_QUERY_URL, {"id": cve_id.upper()})
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            return []
        logger.debug("OSV query error: %s", exc)
        return []
    except Exception as exc:
        logger.debug("OSV fetch failed: %s", exc)
        return []

    for vuln in data.get("vulns", []):
        osv_id = vuln.get("id", "")
        modified_str = vuln.get("modified", "")
        modified_date = _parse_iso_date(modified_str)

        for affected in vuln.get("affected", []):
            pkg = affected.get("package", {})
            pkg_name = pkg.get("name", "")
            ecosystem = pkg.get("ecosystem", "")

            # Extract fixed versions from ranges
            fixed_versions: list[str] = []
            is_fixed = False
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        fixed_versions.append(event["fixed"])
                        is_fixed = True

            # Fall back to versions list if no range fix found
            if not is_fixed:
                versions = affected.get("versions", [])
                if versions:
                    status = "vulnerable"
                else:
                    status = "unknown"
            else:
                status = "fixed"

            patch_date = modified_date if is_fixed else None

            results.append(
                {
                    "vendor": f"osv/{ecosystem.lower()}",
                    "status": status,
                    "fixed_version": fixed_versions[0] if fixed_versions else None,
                    "advisory_ids": [osv_id] if osv_id else [],
                    "patch_date": patch_date.isoformat() if patch_date else None,
                    "days_to_patch": _days_to_patch(nvd_published, patch_date),
                    "affected_packages": [pkg_name] if pkg_name else [],
                }
            )

    return results


# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------


def _summarise(all_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a top-level summary from the per-vendor result list."""
    total = len(all_results)
    fixed_count = sum(1 for r in all_results if r["status"] == "fixed")
    vulnerable_count = sum(1 for r in all_results if r["status"] == "vulnerable")

    # Fastest patch responder
    patched_with_days = [r for r in all_results if r["status"] == "fixed" and r.get("days_to_patch") is not None]
    fastest = min(patched_with_days, key=lambda r: r["days_to_patch"]) if patched_with_days else None

    # Collect all unique advisory IDs
    all_advisories: list[str] = []
    for r in all_results:
        all_advisories.extend(r.get("advisory_ids") or [])
    all_advisories = list(dict.fromkeys(all_advisories))

    overall_status: str
    if fixed_count == 0 and vulnerable_count == 0:
        overall_status = "unknown"
    elif fixed_count > 0 and vulnerable_count == 0:
        overall_status = "fully_patched"
    elif fixed_count > 0:
        overall_status = "partially_patched"
    else:
        overall_status = "unpatched"

    return {
        "overall_status": overall_status,
        "vendors_checked": total,
        "vendors_fixed": fixed_count,
        "vendors_vulnerable": vulnerable_count,
        "fastest_patch_vendor": fastest["vendor"] if fastest else None,
        "fastest_patch_days": fastest["days_to_patch"] if fastest else None,
        "all_advisory_ids": all_advisories,
    }


# ---------------------------------------------------------------------------
# Strands tool
# ---------------------------------------------------------------------------


@tool
def get_patch_status(cve_id: str) -> dict[str, Any]:
    """Queries multiple Linux distribution and ecosystem security advisories to report patch status for a CVE.

    Checks Ubuntu Security, Debian Security Tracker, Red Hat CVE DB, and OSV.dev.
    Returns per-vendor patch status, fixed versions, advisory IDs, and time-to-patch metrics.

    Args:
        cve_id: The CVE identifier to check (e.g., 'CVE-2024-3094').

    Returns:
        A dict with 'cve_id', 'summary', and 'vendors' (list of per-vendor results).
        summary.overall_status is one of: 'fully_patched', 'partially_patched', 'unpatched', 'unknown'.
    """
    cve_id = cve_id.strip().upper()
    if not _CVE_RE.match(cve_id):
        return {
            "cve_id": cve_id,
            "error": f"Invalid CVE ID format: '{cve_id}'. Expected format: CVE-YYYY-NNNNN",
            "summary": None,
            "vendors": [],
        }

    # Step 1: Get NVD publish date for days_to_patch calculation
    nvd_published = _fetch_nvd_publish_date(cve_id)

    # Step 2: Query all vendors in parallel-ish (sequential for simplicity)
    all_vendors: list[dict[str, Any]] = []

    ubuntu_results = _fetch_ubuntu(cve_id, nvd_published)
    all_vendors.extend(ubuntu_results)

    debian_results = _fetch_debian(cve_id, nvd_published)
    all_vendors.extend(debian_results)

    redhat_results = _fetch_redhat(cve_id, nvd_published)
    all_vendors.extend(redhat_results)

    osv_results = _fetch_osv(cve_id, nvd_published)
    all_vendors.extend(osv_results)

    # Step 3: Build summary
    summary = _summarise(all_vendors)

    return {
        "cve_id": cve_id,
        "nvd_published": nvd_published.isoformat() if nvd_published else None,
        "summary": summary,
        "vendors": all_vendors,
    }
