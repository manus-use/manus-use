"""
Tool for tracking a vendor's patch response to a CVE.

Given a CVE identifier, this tool:
1. Fetches NVD data to identify the affected vendor and product.
2. Searches for the vendor's GitHub security advisory (GHSA) for that CVE.
3. Scans the vendor's GitHub security tab (if a repo is identifiable).
4. Checks NVD reference links for vendor advisory / patch / release URLs.
5. Inspects CISA KEV for required-action and due-date metadata.
6. Classifies the vendor patch status as one of:
   - no_patch      — no fix available, no mitigation disclosed
   - patch_available — patch released and confirmed (commit, advisory, or release)
   - patch_backported — patch backported to older branch(es) (indicators found)
   - wont_fix       — vendor explicitly will not release a fix
   - investigating  — vendor has acknowledged but no fix yet (advisory only, no patch)
   - unknown        — insufficient public information to determine status

Returns a structured dict plus a human-readable summary.
"""

from __future__ import annotations

import re
from typing import Any

import requests
from strands.types.tools import ToolResult, ToolUse

from manus_use.tools.tool_output_logger import log_tool_output_size

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

_TIMEOUT = 12  # seconds for each individual HTTP request

# Patterns that signal a vendor has shipped a fix
_PATCH_KEYWORDS: list[str] = [
    "fixed in",
    "fix released",
    "update available",
    "patched in",
    "resolved in",
    "upgraded to",
    "version .* fix",
    "release .* address",
    r"commit\s+[0-9a-f]{7}",
    "pull request",
    "merge request",
    "security release",
    "security update",
    "upgrade to",
    "mitigated in",
]

# Patterns that signal patch backporting
_BACKPORT_KEYWORDS: list[str] = [
    "backport",
    "back.port",
    "lts branch",
    "maintenance branch",
    "stable branch",
    "older version",
    "legacy version",
]

# Patterns that signal wont-fix
_WONT_FIX_KEYWORDS: list[str] = [
    "will not fix",
    "won.t fix",
    "no fix",
    "not fix",
    "out of support",
    "end of life",
    "eol",
    "deprecated",
    "unsupported",
    "by design",
    "not a vulnerability",
    "disputed",
    "working as intended",
    "wontfix",
]

# Patterns that signal the vendor is investigating / has acknowledged
_INVESTIGATING_KEYWORDS: list[str] = [
    "investigating",
    "under investigation",
    "awareness",
    "aware of",
    "is aware",
    "monitoring",
    "tracking",
    "acknowledged",
    "looking into",
]

# Reference-link URL patterns that are typically vendor advisory / patch pages
_ADVISORY_URL_PATTERNS: list[str] = [
    r"github\.com/.+/security/advisories",
    r"github\.com/.+/commit/[0-9a-f]{10,}",
    r"github\.com/.+/releases/tag",
    r"github\.com/.+/pull/\d+",
    r"gitlab\.com/.+/commit/[0-9a-f]{10,}",
    r"gitlab\.com/.+/merge_requests/\d+",
    r"advisory\.",
    r"/security[-_]advisory",
    r"/security[-_]bulletin",
    r"/security[-_]update",
    r"\.security\.",
    r"cve\.mitre\.org",
    r"packetstorm",
    r"exploit-db",
    r"kb\.cert",
    r"bugzilla\.",
    r"jvn\.jp",
]

# ──────────────────────────────────────────────────────────────────────────────
# Tool spec (Strands SDK format)
# ──────────────────────────────────────────────────────────────────────────────

TOOL_SPEC = {
    "name": "track_vendor_response",
    "description": (
        "Tracks the vendor's patch response to a CVE by consulting the NVD reference list, "
        "GitHub Security Advisory database (GHSA), CISA KEV, and the vendor's own GitHub security "
        "tab (when the affected repository is identifiable). "
        "Classifies patch status as: no_patch / patch_available / patch_backported / wont_fix / "
        "investigating / unknown. "
        "Returns the classification, confidence level, evidence links, and a plain-English summary. "
        "Use this when you need to answer 'Is there a fix available, and has the vendor responded?'"
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "The CVE identifier to look up (e.g., 'CVE-2024-3094').",
                },
            },
            "required": ["cve_id"],
        }
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────


def _get(url: str, *, params: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
    """HTTP GET with error capture. Returns parsed JSON or {'_error': str}."""
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        return {"_error": str(exc)}


def _fetch_nvd(cve_id: str) -> dict[str, Any]:
    """Return NVD CVE record dict, or {'_error': ...}."""
    data = _get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": cve_id.upper()},
    )
    if "_error" in data:
        return data
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {"_error": f"No NVD record for {cve_id}"}
    return vulns[0].get("cve", {})


def _nvd_references(nvd_cve: dict[str, Any]) -> list[str]:
    """Extract all reference URLs from an NVD CVE record."""
    refs = nvd_cve.get("references", [])
    return [r.get("url", "") for r in refs if r.get("url")]


def _nvd_affected_vendor_product(nvd_cve: dict[str, Any]) -> tuple[str, str]:
    """Best-effort extraction of (vendor, product) from NVD CPE configurations."""
    configs = nvd_cve.get("configurations", [])
    for config in configs:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                cpe = cpe_match.get("criteria", "")
                # cpe:2.3:a:vendor:product:version:...
                parts = cpe.split(":")
                if len(parts) >= 5:
                    return parts[3], parts[4]
    return "", ""


def _fetch_ghsa(cve_id: str) -> dict[str, Any]:
    """Query GitHub Security Advisory (GHSA) REST API for the CVE."""
    data = _get(
        "https://api.github.com/advisories",
        params={"cve_id": cve_id.upper(), "per_page": 5},
        headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
    )
    if isinstance(data, list):
        return {"advisories": data}
    if isinstance(data, dict) and "_error" not in data:
        return {"advisories": data.get("items", [])}
    return {"advisories": [], "_error": data.get("_error", "")}


def _fetch_cisa_kev(cve_id: str) -> dict[str, Any]:
    """Fetch CISA KEV catalog and find entry for the given CVE."""
    data = _get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    if "_error" in data:
        return {}
    vulns = data.get("vulnerabilities", [])
    for v in vulns:
        if v.get("cveID", "").upper() == cve_id.upper():
            return v
    return {}


def _search_github_repo_advisories(owner: str, repo: str, cve_id: str) -> list[dict[str, Any]]:
    """
    Query GitHub's repository-level security advisories endpoint
    for a specific CVE.  Returns a (possibly empty) list of advisory dicts.
    """
    import os

    headers: dict[str, str] = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    data = _get(
        f"https://api.github.com/repos/{owner}/{repo}/security-advisories",
        params={"per_page": 20},
        headers=headers,
    )
    if isinstance(data, list):
        return [a for a in data if cve_id.upper() in str(a.get("cve_id", "")).upper()]
    return []


def _extract_github_repo_from_refs(refs: list[str]) -> tuple[str, str] | None:
    """
    Try to identify a GitHub repo (owner/repo) from the reference links.
    Returns (owner, repo) or None.
    """
    pattern = re.compile(r"github\.com/([^/]+)/([^/?#]+)", re.IGNORECASE)
    seen: dict[str, int] = {}
    for url in refs:
        m = pattern.search(url)
        if m:
            key = f"{m.group(1)}/{m.group(2)}"
            seen[key] = seen.get(key, 0) + 1
    if not seen:
        return None
    best = max(seen, key=lambda k: seen[k])
    owner, repo = best.split("/", 1)
    # Strip .git suffix
    repo = repo.removesuffix(".git")
    return owner, repo


def _keywords_match(text: str, patterns: list[str]) -> list[str]:
    """Return which patterns matched (case-insensitive) in text."""
    text_lower = text.lower()
    matched = []
    for pat in patterns:
        if re.search(pat, text_lower):
            matched.append(pat)
    return matched


def _classify(
    nvd_refs: list[str],
    ghsa_advisories: list[dict[str, Any]],
    kev_entry: dict[str, Any],
    repo_advisories: list[dict[str, Any]],
) -> tuple[str, str, list[str]]:
    """
    Determine (status, confidence, evidence_urls).

    Classification precedence:
    1. wont_fix  — explicit wont-fix language anywhere
    2. patch_backported — backport language found alongside patch indicators
    3. patch_available  — patch confirmed (commit / release URL or GHSA with patches)
    4. investigating    — acknowledged but no fix
    5. no_patch         — no evidence of any fix
    6. unknown          — insufficient data
    """
    evidence_urls: list[str] = []
    all_text_parts: list[str] = []

    # ── GHSA advisories ──────────────────────────────────────────────────────
    for adv in ghsa_advisories + repo_advisories:
        state = adv.get("state", "").lower()
        # Published GHSA = patch exists
        if state == "published":
            evidence_urls.append(adv.get("html_url", ""))
            # Gather patch references from GHSA
            for ref in adv.get("references", []):
                url = ref if isinstance(ref, str) else ref.get("url", "")
                if url:
                    evidence_urls.append(url)
                    all_text_parts.append(url)
        description = adv.get("description", "") or adv.get("summary", "")
        all_text_parts.append(description.lower())
        # Extract patches from GHSA structured data
        for vuln in adv.get("vulnerabilities", []):
            patched = vuln.get("patched_versions", "")
            if patched and patched not in ("*", "unknown", ""):
                all_text_parts.append(f"patched_versions:{patched}")

    # ── NVD references ────────────────────────────────────────────────────────
    for url in nvd_refs:
        all_text_parts.append(url.lower())
        # URLs that look like patches / releases / advisories
        for apat in _ADVISORY_URL_PATTERNS:
            if re.search(apat, url, re.IGNORECASE):
                evidence_urls.append(url)
                break

    # ── CISA KEV ─────────────────────────────────────────────────────────────
    if kev_entry:
        action = kev_entry.get("requiredAction", "").lower()
        all_text_parts.append(action)
        notes = kev_entry.get("notes", "").lower()
        all_text_parts.append(notes)

    combined_text = " ".join(all_text_parts)
    evidence_urls = [u for u in dict.fromkeys(evidence_urls) if u]  # deduplicate

    # ── Classify ──────────────────────────────────────────────────────────────
    wont_fix_hits = _keywords_match(combined_text, _WONT_FIX_KEYWORDS)
    patch_hits = _keywords_match(combined_text, _PATCH_KEYWORDS)
    backport_hits = _keywords_match(combined_text, _BACKPORT_KEYWORDS)
    investigating_hits = _keywords_match(combined_text, _INVESTIGATING_KEYWORDS)

    # GHSA published or repo advisory published = strong patch signal
    ghsa_published = any((a.get("state", "").lower() == "published") for a in (ghsa_advisories + repo_advisories))
    # GHSA with explicit patched_versions = very strong patch signal
    has_patched_versions = any(
        vuln.get("patched_versions", "") not in ("", "*", "unknown")
        for a in (ghsa_advisories + repo_advisories)
        for vuln in a.get("vulnerabilities", [])
    )
    # Any commit URL in references = patch confirmed
    commit_in_refs = any(re.search(r"github\.com/.+/commit/[0-9a-f]{10,}", u, re.IGNORECASE) for u in nvd_refs)
    # Release URL in references
    release_in_refs = any(re.search(r"github\.com/.+/releases/tag", u, re.IGNORECASE) for u in nvd_refs)

    if wont_fix_hits:
        status = "wont_fix"
        confidence = "high" if len(wont_fix_hits) >= 2 else "moderate"
    elif has_patched_versions or (ghsa_published and (commit_in_refs or release_in_refs or has_patched_versions)):
        if backport_hits:
            status = "patch_backported"
            confidence = "moderate"
        else:
            status = "patch_available"
            confidence = "high"
    elif commit_in_refs or release_in_refs:
        if backport_hits:
            status = "patch_backported"
            confidence = "moderate"
        else:
            status = "patch_available"
            confidence = "high"
    elif ghsa_published:
        status = "patch_available"
        confidence = "moderate"
    elif patch_hits:
        if backport_hits:
            status = "patch_backported"
            confidence = "low"
        else:
            status = "patch_available"
            confidence = "low"
    elif investigating_hits:
        status = "investigating"
        confidence = "moderate"
    elif all_text_parts:
        status = "no_patch"
        confidence = "low"
    else:
        status = "unknown"
        confidence = "low"

    return status, confidence, evidence_urls[:10]  # cap evidence list


def _build_summary(
    cve_id: str,
    status: str,
    confidence: str,
    evidence_urls: list[str],
    vendor: str,
    product: str,
    kev_entry: dict[str, Any],
    ghsa_count: int,
) -> str:
    """Produce a concise plain-English vendor response summary."""
    status_labels = {
        "patch_available": "✅ Patch Available",
        "patch_backported": "🔄 Patch Backported",
        "wont_fix": "🚫 Won't Fix",
        "investigating": "🔍 Under Investigation",
        "no_patch": "❌ No Patch",
        "unknown": "❓ Unknown",
    }
    label = status_labels.get(status, status.replace("_", " ").title())

    lines = [f"Vendor Response for {cve_id.upper()}: {label} (confidence: {confidence})"]
    if vendor or product:
        lines.append(f"Affected: {vendor}/{product}" if vendor and product else f"Affected: {vendor or product}")
    if kev_entry:
        required = kev_entry.get("requiredAction", "")
        due = kev_entry.get("dueDate", "")
        lines.append(f"CISA KEV: required action — {required}" + (f" (due {due})" if due else ""))
    if ghsa_count:
        lines.append(f"GitHub Security Advisories found: {ghsa_count}")
    if evidence_urls:
        lines.append("Evidence:")
        for url in evidence_urls[:5]:
            lines.append(f"  • {url}")
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point (Strands tool)
# ──────────────────────────────────────────────────────────────────────────────


def track_vendor_response(tool: ToolUse, **kwargs: Any) -> ToolResult:
    """Strands tool entry point for vendor response tracking."""
    tool_use_id = tool["toolUseId"]
    tool_input = tool["input"]
    cve_id = tool_input.get("cve_id", "")

    if not isinstance(cve_id, str) or not re.match(r"CVE-\d{4}-\d+", cve_id, re.IGNORECASE):
        result = {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": "Invalid CVE ID format. Must be a string like 'CVE-YYYY-NNNN'."}],
        }
        log_tool_output_size("track_vendor_response", result)
        return result

    cve_id = cve_id.upper()

    # ── Step 1: NVD ────────────────────────────────────────────────────────
    nvd_cve = _fetch_nvd(cve_id)
    if "_error" in nvd_cve:
        nvd_refs: list[str] = []
        vendor, product = "", ""
    else:
        nvd_refs = _nvd_references(nvd_cve)
        vendor, product = _nvd_affected_vendor_product(nvd_cve)

    # ── Step 2: GHSA ────────────────────────────────────────────────────────
    ghsa_result = _fetch_ghsa(cve_id)
    ghsa_advisories = ghsa_result.get("advisories", [])

    # ── Step 3: CISA KEV ────────────────────────────────────────────────────
    kev_entry = _fetch_cisa_kev(cve_id)

    # ── Step 4: Repo-level GitHub security advisories ──────────────────────
    repo_advisories: list[dict[str, Any]] = []
    gh_repo = _extract_github_repo_from_refs(nvd_refs)
    if gh_repo:
        owner, repo = gh_repo
        repo_advisories = _search_github_repo_advisories(owner, repo, cve_id)

    # ── Step 5: Classify ────────────────────────────────────────────────────
    status, confidence, evidence_urls = _classify(nvd_refs, ghsa_advisories, kev_entry, repo_advisories)

    # ── Step 6: Build output ─────────────────────────────────────────────────
    summary = _build_summary(
        cve_id=cve_id,
        status=status,
        confidence=confidence,
        evidence_urls=evidence_urls,
        vendor=vendor,
        product=product,
        kev_entry=kev_entry,
        ghsa_count=len(ghsa_advisories) + len(repo_advisories),
    )

    output: dict[str, Any] = {
        "cve_id": cve_id,
        "status": status,
        "confidence": confidence,
        "vendor": vendor,
        "product": product,
        "evidence_urls": evidence_urls,
        "ghsa_advisories_found": len(ghsa_advisories),
        "repo_advisories_found": len(repo_advisories),
        "in_cisa_kev": bool(kev_entry),
        "cisa_required_action": kev_entry.get("requiredAction", ""),
        "cisa_due_date": kev_entry.get("dueDate", ""),
        "summary": summary,
    }

    result = {
        "toolUseId": tool_use_id,
        "status": "success",
        "content": [{"json": output}],
    }
    log_tool_output_size("track_vendor_response", result)
    return result
