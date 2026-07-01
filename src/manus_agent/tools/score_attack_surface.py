"""
Tool: score_attack_surface

Given a CVE identifier, estimates how *exposed* the vulnerable component is to
potential attackers.  Exposure is distinct from exploitability: a vulnerability
in a web-facing HTTP server is far more exposed than an identical vulnerability
in an offline CLI utility used by developers — even if the underlying CVSS
score is the same.

## Scoring model

Five independent signals are combined into a 1–5 **exposure score**:

1. **Deployment archetype** (1–5) — What kind of software is typically affected?
   Derived from NVD CPE vendor/product strings and the CVE description:
   - 5 → web server / proxy / load-balancer / API gateway  (internet-facing)
   - 4 → network daemon / embedded device / IoT / VPN
   - 3 → application framework / database / middleware (process-level server)
   - 2 → desktop application / GUI tool / browser extension
   - 1 → CLI utility / library / developer tool / SDK

2. **CVSS Attack Vector** (1–5) — How reachable is the vulnerable service?
   - NETWORK → 5, ADJACENT → 3, LOCAL → 2, PHYSICAL → 1

3. **Internet prevalence** (1–5) — How widely deployed is the affected package?
   Estimated from CPE product name heuristics (well-known web stacks score
   higher than obscure niche products).

4. **Authentication scope** (1–5) — Is an unauthenticated attacker able to
   reach the vulnerable code path?
   Derived from ``privilegesRequired`` and ``scope`` CVSS fields:
   - PR=NONE + SCOPE=CHANGED → 5 (pre-auth, crosses trust boundary)
   - PR=NONE                  → 4
   - PR=LOW                   → 3
   - PR=HIGH                  → 2
   - scope or PR unresolvable → 1

5. **Public facing flag** (1 or 5) — Does the CVE description or CWE
   explicitly reference an internet/public/remote-accessible context?

An overall ``exposure_score`` (1–5, float) is the weighted average.
A companion ``exposure_label`` gives a human-readable tier
(minimal / low / moderate / high / critical).

All HTTP calls are mockable — no side effects in unit tests.
"""

from __future__ import annotations

import json as _json
import re
from typing import Any

import requests
from strands import tool

__all__ = ["score_attack_surface"]

# ---------------------------------------------------------------------------
# Scoring weights (must sum to 1.0)
# ---------------------------------------------------------------------------

_WEIGHTS: dict[str, float] = {
    "deployment_archetype": 0.30,
    "attack_vector": 0.25,
    "internet_prevalence": 0.20,
    "auth_scope": 0.15,
    "public_facing": 0.10,
}

# ---------------------------------------------------------------------------
# Keyword sets for deployment archetype detection
# ---------------------------------------------------------------------------

# Each tier: (score, list-of-patterns)
# Patterns are matched case-insensitively against vendor, product, description.
_ARCHETYPE_TIERS: list[tuple[int, list[str]]] = [
    (
        5,
        [
            "apache",
            "nginx",
            "iis",
            "httpd",
            "tomcat",
            "haproxy",
            "traefik",
            "caddy",
            "lighttpd",
            "squid",
            "varnish",
            "express",
            "fastapi",
            "flask",
            "django",
            "rails",
            "wordpress",
            "drupal",
            "joomla",
            "sharepoint",
            "jenkins",
            "confluence",
            "jira",
            "gitlab",
            "github",
            "bitbucket",
            "sonarqube",
            "grafana",
            "kibana",
            "elastic",
            "solr",
            "web server",
            "http server",
            "proxy server",
            "api gateway",
            "load balancer",
            "reverse proxy",
            "cdn",
            "nextjs",
            "nuxt",
            "strapi",
            "magento",
            "prestashop",
            "moodle",
        ],
    ),
    (
        4,
        [
            "router",
            "firewall",
            "switch",
            "vpn",
            "fortinet",
            "cisco",
            "juniper",
            "palo alto",
            "sonicwall",
            "netgear",
            "zyxel",
            "dlink",
            "tplink",
            "mikrotik",
            "openvpn",
            "wireguard",
            "ssl vpn",
            "remote desktop",
            "rdp",
            "iot",
            "embedded",
            "firmware",
            "scada",
            "industrial",
            "plc",
            "hmi",
            "camera",
            "dvr",
            "nvr",
            "nas",
            "opnsense",
            "pfsense",
            "f5",
            "bigip",
            "pulse",
            "ivanti",
            "citrix",
            "vmware",
        ],
    ),
    (
        3,
        [
            "mysql",
            "postgresql",
            "postgres",
            "mongodb",
            "redis",
            "rabbitmq",
            "kafka",
            "elasticsearch",
            "cassandra",
            "memcached",
            "spring",
            "struts",
            "log4j",
            "log4shell",
            "java",
            "jvm",
            "jboss",
            "weblogic",
            "websphere",
            "glassfish",
            "wildfly",
            "keycloak",
            "oauth",
            "ldap",
            "active directory",
            "samba",
            "nfs",
            "smb",
            "smtp",
            "mail server",
            "postfix",
            "exim",
            "sendmail",
            "dovecot",
            "ftp",
            "sftp",
            "ssh",
            "database",
            "middleware",
            "message queue",
            "container",
            "docker",
            "kubernetes",
            "k8s",
            "openshift",
        ],
    ),
    (
        2,
        [
            "browser",
            "firefox",
            "chrome",
            "chromium",
            "safari",
            "edge",
            "internet explorer",
            "pdf reader",
            "acrobat",
            "office",
            "word",
            "excel",
            "powerpoint",
            "outlook",
            "libreoffice",
            "gimp",
            "photoshop",
            "vlc",
            "media player",
            "electron",
            "desktop application",
            "gui",
            "extension",
            "plugin",
            "add-on",
        ],
    ),
    (
        1,
        [
            "cli",
            "command.line",
            "command line",
            "library",
            "sdk",
            "framework",
            "module",
            "package",
            "npm",
            "pip",
            "pypi",
            "gem",
            "cargo",
            "gradle",
            "maven",
            "composer",
            "developer tool",
            "dev tool",
            "build tool",
            "compiler",
            "linter",
            "formatter",
            "test",
            "unittest",
        ],
    ),
]

# ---------------------------------------------------------------------------
# Product names whose widespread internet deployment is well-documented
# Presence → prevalence score = 5
# ---------------------------------------------------------------------------

_HIGH_PREVALENCE_PRODUCTS = frozenset(
    [
        "apache",
        "nginx",
        "iis",
        "wordpress",
        "drupal",
        "joomla",
        "tomcat",
        "log4j",
        "log4shell",
        "spring",
        "struts",
        "sharepoint",
        "exchange",
        "jenkins",
        "confluence",
        "jira",
        "gitlab",
        "github",
        "grafana",
        "kibana",
        "elasticsearch",
        "redis",
        "mysql",
        "postgresql",
        "mongodb",
        "openssl",
        "openssh",
        "php",
        "python",
        "node",
        "nodejs",
        "express",
        "rails",
        "django",
        "flask",
        "fastapi",
        "cisco",
        "fortinet",
        "palo alto",
        "vmware",
        "citrix",
        "ivanti",
        "pulse",
        "f5",
        "bigip",
    ]
)

# ---------------------------------------------------------------------------
# NVD fetch helpers
# ---------------------------------------------------------------------------

_NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"


def _fetch_nvd_data(cve_id: str) -> dict[str, Any]:
    """Fetch and return the raw NVD CVE entry, or ``{}`` on failure."""
    try:
        resp = requests.get(_NVD_CVE_URL.format(cve_id=cve_id.upper()), timeout=15)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if vulns:
            return vulns[0].get("cve", {})
    except requests.RequestException:
        pass
    return {}


def _extract_cvss_fields(cve_data: dict[str, Any]) -> dict[str, Any]:
    """Return a flat dict of CVSS v3.x fields, or ``{}`` if unavailable."""
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            cv = entries[0].get("cvssData", {})
            return {
                "attackVector": cv.get("attackVector", ""),
                "privilegesRequired": cv.get("privilegesRequired", ""),
                "scope": cv.get("scope", ""),
                "baseScore": cv.get("baseScore"),
            }
    return {}


def _extract_description(cve_data: dict[str, Any]) -> str:
    """Return the English CVE description text, or ``""`` if absent."""
    for d in cve_data.get("descriptions", []):
        if d.get("lang", "").lower().startswith("en"):
            return d.get("value", "")
    return ""


def _extract_cpe_strings(cve_data: dict[str, Any]) -> list[str]:
    """Return all CPE 2.3 strings from the NVD configurations block."""
    cpe_strings: list[str] = []
    configs = cve_data.get("configurations", [])
    for config in configs:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                uri = match.get("criteria", "")
                if uri:
                    cpe_strings.append(uri)
    return cpe_strings


def _extract_cwes(cve_data: dict[str, Any]) -> list[str]:
    """Return all CWE IDs associated with the CVE."""
    cwes: list[str] = []
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)
    return cwes


# ---------------------------------------------------------------------------
# CPE parsing helpers
# ---------------------------------------------------------------------------

_CPE_RE = re.compile(r"cpe:2\.3:[ao]:([^:]+):([^:]+):", re.IGNORECASE)


def _cpe_vendor_product(cpe_string: str) -> tuple[str, str]:
    """Extract (vendor, product) from a CPE 2.3 string, lower-cased."""
    m = _CPE_RE.match(cpe_string)
    if m:
        return m.group(1).lower(), m.group(2).lower()
    return "", ""


def _build_target_corpus(description: str, cpe_strings: list[str]) -> str:
    """Build a single lower-cased searchable text corpus from description + CPEs."""
    parts = [description.lower()]
    for cpe in cpe_strings:
        vendor, product = _cpe_vendor_product(cpe)
        parts.append(vendor)
        parts.append(product.replace("_", " ").replace("-", " "))
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Individual dimension scorers
# ---------------------------------------------------------------------------


def _score_deployment_archetype(corpus: str) -> tuple[int, str]:
    """Return (score 1-5, matched_archetype_label) from keyword tiers."""
    for score, keywords in _ARCHETYPE_TIERS:
        for kw in keywords:
            if kw in corpus:
                return score, _archetype_label(score)
    # Default: treat unknown as library/SDK (lowest exposure)
    return 1, "cli_or_library"


def _archetype_label(score: int) -> str:
    labels = {
        5: "web_server_or_api_gateway",
        4: "network_device_or_iot",
        3: "database_or_middleware",
        2: "desktop_or_browser",
        1: "cli_or_library",
    }
    return labels.get(score, "unknown")


def _score_attack_vector(av: str) -> int:
    """Convert NVD attackVector to exposure score (higher = more exposed)."""
    return {
        "NETWORK": 5,
        "ADJACENT": 3,
        "LOCAL": 2,
        "PHYSICAL": 1,
    }.get(av.upper(), 3)  # default moderate if unknown


def _score_internet_prevalence(corpus: str) -> int:
    """Estimate how widely deployed the component is (1-5)."""
    for token in _HIGH_PREVALENCE_PRODUCTS:
        if token in corpus:
            return 5
    # Medium-prevalence heuristics
    medium_signals = [
        "server",
        "service",
        "daemon",
        "application",
        "platform",
        "suite",
        "enterprise",
        "cloud",
    ]
    hits = sum(1 for s in medium_signals if s in corpus)
    if hits >= 3:
        return 4
    if hits >= 1:
        return 3
    return 2  # generic fallback


def _score_auth_scope(pr: str, scope: str) -> int:
    """Score how easily an unauthenticated attacker can reach the bug."""
    pr_upper = pr.upper()
    scope_upper = scope.upper()
    if pr_upper == "NONE" and scope_upper == "CHANGED":
        return 5  # pre-auth + crosses trust boundary
    if pr_upper == "NONE":
        return 4
    if pr_upper == "LOW":
        return 3
    if pr_upper == "HIGH":
        return 2
    return 1  # unknown / unresolvable


_PUBLIC_FACING_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\binternet[- ]facing\b",
        r"\bpublicly accessible\b",
        r"\bremote\s+attacker\b",
        r"\bunauthenticated\s+remote\b",
        r"\bremote\s+code\s+execution\b",
        r"\bremote\s+unauthenticated\b",
        r"\bwithout\s+authentication\b",
        r"\bno\s+authentication\b",
        r"\banonymous\s+user\b",
        r"\bpre-auth\b",
        r"\bexposed\s+to\s+the\s+internet\b",
        r"\bpublic[- ]facing\b",
        r"\binbound\s+request\b",
    ]
]

# CWEs that strongly imply public-facing / remote exposure
_PUBLIC_FACING_CWES = frozenset(
    ["CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-502", "CWE-918", "CWE-611", "CWE-352", "CWE-287"]
)


def _score_public_facing(description: str, cwes: list[str]) -> int:
    """Return 5 if description/CWEs signal internet/public exposure, else 1."""
    for pat in _PUBLIC_FACING_PATTERNS:
        if pat.search(description):
            return 5
    for cwe in cwes:
        if cwe in _PUBLIC_FACING_CWES:
            return 5
    return 1


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def _compute_overall(dimensions: dict[str, int]) -> float:
    """Weighted average of all dimension scores, rounded to 2dp."""
    return round(sum(_WEIGHTS[k] * dimensions[k] for k in _WEIGHTS), 2)


def _exposure_label(score: float) -> str:
    if score < 1.5:
        return "minimal"
    if score < 2.5:
        return "low"
    if score < 3.5:
        return "moderate"
    if score < 4.5:
        return "high"
    return "critical"


def _dimension_label(score: int) -> str:
    labels = ["", "minimal", "low", "moderate", "high", "critical"]
    return labels[max(1, min(5, score))]


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------


def _run_attack_surface(cve_id: str) -> dict[str, Any]:
    """Execute the full attack-surface scoring pipeline for *cve_id*."""
    cve_id = cve_id.upper().strip()

    # ── 1. Fetch NVD data ────────────────────────────────────────────────────
    cve_data = _fetch_nvd_data(cve_id)
    cvss = _extract_cvss_fields(cve_data)
    description = _extract_description(cve_data)
    cpe_strings = _extract_cpe_strings(cve_data)
    cwes = _extract_cwes(cve_data)

    # ── 2. Build searchable corpus ───────────────────────────────────────────
    corpus = _build_target_corpus(description, cpe_strings)

    # ── 3. Score each dimension ──────────────────────────────────────────────
    av = cvss.get("attackVector", "")
    pr = cvss.get("privilegesRequired", "")
    scope = cvss.get("scope", "")

    archetype_score, archetype_label = _score_deployment_archetype(corpus)

    dimensions: dict[str, int] = {
        "deployment_archetype": archetype_score,
        "attack_vector": _score_attack_vector(av),
        "internet_prevalence": _score_internet_prevalence(corpus),
        "auth_scope": _score_auth_scope(pr, scope),
        "public_facing": _score_public_facing(description, cwes),
    }

    overall = _compute_overall(dimensions)

    return {
        "cve_id": cve_id,
        "exposure_score": overall,
        "exposure_label": _exposure_label(overall),
        "archetype": archetype_label,
        "dimensions": dimensions,
        "cvss_available": bool(cvss),
        "cpe_count": len(cpe_strings),
        "cwes": cwes,
        "attack_vector": av or "unknown",
        "privileges_required": pr or "unknown",
        "scope": scope or "unknown",
        "cvss_base_score": cvss.get("baseScore"),
        "rationale": _build_rationale(dimensions, archetype_label, av, pr, scope, description),
    }


def _build_rationale(
    dimensions: dict[str, int],
    archetype_label: str,
    av: str,
    pr: str,
    scope: str,
    description: str,
) -> str:
    """Build a one-paragraph rationale explaining the exposure score."""
    parts: list[str] = []

    arch_score = dimensions["deployment_archetype"]
    if arch_score >= 4:
        parts.append(
            f"The component is classified as a '{archetype_label.replace('_', ' ')}' "
            "— a high-exposure deployment class."
        )
    elif arch_score == 3:
        parts.append(
            f"The component is classified as '{archetype_label.replace('_', ' ')}' "
            "— a moderate-exposure server-side component."
        )
    else:
        parts.append(
            f"The component is classified as '{archetype_label.replace('_', ' ')}' "
            "— a relatively low-exposure component type."
        )

    av_score = dimensions["attack_vector"]
    if av:
        av_map = {
            5: "network-reachable (NETWORK)",
            3: "adjacent-network only",
            2: "local access required",
            1: "physical access required",
        }
        parts.append(f"Attack vector is {av_map.get(av_score, av)} ({av}).")

    auth_score = dimensions["auth_scope"]
    if pr:
        if auth_score >= 4:
            parts.append("No authentication is required, maximising the attacker's reach.")
        elif auth_score == 3:
            parts.append("Low-privilege credentials are required, slightly limiting exposure.")
        else:
            parts.append("High privileges are required, substantially reducing exposure.")

    if dimensions["public_facing"] == 5:
        parts.append("The vulnerability description or CWE strongly indicates public/internet-facing exposure.")

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Text renderer
# ---------------------------------------------------------------------------


def _render_text(result: dict[str, Any]) -> str:
    lines = [
        f"Attack Surface Exposure Score: {result['cve_id']}",
        "=" * 60,
        f"  Exposure score   : {result['exposure_score']:.2f} / 5  ({result['exposure_label'].upper()})",
        f"  Component type   : {result['archetype'].replace('_', ' ')}",
        f"  CVSS base score  : {result['cvss_base_score'] if result['cvss_base_score'] is not None else 'N/A'}",
        "",
        "Dimension breakdown (1 = minimal exposure, 5 = maximum)",
        "-" * 60,
    ]
    dim_names = {
        "deployment_archetype": "Deployment archetype",
        "attack_vector": "CVSS attack vector",
        "internet_prevalence": "Internet prevalence",
        "auth_scope": "Authentication scope",
        "public_facing": "Public-facing indicators",
    }
    for key, label in dim_names.items():
        score = result["dimensions"][key]
        dlabel = _dimension_label(score)
        lines.append(f"  {label:<30}: {score}/5  ({dlabel})")
    lines += [
        "",
        "Rationale",
        "-" * 60,
        f"  {result['rationale']}",
        "",
        "Data sources",
        "-" * 60,
        f"  NVD CVSS data    : {'available' if result['cvss_available'] else 'not available'}",
        f"  CPE entries      : {result['cpe_count']}",
        f"  CWEs             : {', '.join(result['cwes']) if result['cwes'] else 'none'}",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Strands tool entry point
# ---------------------------------------------------------------------------

TOOL_SPEC = {
    "name": "score_attack_surface",
    "description": (
        "Estimates how exposed a vulnerable component is to potential attackers on a 1–5 scale "
        "(1 = minimal exposure, 5 = critical/internet-facing). "
        "Analyses five independent signals: deployment archetype (web server vs library vs CLI), "
        "CVSS attack vector, internet prevalence of the affected product, authentication requirements, "
        "and public-facing indicators from the CVE description and CWEs. "
        "Returns a weighted exposure score, a human-readable label "
        "(minimal/low/moderate/high/critical), a component archetype, and a one-paragraph rationale. "
        "Use alongside score_exploit_complexity to get a full attacker-perspective picture: "
        "complexity measures *how hard* an exploit is, exposure measures *how reachable* the target is."
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier to score (e.g., 'CVE-2021-44228').",
                },
                "output": {
                    "type": "string",
                    "enum": ["text", "json"],
                    "description": "Output format: 'text' (default) or 'json'.",
                },
            },
            "required": ["cve_id"],
        }
    },
}


@tool
def score_attack_surface(cve_id: str, output: str = "text") -> str:
    """Estimate the attack surface exposure of a CVE on a 1–5 scale.

    Args:
        cve_id: CVE identifier (e.g. 'CVE-2021-44228').
        output: 'text' (default) or 'json'.

    Returns:
        Formatted report string.
    """
    cve_id = cve_id.strip() if isinstance(cve_id, str) else cve_id
    if not isinstance(cve_id, str) or not re.match(r"CVE-\d{4}-\d+", cve_id, re.IGNORECASE):
        return "Error: cve_id must be a valid CVE identifier like 'CVE-2021-44228'."

    result = _run_attack_surface(cve_id)

    if output == "json":
        return _json.dumps(result, indent=2)

    return _render_text(result)
