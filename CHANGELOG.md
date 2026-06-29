# Changelog

All notable changes to **manus-use** are documented here.

This project follows [Conventional Commits](https://www.conventionalcommits.org/)
and [Semantic Versioning](https://semver.org/).

<!-- Unreleased entries are added here by `scripts/release.py` -->
## [Unreleased]

### Added
- `score_temporal_priority` tool and `manus-use temporal-priority` CLI subcommand —
  scores how urgently a CVE must be acted on *today* using CVSS, EPSS, spike recency
  (exponential decay with 30-day half-life), CISA KEV membership, patch availability,
  and CVE age pressure. Returns a 0–100 score with CRITICAL/HIGH/MEDIUM/LOW band.
- `scan_sbom` tool and `manus-use sbom-scan` CLI subcommand — scans a CycloneDX or
  SPDX SBOM file for vulnerable dependencies using OSV.dev batch queries, EPSS
  enrichment, and CISA KEV cross-reference. Supports JSON and XML SBOM formats.
- `get_dependency_blast_radius` tool and `manus-use blast-radius` CLI subcommand —
  given a `package@version` identifier, resolves all known downstream dependents across
  PyPI, npm, and Maven to quantify exposure surface.
- `check_poc_freshness` tool and `manus-use poc-freshness` CLI subcommand — assesses
  whether public PoC exploits for a CVE are still active, recently updated, or stale
  (archived/dormant), helping prioritise exploits with live maintainers over abandoned ones.
- `track_vendor_response` tool and `manus-use vendor-response` CLI subcommand — tracks
  vendor patch/advisory state by cross-referencing NVD, VulnCheck KEV, and CISA KEV
  to give a confidence-weighted vendor response status.
- `get_affected_version_range` tool and `manus-use version-range` CLI subcommand —
  resolves the precise affected version range for a CVE from NVD CPE data, returning
  structured `versionStartIncluding` / `versionEndExcluding` bounds.
- `get_cve_timeline` tool and `manus-use timeline` CLI subcommand — builds a
  chronological timeline for a CVE from NVD publication date through advisory issuances,
  patch commits, PoC appearance, and KEV addition.
- `find_silent_patches` tool and `manus-use silent-patches` CLI subcommand — detects
  security fixes committed without a CVE assignment by scanning commit messages for
  security-related keywords across GitHub repositories.
- `search_poc_sources` multi-source PoC aggregator tool — consolidates results from
  Exploit-DB, PacketStorm, Trickest CVEdb, and OTX in a single ranked response.
- `get_vulncheck_data` tool — enriches CVE data with VulnCheck KEV and NVD2 indices
  (requires `VULNCHECK_API_KEY`; degrades gracefully when absent).
- `score_exploit_complexity` tool and `manus-use exploit-complexity` CLI subcommand —
  scores how hard a CVE is to weaponise using attack vector, attack complexity, and
  privileges-required CVSS metrics plus exploit-in-the-wild signals.
- `compare_cves` tool and `manus-use compare` CLI subcommand — side-by-side comparison
  of two CVEs across CVSS, EPSS, KEV membership, and patch status.
- `get_patch_diff` tool and `manus-use patch-diff` CLI subcommand — fetches and
  summarises the patch diff from a GitHub commit URL.
- `get_epss_trend` tool and `manus-use epss-trend` CLI subcommand — retrieves daily
  EPSS scores for a CVE and detects exploitation spikes.
- `manus-use poc-search` CLI subcommand — searches public PoC sources from the command
  line.
- `.github/workflows/publish.yml` — automated PyPI publishing via OIDC Trusted
  Publishing (no long-lived API tokens), triggered on `v*` tags; runs validate →
  build → publish-pypi → github-release pipeline.
- `.pre-commit-config.yaml` — pre-commit hooks: ruff lint+format, check-yaml,
  check-toml, end-of-file-fixer, check-merge-conflict, debug-statements.
- `scripts/release.py` — release helper: parses conventional commits, generates
  CHANGELOG sections, bumps version in `pyproject.toml`, and optionally creates a
  GitHub release tag.

---

## [0.1.0] — 2026-06-26

### Added
- `VulnerabilityIntelligenceAgent` — Strands-based agent for deep CVE analysis,
  incorporating NVD data, EPSS scores, CISA KEV, GitHub advisories, PoC search,
  and exploit verification.
- `manus-use analyze <CVE-ID>` — one-shot CLI to run the vulnerability intelligence
  agent against a single CVE.
- `manus-use discover` — discover recently published CVEs above an EPSS threshold.
- `manus-use remediate <CVE-ID>` — generate a remediation plan for a CVE.
- `manus-use variants <CVE-ID>` — find variant/related CVEs in the same component or
  by the same researcher.
- `manus-use run` — general-purpose interactive and single-shot agent runner.
- `manus-use init` — initialise a `config.toml` with API keys and model settings.
- `manus-use doctor` — validate configuration and check connectivity.
- `ManusAgent` — general-purpose multi-tool agent with browser, code execution,
  web search, and file operations.
- `WorkflowAgent` — multi-agent orchestrator capable of spawning and coordinating
  specialist sub-agents.
- Core tools: `check_cisa_kev`, `get_cve_week`, `get_github_advisory`, `get_nvd_data`,
  `get_otx_cve_details`, `search_exploit_db`, `search_for_exploits`,
  `search_packetstorm`, `get_trickest_pocs`, `verify_exploit`, `submit_cves`,
  `python_repl`, `code_execute`, `http_request`, `web_search`, `file_operations`,
  `browser_tools`.
- `config.toml` support (Pydantic model) with `.env` override via `MANUS_*` env vars.
- Docker sandbox for safe code execution (`manus-use init --sandbox`).
- Browser automation via Playwright (`manus-use init --browser`).

---

[Unreleased]: https://github.com/manus-use/manus-use/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/manus-use/manus-use/releases/tag/v0.1.0
