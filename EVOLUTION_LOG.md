
---

## 2026-06-28 UTC

**Branch:** feat/auto-20260628-0000  
**PR:** #59  
**Commit:** 10e1cd6

### Contribution: PoC Freshness Checker

Added `check_poc_freshness` Strands tool and `manus-use poc-freshness CVE-XXXX` CLI subcommand.

**Motivation:** EPSS and CVSS scores do not capture ongoing attacker investment. A CVE with a 0.3 EPSS score backed by an actively-maintained exploit framework is operationally far more dangerous. This tool surfaces that signal.

**Tool: `check_poc_freshness(cve_id, active_days=90)`**

Two-phase pipeline:
1. Discovery from trickest/cve + NVD references, deduplicated.
2. Per-repo GitHub REST API classification into 6 states:
   - `active` — commits within last active_days days (default: 90)
   - `framework` — >=5 contributors AND >=50 commits AND >=10 watchers
   - `stale` — exists but no recent activity
   - `archived` — owner archived the repo
   - `deleted` — 404 / gone
   - `non_github` — non-GitHub URLs probed for HTTP status

Active or framework repos trigger a WARNING banner.
Per-repo metadata: last_commit_date, stars, forks, contributors, commit_count.
Supports GITHUB_TOKEN / GH_TOKEN env var.

**CLI:** `manus-use poc-freshness CVE-2024-3094 [--days 30] [--output json]`

**VI Agent wiring:** check_poc_freshness added to tool list; new Step 6b in system prompt.

**Tests:** 42 new tests (100% mocked). 592 total passing (up from 550). Ruff clean.

**Suggested next contribution:** PoC quality scorer — for each active PoC repo, assess how weaponised the code is (working RCE, auth bypass, partial trigger, or demo-only) by inspecting README, code structure, and issue tracker signals. Builds on check_poc_freshness output.
