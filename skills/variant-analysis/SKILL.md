---
name: variant-analysis
description: >
  Perform variant analysis and vulnerability hunting on open-source projects using Claude Code.
  Activate when user asks to: analyze a CVE/GHSA for variants, hunt for new vulnerabilities in a codebase,
  find similar bugs to a known vulnerability, do security research on a GitHub project,
  write PoCs for discovered vulnerabilities, or prepare security advisory reports for responsible disclosure.
  Covers: CVE variant analysis, broad vulnerability hunting (SSRF, SQLi, command injection, auth bypass, etc.),
  PoC development, report generation, and GitHub Security Advisory submission.
---

# Variant Analysis & Vulnerability Hunting

Security research workflow using Claude Code (Opus) for deep codebase analysis.

## Prerequisites

- **Claude Code** installed and configured (`claude` CLI)
- **Bedrock access** with Opus 4.6 (`us.anthropic.claude-opus-4-6-v1`) — ALWAYS use Opus for variant analysis
- **gh CLI** authenticated for advisory submission
- **Docker** for live PoC testing (optional)

## Approval Gate (MANDATORY)

**NEVER submit GHSAs, open PRs, or take any public-facing action without explicit user approval.**

You MAY do autonomously:
- Clone repos, read code, explore codebases
- Run variant analysis / vulnerability hunting
- Write PoCs and reports locally
- Run local tests and validation

You MUST wait for approval before:
- Submitting any GHSA / private vulnerability report
- Opening any GitHub issue
- Any public-facing action on GitHub

Present findings first → get approval → then execute.

## Workflow Overview

### Phase 1: Setup & Clone

```bash
mkdir -p /tmp/<project>-analysis && cd /tmp/<project>-analysis && git init
git clone --depth=500 https://github.com/<org>/<project>.git
```

If analyzing a specific CVE, fetch the research writeup and save locally — Claude Code may not have network access:

```bash
# Save research/advisory details to a local file
write research.md  # with CVE details, root cause, affected versions, fix commits
```

### Phase 2: Variant Analysis (for a known CVE)

**Always use Claude Code with Opus for variant analysis.** Opus is significantly better at:
- Holding large codebases in context while tracing patterns
- Catching subtle auth bypass variants that Sonnet misses
- Following complex call chains across multiple files

Do NOT use `sessions_spawn` subagents for this phase — they use Sonnet by default and lack the depth needed.

Launch Claude Code:

```bash
claude --model us.anthropic.claude-opus-4-6-v1 \
  --permission-mode bypassPermissions --print \
  -p "<prompt>"
```

**Key prompt elements:**
1. Point to the local repo and research file
2. Instruct to read fix commits: `git show <commit_hash>`
3. Define variant patterns to search for (similar to the root cause)
4. Request **incremental writing** to a report file (critical — prevents losing work on timeout)
5. Explicitly state: "Do NOT attempt any network operations"

See `references/variant-analysis-prompt.md` for a full prompt template.

### Phase 3: Broad Vulnerability Hunting

Also use **Opus** for broad hunting. Same command pattern as Phase 2.
See `references/vuln-hunting-prompt.md` for the full prompt covering:

- SSRF, SQL Injection, Command Injection
- Auth/Authz bypass, Credential exposure
- Path traversal, Prototype pollution
- DoS (ReDoS, decompression bombs)
- Privilege escalation, Webhook security

### Phase 4: PoC Development & Verification

PoC writing can use **Sonnet 4.6** (cheaper, fast enough for focused tasks with clear scope):

```bash
claude --model us.anthropic.claude-sonnet-4-6 \
  --permission-mode bypassPermissions --print \
  --allowedTools "Bash(*),Read,Write" \
  -p "<prompt referencing findings.md>"
```

#### Required Deliverables (MANDATORY for each finding)

**1. Standalone PoC script** (`pocs/VH-XX-poc.py`):
- Self-contained Python script (minimal dependencies: `requests`, `websockets`, `argparse`)
- `--target URL` flag (e.g. `http://localhost:7860`)
- `--check-only` flag (validates vuln exists without destructive action)
- Clear success/fail output with explanation
- Comments explaining each step
- Handles auth (token/cookie) via `--token` or `--username`/`--password` flags

**2. Step-by-step reproduction instructions** (in each `reports/VH-XX-title.md`):
- Prerequisites (target version, Docker image, config)
- Setup steps (how to get a running instance)
- Manual reproduction steps (curl/websocket commands)
- Expected vs actual behavior
- Screenshot/output examples where helpful

**3. Optional: Live verification** against a running instance:
- Spin up target in Docker if feasible
- Run PoC with `--check-only`
- Document results
- This step is optional — skip if no Docker image available or setup is too complex

#### Output structure:
```
reports/VH-XX-title.md     # GHSA format + repro steps
pocs/VH-XX-poc.py          # Standalone exploit script
summary.md                 # Overview of all findings
```

See `references/report-template.md` for the advisory format.

### Phase 5: Review & Validation

**Code review** — Launch Claude Code to verify every file:line reference against actual source:

```bash
claude -p "Read each report in ./reports/ and verify every code reference against ./project/ source..."
```

**Live testing** — Spin up the target in Docker and run PoCs:

```bash
docker run -d --name test-instance -p <port>:<port> <image>
python3 pocs/VH-XX-poc.py --target http://localhost:<port> --check-only
```

### Phase 6: Responsible Disclosure

**⚠️ CRITICAL: Verify the real latest released version before submitting.**

The version in `vulnerable_version_range` must be an actual published release — NOT a git tag from main, NOT a guessed future version.

```bash
# For npm packages:
curl -s https://registry.npmjs.org/<package>/latest | jq -r '.version'

# For PyPI packages:
curl -s https://pypi.org/pypi/<package>/json | jq -r '.info.version'

# Cross-check: what did you actually analyze?
cd /path/to/cloned/repo && git describe --tags
# If this shows e.g. "v2.9.0-121-gabcdef", that's UNRELEASED.
# Use the latest published version instead (e.g. "<=2.8.3").
```

The git tag in the repo may be ahead of what's actually published to package registries. Always use the registry as the source of truth.

Submit via GitHub Security Advisory API:

```python
# Python script pattern for batch submission
import json, subprocess
payload = json.dumps({
    "summary": "...",
    "description": report_content,
    "severity": "high",
    "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "..."}, "vulnerable_version_range": "<= X.Y.Z"}],
    "cwe_ids": ["CWE-XXX"]
})
subprocess.run(["gh", "api", "--method", "POST",
    "/repos/<org>/<repo>/security-advisories/reports",
    "--input", "-"], input=payload, text=True)
```

Check the project's `SECURITY.md` first — some projects prefer email or dedicated programs.

**If private vulnerability reporting is not enabled**, open a lightweight GitHub issue asking the maintainer to enable it (Settings → Security → Code security → Private vulnerability reporting). Do NOT include vulnerability details or CVE references in the issue.

### Phase 7: Archive to Private Repo

After submission, push all reports, PoCs, variant analyses, and review files to a private GitHub repo for record-keeping:

```bash
# Clone the repo (already created)
git clone https://github.com/manusjs/vulnerability-reports.git /tmp/vuln-reports-repo

# Organize by project
mkdir -p /tmp/vuln-reports-repo/<project>/{reports,pocs}
cp reports/*.md /tmp/vuln-reports-repo/<project>/reports/
cp pocs/*.py /tmp/vuln-reports-repo/<project>/pocs/
cp variant-analysis-report.md /tmp/vuln-reports-repo/<project>/
cp final-review.md /tmp/vuln-reports-repo/<project>/

# Push
cd /tmp/vuln-reports-repo
git add -A && git commit -m "Add <project> vulnerability reports" && git push
```

**Archive repo:** https://github.com/manusjs/vulnerability-reports (private)

Update `README.md` with a summary table of all advisories (GHSA IDs, severity, status).

### Best Practices for Advisory Content

- **Do NOT reference known CVEs** in advisory titles or descriptions — this tips off attackers about what to look for
- **Do NOT mention "incomplete fix"** — describe the vulnerability independently
- **DO include full PoC code** in a `<details>` section within the report — maintainers need everything in one place
- **DO verify CVSS math** with a separate Claude Code review pass before submission
- **DO credit consistently**: "Reported by **zx (Jace)**" (or your chosen credit line)

## Common Pitfalls

1. **Claude Code timeout without output** — Always instruct "write findings INCREMENTALLY, do NOT wait until the end"
2. **PTY output not captured** — Use `-p` (print mode) for one-shot tasks; check for report files rather than relying on terminal output
3. **Network blocked in sandbox** — Clone repos and save research locally BEFORE launching Claude Code
4. **CVSS score/vector mismatch** — Always verify the math; use an online CVSS calculator
5. **False positives** — Always verify code references against actual source before submitting
6. **Model marketplace access** — Check `aws bedrock list-inference-profiles` for available models; use cross-region prefix (`us.anthropic.claude-*`)
7. **Submitting with nonexistent versions** — Always check the package registry (npm/PyPI) for the real latest version. Git tags on main may be ahead of published releases. Submitting `<=2.9.0` when latest is `2.8.3` looks sloppy and undermines credibility.
