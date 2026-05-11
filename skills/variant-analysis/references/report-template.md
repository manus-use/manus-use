# Security Advisory Report Template

Format for GitHub Security Advisory submission.

## Template

```markdown
# {Vulnerability Title}

## Summary
{One paragraph describing the vulnerability.}

## Severity
**CVSS v3.1: {score} ({High/Medium/Low})**
Vector: `{CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...}`

**Justification:** {Explain each CVSS metric choice.}

## Affected Versions
- {project} <= {version}
- Introduced in: {commit/version} ({date})

## Description

### Root Cause
{What is fundamentally wrong in the code.}

### Affected Code Path
**`{file}:{lines}`**
```{language}
{vulnerable code snippet}
```

### Data Flow
1. {User input entry point}
2. {How it reaches the vulnerable sink}
3. {What happens — the exploit}

## Proof of Concept

### Prerequisites
- {Project version}
- {Required user role/permissions}
- {Any setup needed}

### Steps to Reproduce
1. {Step with exact curl/API command}
2. {Step}
3. {Observe: what happens}

### Expected vs Actual Behavior
- **Expected:** {What should happen}
- **Actual:** {What does happen}

## Impact
{What can an attacker achieve? Be specific: data access, actions, blast radius.}

## Suggested Fix
```{language}
{Code diff or description of the fix}
```

## References
- **CWE:** CWE-{number} ({name})
- **Vulnerable code:** `{file}:{lines}`
- **Similar CVEs:** {if any}

---

**Reported by:** {researcher name}
```

## PoC Script Pattern

```python
#!/usr/bin/env python3
"""
{VH-XX}: {Title} PoC
Target: {project} <= {version}
CWE: CWE-{number}

Usage:
    python3 poc.py --target http://localhost:PORT --check-only
    python3 poc.py --target http://localhost:PORT --email user@test.com --password pass
"""
import argparse, requests, sys

def main():
    parser = argparse.ArgumentParser(description="{Title} PoC")
    parser.add_argument("--target", default="http://localhost:5678")
    parser.add_argument("--email", help="Auth email")
    parser.add_argument("--password", help="Auth password")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()

    if args.check_only:
        # Safe check — just verify endpoint exists
        ...
        sys.exit(0)

    # Full exploitation
    ...

if __name__ == "__main__":
    main()
```

## Submission Checklist

- [ ] Every file:line reference verified against actual source code
- [ ] CVSS score matches the vector string (use calculator)
- [ ] PoC tested against live instance
- [ ] No false positives — vulnerability confirmed exploitable
- [ ] Report includes "Reported by" credit line
- [ ] One advisory per vulnerability (don't bundle)
