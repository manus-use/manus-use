# GitHub Security Advisory (GHSA) Template

Use for coordinated vulnerability disclosure via GitHub's private reporting feature or direct maintainer contact.

---

## Advisory Fields

| Field | Value |
|---|---|
| **Ecosystem** | npm / PyPI / Go / Maven / RubyGems / crates.io / NuGet / etc. |
| **Package** | `package-name` |
| **Affected versions** | `< 1.2.3` |
| **Patched version** | `1.2.4` |
| **CWE** | [CWE-XXX: Name](https://cwe.mitre.org/data/definitions/XXX.html) |
| **CVSS v3.1** | [Calculator](https://www.first.org/cvss/calculator/3.1) — e.g., `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8 Critical |
| **Severity** | Critical / High / Medium / Low |

---

## Advisory Body

### Summary

[One paragraph: what is the vulnerability, what package is affected, and what can an attacker do?]

### Details

[Technical description of the vulnerable code path. Include relevant file paths and line numbers. Do NOT include working exploit code in public advisories — describe the mechanism without weaponizing it.]

**Vulnerable code (simplified):**
```language
// path/to/file.go:42
// Describe the vulnerable pattern here
```

### PoC

[Only include in private reports. Describe the steps to reproduce without a ready-to-run exploit.]

### Impact

[Who is affected? What data or systems are at risk? Under what conditions is this exploitable?]

### Patches

[Describe the fix. Link to the patch PR once merged.]

### Workarounds

[Are there any mitigations short of upgrading? Config changes, input sanitization, etc.]

### References

- [Issue tracker link]
- [Patch PR link]
- [Related CVE or advisory if any]

### Credits

[Your name / handle, if you want credit. Some reporters prefer anonymity.]

---

## Disclosure Checklist

- [ ] Identified private reporting channel (`SECURITY.md` or GitHub private reporting)
- [ ] Sent initial report with summary + PoC (private)
- [ ] Agreed on embargo date with maintainers (log in MEMORY.md)
- [ ] Patch PR ready (kept private until embargo lifts)
- [ ] GHSA drafted and shared with maintainers for review
- [ ] CVE requested (GitHub auto-requests, or via MITRE if needed)
- [ ] Public disclosure after patch release + embargo date

## Common CWEs for Reference

| CWE | Name |
|---|---|
| CWE-20 | Improper Input Validation |
| CWE-22 | Path Traversal |
| CWE-78 | OS Command Injection |
| CWE-79 | Cross-site Scripting (XSS) |
| CWE-89 | SQL Injection |
| CWE-94 | Code Injection |
| CWE-125 | Out-of-bounds Read |
| CWE-190 | Integer Overflow |
| CWE-200 | Exposure of Sensitive Information |
| CWE-287 | Improper Authentication |
| CWE-295 | Improper Certificate Validation |
| CWE-400 | Uncontrolled Resource Consumption |
| CWE-416 | Use After Free |
| CWE-502 | Deserialization of Untrusted Data |
| CWE-601 | Open Redirect |
| CWE-611 | XML External Entity (XXE) |
| CWE-918 | SSRF |
