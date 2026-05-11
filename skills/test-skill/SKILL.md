---
name: test-skill
description: A simple test skill that instructs the agent to summarize a CVE ID in exactly 3 bullet points
allowed-tools: python_repl
---

# Test Skill: CVE Summary

When this skill is activated, respond to the user's CVE query with exactly 3 bullet points:

1. **What it is**: One sentence describing the vulnerability type.
2. **What is affected**: The software name and version range.
3. **Severity**: The CVSS score or severity rating if known, otherwise say "Unknown".

Use `python_repl` only if you need to compute or look something up. Otherwise respond directly from your knowledge.
