# Variant Analysis Prompt Template

Use this template when analyzing a specific CVE for variants in the same codebase.

## Template

```
You are a vulnerability researcher performing variant analysis on {CVE_ID} ({GHSA_ID}) in {PROJECT}.

The {PROJECT} repo is at ./{PROJECT}/
The vulnerability details are in ./research.md

## Your Task

1. Read research.md for context on the original vulnerability
2. Examine the fix commit(s):
   - git -C ./{PROJECT} show {COMMIT_HASH}
3. Understand the root cause deeply — what was the vulnerability pattern?
4. VARIANT ANALYSIS — search the entire codebase for:
   a. {PATTERN_1} (e.g., "Other webhook endpoints with similar file access issues")
   b. {PATTERN_2} (e.g., "Other unauthenticated endpoints that could be abused")
   c. {PATTERN_3} (e.g., "Similar improper input validation")
   d. {PATTERN_4} (e.g., "Path traversal or file inclusion patterns")
   e. {PATTERN_5} (e.g., "Code execution sinks reachable from unauthenticated inputs")
5. For each potential variant found, document:
   - Location in code (file + line)
   - Description of the issue
   - Potential impact
   - Whether it appears to be exploitable
6. Write a detailed report to variant-analysis-report.md

IMPORTANT: Write findings INCREMENTALLY as you discover them. Do NOT wait until the end.
Work entirely from the local ./{PROJECT}/ directory. Do NOT attempt any network operations.
```

## Tips

- Tailor patterns (a-e) to match the root cause class of the original CVE
- For content-type confusion bugs: search for file handling without content-type guards
- For sandbox escapes: search for eval/Function/vm usage, prototype chains, unproxied constructors
- For SSRF: search for axios/fetch/http.request with user-controlled URLs
- For auth bypass: check middleware ordering, missing auth decorators, endpoints registered outside the auth pipeline
