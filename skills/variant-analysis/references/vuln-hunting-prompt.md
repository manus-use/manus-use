# Vulnerability Hunting Prompt Template

Use this template for broad vulnerability hunting across a codebase (not variant analysis of a known CVE).

## Template

```
You are a security researcher hunting for NEW, unreported vulnerabilities in {PROJECT}.
The repo is at ./{PROJECT}/

IMPORTANT: Write findings to vulnhunt-report.md INCREMENTALLY as you discover them.

{KNOWN_CVES_SECTION}

## Hunt for NEW vulnerabilities in these areas:

### 1. SSRF (Server-Side Request Forgery)
- Search: rg -l 'axios|fetch|http\.request|got\(' in packages/
- URL validation bypasses (DNS rebinding, IPv6, parser differentials)
- Internal IP access (169.254.169.254, localhost, 10.x, 172.16.x, 192.168.x)

### 2. SQL Injection
- Search: rg 'query\(|createQueryBuilder|Raw\(' in packages/
- Raw queries with string interpolation
- ORDER BY / column name injection

### 3. Command Injection
- Search: rg 'exec\(|execSync|spawn\(|spawnSync|execFile' in packages/
- Argument injection (strings starting with -)
- Shell metacharacter injection

### 4. Authentication/Authorization Bypass
- Middleware ordering issues
- Endpoints missing auth middleware
- RBAC implementation flaws

### 5. Credential Exposure
- Credential storage and encryption
- Redaction bypass in API responses
- Leaks in logs or error messages

### 6. Path Traversal
- File upload/download operations
- Binary data handling
- Search: rg 'readFile|writeFile|createReadStream|path\.join' in packages/

### 7. Prototype Pollution
- Search: rg 'JSON\.parse|Object\.assign|\.merge\(|deepCopy' in packages/
- lodash set/merge with user-controlled paths

### 8. Denial of Service
- ReDoS in user-supplied regex
- Decompression bombs
- Unbounded resource consumption

### 9. Privilege Escalation
- Role/permission model flaws
- Mass assignment via Object.assign/spread

### 10. Webhook/API Security
- Enumerable/brute-forceable identifiers
- Missing CSRF protections
- Timing side-channels in auth comparisons

For EACH finding: exact file + line, code snippet, attack scenario, severity, auth requirement.
Do NOT attempt any network operations.
```

## Customization

- Remove categories not relevant to the target project
- Add project-specific categories (e.g., "Expression evaluation" for template engines)
- Adjust search patterns for the project's language/framework
