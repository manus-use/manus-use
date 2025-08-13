# Ivanti EPMM Vulnerabilities: CVE-2025-4427 & CVE-2025-4428

## Executive Summary

This report details two critical vulnerabilities discovered in Ivanti Endpoint Manager Mobile (EPMM) that, when chained together, allow for unauthenticated remote code execution. These vulnerabilities represent a significant security risk for organizations using affected versions of Ivanti EPMM.

| Vulnerability | Type | Severity | CVSS | CWE |
|--------------|------|----------|------|-----|
| CVE-2025-4427 | Authentication Bypass | Critical | 5.3 | CWE-288 |
| CVE-2025-4428 | Remote Code Execution | Critical | N/A | CWE-94 |

## Vulnerability Details

### CVE-2025-4427: Authentication Bypass

**Description:**  
An authentication bypass vulnerability in Ivanti Endpoint Manager Mobile allowing attackers to access protected resources without proper credentials. This vulnerability enables attackers to bypass authentication mechanisms and gain unauthorized access to the application.

**Technical Details:**  
The vulnerability exists in the authentication mechanism of Ivanti EPMM. When exploited, it allows attackers to bypass authentication checks and access protected resources that should only be available to authenticated users. This serves as the initial entry point in the exploit chain.

**Affected Systems:**  
Ivanti Endpoint Manager Mobile (EPMM)

**Severity:** Critical  
**CVSS Score:** 5.3  
**CWE:** CWE-288 (Authentication Bypass)

### CVE-2025-4428: Remote Code Execution

**Description:**  
A remote code execution vulnerability in Ivanti Endpoint Manager Mobile due to unsafe user input handling in bean validators, leading to Server-Side Template Injection (SSTI).

**Technical Details:**  
The vulnerability stems from improper validation of user input in one of the bean validators, which becomes a sink for Server-Side Template Injection. After bypassing authentication using CVE-2025-4427, attackers can exploit this vulnerability to inject and execute arbitrary code on the affected system.

**Affected Systems:**  
Ivanti Endpoint Manager Mobile (EPMM)

**Severity:** Critical  
**CVSS Score:** Not specified  
**CWE:** CWE-94 (Improper Control of Generation of Code)

## Exploit Chain

These vulnerabilities are particularly dangerous when used together in a chain attack:

1. **Step 1:** Exploit CVE-2025-4427 to bypass authentication and gain unauthorized access to the application
2. **Step 2:** Leverage CVE-2025-4428 to inject and execute arbitrary code via Server-Side Template Injection

This chain allows attackers to achieve unauthenticated remote code execution on affected Ivanti EPMM instances, potentially leading to complete system compromise.

## Proof of Concept (PoC)

### Available PoC Repositories

#### 1. watchTowr Labs Repository

**Repository:** [watchTowr-vs-Ivanti-EPMM-CVE-2025-4427-CVE-2025-4428](https://github.com/watchtowrlabs/watchTowr-vs-Ivanti-EPMM-CVE-2025-4427-CVE-2025-4428)

**Description:**  
This repository contains a detection tool called 'watchTowr-vs-Ivanti-EPMM-rce-chain.py' that can identify if an Ivanti EPMM instance is vulnerable to the pre-auth RCE chain combining both CVEs.

**Features:**
- Vulnerability detection for the CVE-2025-4427 and CVE-2025-4428 chain
- Command-line interface for easy usage
- Detailed output with vulnerability status

**Usage Example:**
```bash
$ python3 watchTowr-vs-Ivanti-EPMM-CVE-2025-4427-CVE-2025-4428.py -H https://192.168.1.100
```

**Authors:** Sonny and Piotr from watchTowr Labs

#### 2. xie-22 Repository

**Repository:** [CVE-2025-4428](https://github.com/xie-22/CVE-2025-4428)

**Description:**  
This repository contains more comprehensive exploitation tools for the Ivanti EPMM vulnerabilities, including both detection and proof-of-concept exploitation code.

**Files:**
- `CVE-2025-4427.yaml` - Details the authentication bypass vulnerability
- `CVE-2025-4428.py` - Contains the exploitation code for the RCE vulnerability
- `README.md` - Comprehensive documentation

**Features:**
- Vulnerability detection
- Command execution testing
- Retry mechanism
- Logging capabilities
- Proxy support
- Multi-shell support
- Output redirection

**Author:** xie-22

## Mitigation Recommendations

1. **Update Systems:**
   - Apply the latest security patches provided by Ivanti as soon as they become available

2. **Network Segmentation:**
   - Isolate Ivanti EPMM instances from the public internet
   - Implement strict network access controls

3. **Monitoring:**
   - Monitor systems for suspicious activities that might indicate exploitation attempts
   - Implement intrusion detection systems to identify potential attacks

4. **Authentication Controls:**
   - Implement additional authentication mechanisms where possible
   - Use multi-factor authentication for administrative access

5. **Web Application Firewall:**
   - Deploy a WAF to help block exploitation attempts
   - Configure rules to detect and block template injection attacks

## Detection Methods

Security teams can use the following methods to detect potential exploitation:

1. **Network Traffic Analysis:**
   - Monitor for unusual HTTP requests to Ivanti EPMM instances
   - Look for suspicious patterns in request parameters that might indicate template injection attempts

2. **Log Analysis:**
   - Review authentication logs for anomalies
   - Monitor for unexpected command executions or process spawns

3. **Utilize Available PoC Tools:**
   - Use the detection tools from the PoC repositories in a controlled environment to identify vulnerable systems

4. **Endpoint Monitoring:**
   - Monitor for unexpected file system changes or process executions on Ivanti EPMM servers

## Conclusion

The combination of CVE-2025-4427 and CVE-2025-4428 represents a critical security risk for organizations using Ivanti Endpoint Manager Mobile. The authentication bypass vulnerability (CVE-2025-4427) provides the initial access, while the code injection vulnerability (CVE-2025-4428) enables remote code execution. Organizations should prioritize patching these vulnerabilities and implementing the recommended mitigations to protect their systems.

## References

1. [watchTowr Labs PoC Repository](https://github.com/watchtowrlabs/watchTowr-vs-Ivanti-EPMM-CVE-2025-4427-CVE-2025-4428)
2. [xie-22 PoC Repository](https://github.com/xie-22/CVE-2025-4428)
3. [CVE-2025-4427 MITRE Entry](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-4427)
4. [CVE-2025-4428 MITRE Entry](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-4428)