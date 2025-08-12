from typing import Any, List, Dict
from strands.types.tools import ToolResult, ToolUse
import requests
import json

TOOL_SPEC = {
    "name": "submit_cves",
    "description": "Submits a discovered CVE, along with its associated intelligence data, to a downstream system or webhook.",
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "The unique identifier for the vulnerability (e.g., 'CVE-2025-12345')."
                },
                "cvss_score": {
                    "type": "string",
                    "description": "The CVSS score and vector, formatted as 'Severity(Score),Vector' (e.g., 'Critical(9.8),CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')."
                },
                "cisa_kev": {
                    "type": "boolean",
                    "description": "Indicates if the vulnerability is in the CISA Known Exploited Vulnerabilities (KEV) catalog."
                },
                "exploited": {
                    "type": "boolean",
                    "description": "Indicates if the vulnerability is exploited in the wild, based on OTX or other threat intelligence."
                },
                "epss_score": {
                    "type": "string",
                    "description": "The Exploit Prediction Scoring System (EPSS) score (e.g., 0.94577)."
                },
                "epss_percentile": {
                    "type": "string",
                    "description": "The EPSS percentile (e.g., 0.999)."
                },
                "affected_products": {
                    "type": "string",
                    "description": "A single, comma-separated string listing the products including vendors, packages, or components confirmed to be affected by the CVE."
                },
                "affected_versions": {
                    "type": "string",
                    "description": "A single string containing a comma-separated list of affected product versions."
                },
                "cwe": {
                    "type": "string",
                    "description": "The Common Weakness Enumeration (CWE) identifier (e.g., 'CWE-79')."
                },
                "public_disclosure_date": {
                    "type": "string",
                    "description": "The date when the vulnerability was publicly disclosed (YYYY-MM-DD)."
                },
                "description": {
                    "type": "string",
                    "description": "The description of the CVE",
                },
                "priority": {
                    "type": "string",
                    "description": """Indicates the popularity and usage level of the affected software, including any third-party libraries or dependencies. Accepted values: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].
                    - 'CRITICAL': CVE affects core operating systems, foundational internet infrastructure, or extremely common libraries (e.g., Windows, OpenSSL, Apache).
                    - 'HIGH': CVE affects widely used applications, libraries, or components (e.g., Chrome, Log4j, jQuery).
                    - 'MEDIUM': CVE affects moderately popular software or libraries, but not universally adopted.
                    - 'LOW': CVE affects niche, specialized, or rarely used software or components.
                    Always consider both the primary software and any included third-party dependencies when assigning this value."""
                }
            },
            "required": ["cve_id", "priority", "cvss_score", "epss_score", "epss_percentile", "affected_products", "cisa_kev", "exploited", "cwe", "cpe"]
        }
    },
}

def submit_cves(tool: ToolUse, **kwargs: Any) -> ToolResult:
    tool_use_id = tool["toolUseId"]
    cve = tool["input"]
    print("============================")
    print(cve)
    if not cve:
        return {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": "The 'cve' parameter cannot be empty."}]
        }
    
    print(f"Submitting {cve.get("cve_id","NA")} to webhook...")
    
    """ First webhook (webhook.site) - with timeout
    try:
        url1 = "https://webhook.site/693c24d6-518f-48b7-8af5-e71563fabd5e"
        headers = {"Content-Type": "application/json"}
        response = requests.post(url1, headers=headers, json=cve, timeout=10)
        print(f"Webhook.site response: {response.status_code}")
    except Exception as e:
        print(f"Warning: webhook.site failed: {e}")
    """
    # Main webhook (Lark)
    url = "https://webhook.site/693c24d6-518f-48b7-8af5-e71563fabd5e"
    headers = {"Content-Type": "application/json"}

    try:
        print(f"Submitting CVE: {cve.get("cve_id","NA")}")
        response = requests.post(url, headers=headers, json=cve, timeout=30)
        response.raise_for_status()
        success_message = f"Successfully submitted {cve.get("cve_id","NA")}"
        print(success_message)
        
        return {
            "toolUseId": tool_use_id,
            "status": "success",
            "content": [{"text": success_message}]
        }
    except requests.exceptions.HTTPError as http_err:
        error_message = f"HTTP error occurred while submitting CVEs: {http_err}"
        print(error_message)
        return {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": error_message}]
        }
    except Exception as err:
        error_message = f"An unexpected error occurred: {err}"
        print(error_message)
        return {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": error_message}]
        }