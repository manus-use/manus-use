from typing import Any, List, Dict
from strands.types.tools import ToolResult, ToolUse
import requests
import json

TOOL_SPEC = {
    "name": "submit_cves",
    "description": "Submits a list of discovered CVEs, along with their associated intelligence data, to a downstream system or webhook.",
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "cve_list": {
                    "type": "array",
                    "description": "A list of discovered vulnerabilities to submit.",
                    "items": {
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
                                "description": "This field represents the popularity and widespread use of the software or 3rd libraries affected by the CVE. Assign a value based on the following categories: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']. 'CRITICAL' indicates the affected software is a core operating system or foundational internet infrastructure (e.g., Windows, OpenSSL, Apache). 'HIGH' indicates it is a very widely-used application or library (e.g., Chrome, Log4j). 'MEDIUM' is for popular but less ubiquitous software. 'LOW' is for niche or specialized software."
                            }
                        },
                        "required": ["cve_id", "cvss_score", "epss_score", "epss_percentile", "affected_products", "cisa_kev", "exploited", "cwe", "cpe"]
                    }
                }
            },
            "required": ["cve_list"],
        }
    },
}

def submit_cves(tool: ToolUse, **kwargs: Any) -> ToolResult:
    tool_use_id = tool["toolUseId"]
    cve_list = tool["input"].get("cve_list", [])
    url = "https://webhook.site/693c24d6-518f-48b7-8af5-e71563fabd5e"
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, headers=headers, json=cve_list)
    #print("=====================")
    print(cve_list)
    if not cve_list:
        return {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": "The 'cve_list' parameter cannot be empty."}]
        }

    print(f"Submitting {len(cve_list)} CVEs to webhook...")

    url = "https://webhook.site/693c24d6-518f-48b7-8af5-e71563fabd5e"
    headers = {"Content-Type": "application/json"}

    try:
        for cve in cve_list:
            print(cve)
            response = requests.post(url, headers=headers, json=cve)
            response.raise_for_status()
        submitted_ids = [cve.get('cve_id', 'Unknown') for cve in cve_list]
        success_message = f"Successfully submitted {len(cve_list)} CVEs: {', '.join(submitted_ids)}"
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