#!/usr/bin/env python3
"""
Custom tool for fetching detailed NVD data for CVEs.
This module follows the Strands SDK's module-based tool specification.
"""

import requests
import json
from typing import Dict, Any
from strands.types.tools import ToolResult, ToolUse

TOOL_SPEC = { # Minor change to force re-evaluation
    "name": "get_nvd_data",
    "description": (
        "Fetches detailed, authoritative vulnerability data for a given CVE ID directly from the "
        "official National Vulnerability Database (NVD) API. This should be the primary and first tool used "
        "to gather information about a CVE. The output will also indicate if the CVE is in the CISA Known "
        "Exploited Vulnerabilities (KEV) Catalog."
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "The CVE identifier to look up (e.g., 'CVE-2024-3094').",
                }
            },
            "required": ["cve_id"],
        }
    },
}

def get_nvd_data(tool: ToolUse, **kwargs: Any) -> ToolResult:
    tool_use_id = tool["toolUseId"]
    tool_input = tool["input"]
    cve_id = tool_input.get("cve_id")

    if not isinstance(cve_id, str) or not cve_id.upper().startswith("CVE-"):
        return {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": "Invalid CVE ID format. Must be a string like 'CVE-YYYY-NNNN'."}],
        }

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    url = f"{base_url}?cveId={cve_id.upper()}"

    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()

        if not data.get("vulnerabilities"):
            return {
                "toolUseId": tool_use_id,
                "status": "error",
                "content": [{"text": f"No vulnerability data found for {cve_id}. It may be an invalid or rejected CVE."}]
            }

        vulnerability_data = data["vulnerabilities"][0]

        # Extract CISA KEV information if available
        cisa_kev_info = {"is_in_kev": False}
        if "cisaExploitAdd" in vulnerability_data.get("cve", {}).get("vulnStatus", ""):
            cisa_kev_info["is_in_kev"] = True
            cisa_kev_info["date_added"] = vulnerability_data["cve"]["cisaExploitAdd"]
            cisa_kev_info["required_action"] = vulnerability_data["cve"]["cisaRequiredAction"]
            cisa_kev_info["due_date"] = vulnerability_data["cve"]["cisaActionDue"]
            # Add other relevant CISA fields if they exist and are needed

        # Add CISA KEV info to the main vulnerability data
        vulnerability_data["cisa_kev_info"] = cisa_kev_info

        return {
            "toolUseId": tool_use_id,
            "status": "success",
            "content": [{"json": vulnerability_data}]
        }

    except requests.exceptions.RequestException as e:
        return {"toolUseId": tool_use_id, "status": "error", "content": [{"text": f"Request to NVD API failed: {e}"}]}
    except json.JSONDecodeError:
        return {"toolUseId": tool_use_id, "status": "error", "content": [{"text": "Failed to parse JSON response from NVD API."}]}
    except Exception as e:
        return {"toolUseId": tool_use_id, "status": "error", "content": [{"text": f"An unexpected error occurred: {e}"}]}