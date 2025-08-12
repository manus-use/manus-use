#!/usr/bin/env python3
"""
Custom tool for fetching detailed CWE (Common Weakness Enumeration) information.
This module follows the Strands SDK's module-based tool specification.
"""

import requests
import json
from typing import Dict, Any
from strands.types.tools import ToolResult, ToolUse

TOOL_SPEC = {
    "name": "get_cwe_details",
    "description": (
        "Fetches detailed information about a Common Weakness Enumeration (CWE) ID from the "
        "MITRE CWE website. Provides context on the nature of the vulnerability, its description, "
        "and potential mitigations. This tool is crucial for understanding the underlying "
        "weakness type of a CVE."
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "cwe_id": {
                    "type": "string",
                    "description": "The CWE identifier to look up (e.g., 'CWE-79').",
                }
            },
            "required": ["cwe_id"],
        }
    },
}

def get_cwe_details(tool: ToolUse, **kwargs: Any) -> ToolResult:
    tool_use_id = tool["toolUseId"]
    tool_input = tool["input"]
    cwe_id = tool_input.get("cwe_id")

    if not isinstance(cwe_id, str) or not cwe_id.upper().startswith("CWE-"):
        return {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": "Invalid CWE ID format. Must be a string like 'CWE-NNN'."}],
        }

    # Extract just the number from CWE-NNN
    cwe_number = cwe_id.upper().replace("CWE-", "")
    if not cwe_number.isdigit():
        return {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": "Invalid CWE ID format. Number part is missing or invalid."}]
        }

    url = f"https://cwe.mitre.org/data/definitions/{cwe_number}.html"

    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()  # Raise an exception for bad status codes

        html_content = response.text

        # Basic parsing to extract the description. This is fragile and relies on HTML structure.
        # A more robust solution would use BeautifulSoup or a similar library.
        description_start_marker = '<div id="Description">'
        description_end_marker = '<div id="Extended_Description">'

        start_index = html_content.find(description_start_marker)
        if start_index == -1:
            return {"toolUseId": tool_use_id, "status": "error", "content": [{"text": f"Could not find description for {cwe_id} on the page."}]}

        # Adjust start_index to point to the content after the marker
        start_index += len(description_start_marker)

        end_index = html_content.find(description_end_marker, start_index)
        if end_index == -1:
            # Fallback if Extended_Description is not present, try to find the next div
            end_index = html_content.find('<div id=', start_index)
            if end_index == -1:
                end_index = len(html_content) # Read to end if no other div found

        raw_description = html_content[start_index:end_index].strip()

        # Simple HTML tag stripping (very basic)
        clean_description = raw_description.replace('<p>', '').replace('</p>', '').replace('<ul>', '').replace('</ul>', '').replace('<li>', '').replace('</li>', '').replace('<br>', '').replace('<br/>', '').strip()

        return {
            "toolUseId": tool_use_id,
            "status": "success",
            "content": [{"json": {
                "cwe_id": cwe_id,
                "description": clean_description,
                "url": url
            }}]
        }

    except requests.exceptions.RequestException as e:
        return {"toolUseId": tool_use_id, "status": "error", "content": [{"text": f"Request to CWE website failed: {e}"}]}
    except Exception as e:
        return {"toolUseId": tool_use_id, "status": "error", "content": [{"text": f"An unexpected error occurred during CWE details fetching: {e}"}]}