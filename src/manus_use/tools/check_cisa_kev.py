#!/usr/bin/env python3
"""
Custom tool for checking if a CVE exists in the CISA Known Exploited Vulnerabilities (KEV) catalog.
This module follows the Strands SDK's module-based tool specification.
"""

import requests
import json
import time
from pathlib import Path
from typing import Dict, Any, List
from strands.types.tools import ToolResult, ToolUse

TOOL_SPEC = {
    "name": "check_cisa_kev",
    "description": (
        "Checks if a CVE ID is present in the CISA Known Exploited Vulnerabilities (KEV) catalog. "
        "This is a critical check to determine if a vulnerability is being actively exploited in the wild."
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "The CVE ID to check (e.g., 'CVE-2024-3094').",
                }
            },
            "required": ["cve_id"],
        }
    },
}

# --- Caching Mechanism ---
CACHE_FILE = Path(__file__).parent / ".cisa_kev_cache.json"
CACHE_DURATION = 3600  # Cache for 1 hour

def _get_kev_data() -> Dict[str, Any]:
    """Fetches KEV data from CISA, with caching."""
    if CACHE_FILE.exists():
        cached_data = json.loads(CACHE_FILE.read_text())
        if time.time() - cached_data.get("timestamp", 0) < CACHE_DURATION:
            return cached_data.get("data", {})

    try:
        response = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=15)
        response.raise_for_status()
        data = response.json()
        
        # Save to cache
        CACHE_FILE.write_text(json.dumps({"timestamp": time.time(), "data": data}))
        return data
    except requests.exceptions.RequestException as e:
        print(f"Error fetching CISA KEV data: {e}")
        return {}

def check_cisa_kev(tool: ToolUse, **kwargs: Any) -> ToolResult:
    tool_use_id = tool["toolUseId"]
    tool_input = tool["input"]
    cve_id = tool_input.get("cve_id")

    if not isinstance(cve_id, str) or not cve_id.strip():
        return {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": "Invalid CVE ID. Must be a non-empty string."}]
        }

    kev_data = _get_kev_data()
    if not kev_data or "vulnerabilities" not in kev_data:
        return {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": "Could not retrieve or parse CISA KEV data."}]
        }

    found = False
    vulnerability_details = {}
    for vuln in kev_data.get("vulnerabilities", []):
        if vuln.get("cveID") == cve_id.upper():
            found = True
            vulnerability_details = vuln
            break

    if found:
        summary = f"CRITICAL FINDING: {cve_id} is listed in the CISA KEV catalog, indicating active exploitation."
        return {
            "toolUseId": tool_use_id,
            "status": "success",
            "content": [{"json": {"summary": summary, "exploited": True, "details": vulnerability_details}}]
        }
    else:
        summary = f"{cve_id} was not found in the CISA KEV catalog."
        return {
            "toolUseId": tool_use_id,
            "status": "success",
            "content": [{"json": {"summary": summary, "exploited": False}}]
        }
