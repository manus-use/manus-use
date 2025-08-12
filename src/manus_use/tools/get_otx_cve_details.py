#!/usr/bin/env python3
"""
Custom tool for fetching threat intelligence data from AlienVault OTX.
This module follows the Strands SDK's module-based tool specification.
"""

import os
import requests
import json
from typing import Dict, Any
from strands.types.tools import ToolResult, ToolUse

from manus_use.config import Config

TOOL_SPEC = {
    "name": "get_otx_cve_details",
    "description": (
        "Fetches threat intelligence data for a given CVE ID from AlienVault OTX (Open Threat Exchange). "
        "This tool provides context on how a vulnerability is being used in the wild, including associated pulses, "
        "Indicators of Compromise (IoCs), and related threat actors."
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

def get_otx_cve_details(tool: ToolUse, **kwargs: Any) -> ToolResult:
    """
    Searches AlienVault OTX for information about a given CVE ID.
    """
    tool_use_id = tool["toolUseId"]
    tool_input = tool["input"]
    cve_id = tool_input.get("cve_id")

    if not isinstance(cve_id, str) or not cve_id.upper().startswith("CVE-"):
        return {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": "Invalid CVE ID format. Must be a string like 'CVE-YYYY-NNNN'."}],
        }

    try:
        config = Config.from_file()
        api_key = os.environ.get("OTX_API_KEY") or (config.otx.api_key if config.otx else None)
    except Exception:
        api_key = os.environ.get("OTX_API_KEY")

    if not api_key:
        return {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": "AlienVault OTX API key not found. Please set it in your config.toml or as an OTX_API_KEY environment variable."}]
        }

    headers = {"X-OTX-API-KEY": api_key}
    url = f"https://otx.alienvault.com/api/v1/indicators/cve/{cve_id.upper()}"

    try:
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()
        print("8888888888: " + response.text)
        data = response.json()

        if not data or not data.get("pulse_info", {}).get("pulses"):
            return {
                "toolUseId": tool_use_id,
                "status": "success",
                "content": [{"text": f"No specific threat intelligence pulses found for {cve_id} in AlienVault OTX. This may indicate it is not currently part of a major tracked campaign."}]
            }

        return {
            "toolUseId": tool_use_id,
            "status": "success",
            "content": [{"json": data}]
        }

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return {
                "toolUseId": tool_use_id,
                "status": "success",
                "content": [{"text": f"No information found for {cve_id} in AlienVault OTX."}]
            }
        return {"toolUseId": tool_use_id, "status": "error", "content": [{"text": f"Request to AlienVault OTX API failed with HTTP error: {e}"}]}
    except requests.exceptions.RequestException as e:
        return {"toolUseId": tool_use_id, "status": "error", "content": [{"text": f"Request to AlienVault OTX API failed: {e}"}]}
    except json.JSONDecodeError:
        return {"toolUseId": tool_use_id, "status": "error", "content": [{"text": "Failed to parse JSON response from AlienVault OTX API."}]}
    except Exception as e:
        return {"toolUseId": tool_use_id, "status": "error", "content": [{"text": f"An unexpected error occurred: {e}"}]}
