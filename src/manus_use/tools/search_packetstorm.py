#!/usr/bin/env python3
"""
Custom tool for searching Packet Storm Security for exploits.
This module follows the Strands SDK's module-based tool specification.
"""

import requests
from typing import Dict, Any, List
from strands.types.tools import ToolResult, ToolUse

TOOL_SPEC = {
    "name": "search_packetstorm",
    "description": (
        "Searches the Packet Storm Security database for public exploits related to a given CVE ID or general keyword. "
        "This tool is useful for finding exploits that may not be available on other platforms."
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The CVE ID (e.g., 'CVE-2024-3094') or general keyword to search for exploits.",
                }
            },
            "required": ["query"],
        }
    },
}

def search_packetstorm(tool: ToolUse, **kwargs: Any) -> ToolResult:
    tool_use_id = tool["toolUseId"]
    tool_input = tool["input"]
    query = tool_input.get("query")

    if not isinstance(query, str) or not query.strip():
        return {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": "Invalid query. Must be a non-empty string."}]
        }

    base_url = "https://packetstormsecurity.com/search/files/"
    url = f"{base_url}?q={requests.utils.quote(query)}"

    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()

        html_content = response.text
        results: List[Dict[str, Any]] = []

        # Basic parsing to find exploit links
        exploit_entries = html_content.split('<dl class="file">')
        
        for entry in exploit_entries[1:]:
            title_start = entry.find('<dt><a href="')
            if title_start == -1: continue
            
            link_start = entry.find('">', title_start) + 2
            link_end = entry.find('</a></dt>', link_start)
            
            title = entry[link_start:link_end].strip()
            link = "https://packetstormsecurity.com" + entry[title_start + len('<dt><a href="'):link_start-2]

            results.append({
                "title": title,
                "link": link,
            })
            
            if len(results) >= 5: # Limit to top 5 results
                break

        if not results:
            return {
                "toolUseId": tool_use_id,
                "status": "success",
                "content": [{"json": {"summary": f"No exploits found on Packet Storm for '{query}'.", "exploits": []}}]
            }

        summary = f"Found {len(results)} potential exploits on Packet Storm for '{query}'."
        return {
            "toolUseId": tool_use_id,
            "status": "success",
            "content": [{"json": {"summary": summary, "exploits": results}}]
        }

    except requests.exceptions.RequestException as e:
        return {"toolUseId": tool_use_id, "status": "error", "content": [{"text": f"Request to Packet Storm failed: {e}"}]}
    except Exception as e:
        return {"toolUseId": tool_use_id, "status": "error", "content": [{"text": f"An unexpected error occurred during Packet Storm search: {e}"}]}
