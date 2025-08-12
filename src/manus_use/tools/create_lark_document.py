from typing import Any
from strands.types.tools import ToolResult, ToolUse
import os
from src.manus_use.config import Config


TOOL_SPEC = {
    "name": "create_lark_document",
    "description": """Create a lark document for vulnerability assessment.""",
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Format as '[VI-{XXX}] CVE-{YEAR}-{NUMBER} Assessment: {Brief Description} in {Product}` where XXX is a three-digit identifier (e.g., VI-001, VI-104, VI-999",
                },
                "disclosure": {
                    "type": "string",
                    "description": "Discovery and disclosure information",
                },
                "public_disclosure": {
                    "type": "string",
                    "description": "Date when the vulnerability was publicly disclosed (YYYY-MM-DD)",
                },
                "sources": {
                    "type": "string",
                    "description": "A single string with a comma-separated list of URLs or references to publicly available sources of information on the vulnerability.",
                },
                "proof_of_concept_links": {
                    "type": "string",
                    "description": "A single string containing a comma-separated list of URLs to publicly available proof-of-concept exploits (e.g., GitHub links).",
                },
                "cpe": {
                    "type": "string",
                    "description": "Common Platform Enumeration identifier",
                },
                "affected_versions": {
                    "type": "string",
                    "description": "A single string containing a comma-separated list of affected product versions.",
                },
                "technical_details": {
                    "type": "string",
                    "description": "Single plain-text paragraph summarizing the detailed technical explanation including Exploitation Scenarios, Evidence of active exploitation in the wild, and Detection, without any Markdown formatting, bullet points, or lists. Combine them into one cohesive paragraph suitable for inclusion in a professional report",
                },
                "cwe_info": {
                    "type": "string",
                    "description": "Common Weakness Enumeration classification",
                },
                "cvss_score": {
                    "type": "string",
                    "description": "Format as 'Severity(Score),Vector' e.g. 'Critical(9.8),CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'",
                },
                "recommendations": {
                    "type": "string",
                    "description": "Single plain-text paragraph summarizing the recommended remediation actions without any Markdown formatting, bullet points, or lists. Combine them into one cohesive paragraph suitable for inclusion in a professional report",
                },
                "background": {
                    "type": "string",
                    "description": "Single plain-text paragraph summarizing the Brief background on the affected software without any Markdown formatting, bullet points, or lists. Combine them into one cohesive paragraph suitable for inclusion in a professional report",
                },
            },
            "required": [
                "title",
                "disclosure",
                "public_disclosure",
                "sources",
                "proof_of_concept_links",
                "cpe",
                "affected_versions",
                "technical_details",
                "cwe_info",
                "cvss_score",
                "recommendations",
                "background"
            ],
        }
    },
}

def create_lark_document(tool: ToolUse, **kwargs: Any) -> ToolResult:
    tool_use_id = tool["toolUseId"]
    title = tool["input"]["title"]
    print(f"Creating lark document with title: {tool['input']}")
    import requests
    config = Config.from_file()
    url = getattr(getattr(config, 'lark', None), 'document_url', None)
    if not url:
        url = os.environ.get("LARK_DOCUMENT_URL")
    if not url:
        raise ValueError("Lark document API URL not set in config or environment. Please set [lark] document_url in your config.toml or the LARK_DOCUMENT_URL environment variable.")
    api_token = getattr(getattr(config, 'lark', None), 'api_token', None)
    if not api_token:
        api_token = os.environ.get("LARK_API_TOKEN")
    if not api_token:
        raise ValueError("Lark API token not set in config or environment. Please set [lark] api_token in your config.toml or the LARK_API_TOKEN environment variable.")
    headers = {
        "Authorization": f"Bearer {api_token}"
    }
    try:
        response = requests.post(url, headers=headers, json=tool['input'])
        response.raise_for_status()  # Raises an HTTPError if the response status code is 4XX/5XX
        print(response.text)
        return {
            "toolUseId": tool_use_id,
            "status": "success",
            "content": [{"text": f"Created lark document at {title}"}],
        }
    except requests.exceptions.HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
        return {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": f"Failed to create lark document: {http_err}"}],
        }
    except Exception as err:
        print(f'Other error occurred: {err}')
        return {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": f"Failed to create lark document: {err}"}],
        }