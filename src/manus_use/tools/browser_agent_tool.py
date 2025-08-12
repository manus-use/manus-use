#!/usr/bin/env python3
"""
Custom tool that wraps the browser_use agent, making it available as a tool for other Strands agents.
This follows the Agents as Tools pattern.
"""

import asyncio
import json
from typing import Dict, Any
from strands.types.tools import ToolResult, ToolUse

# Import the core logic from the browser agent
from manus_use.agents.browser import run_browser_task

TOOL_SPEC = {
    "name": "browser_agent_tool",
    "description": (
        "A powerful browser-based agent for complex web interactions. Use this when simpler tools like 'http_request' or 'python_repl' fail to retrieve the full content of a web page, which is common for pages that rely heavily on JavaScript or client-side rendering. It is ideal for dynamically validating Proof-of-Concepts (PoCs) by navigating to a page, clicking buttons, and observing the results. The 'task' input must be a very clear, step-by-step instruction for the browser agent to follow."
    ),
    "inputSchema": {
        "json": {
            "type": "object",
            "properties": {
                "task": {
                    "type": "string",
                    "description": "A clear, specific, and detailed instruction for the browser agent. For example: 'Navigate to http://example.com/poc.html, click the button with id 'run_exploit', and describe the result.'",
                }
            },
            "required": ["task"],
        }
    },
}

def browser_agent_tool(tool: ToolUse, **kwargs: Any) -> ToolResult:
    """
    Executes the browser agent with a given task.
    """
    tool_use_id = tool["toolUseId"]
    tool_input = tool["input"]
    task = tool_input.get("task")

    if not task:
        return {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": "The 'task' input is required for the browser_agent_tool."}]
        }

    try:
        # Use asyncio.run() to execute the async function from this synchronous tool
        result_json_str = asyncio.run(run_browser_task(task))
        return {
            "toolUseId": tool_use_id,
            "status": "success",
            "content": [{"json": json.loads(result_json_str)}]
        }
    except Exception as e:
        error_message = f"An error occurred while running the browser agent: {e}"
        print(error_message)
        return {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": error_message}]
        }
