#!/usr/bin/env python3
"""Wrapper around strands_tools.http_request with output truncation."""

from typing import Any

from strands.types.tools import ToolResult, ToolUse
from strands_tools.http_request import http_request as _http_request
from manus_use.tools.tool_output_logger import log_tool_output_size

MAX_OUTPUT_CHARS = 100_000


def http_request(tool: ToolUse, **kwargs: Any) -> ToolResult:
    result = _http_request(tool, **kwargs)
    try:
        content = result.get("content", [])
        total_before = sum(
            len(item.get("text", ""))
            for item in content
            if isinstance(item, dict) and isinstance(item.get("text"), str)
        )
        if total_before:
            print(f"[http_request] Output size before truncation: {total_before} chars")

        truncated_any = False
        truncated_content = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                text = item["text"]
                if len(text) > MAX_OUTPUT_CHARS:
                    text = text[:MAX_OUTPUT_CHARS] + "\n[truncated]"
                    truncated_any = True
                truncated_content.append({**item, "text": text})
            else:
                truncated_content.append(item)

        total_after = sum(
            len(item.get("text", ""))
            for item in truncated_content
            if isinstance(item, dict) and isinstance(item.get("text"), str)
        )
        if total_after:
            print(f"[http_request] Output size after truncation: {total_after} chars")

        if truncated_any:
            result = {**result, "content": truncated_content}

        log_tool_output_size("http_request", result)
        return result
    except Exception as exc:
        print(f"[http_request] Truncation/logging failed: {exc}")
        return result
