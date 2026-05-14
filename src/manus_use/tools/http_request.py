#!/usr/bin/env python3
"""Wrapper around strands_tools.http_request with output truncation."""

import os
from typing import Any

from strands.types.tools import ToolResult, ToolUse
from strands_tools.http_request import TOOL_SPEC, http_request as _http_request
from manus_use.tools.tool_output_logger import log_tool_output_size

# Truncation limits — override via environment variables if needed.
# Per-item limit: max chars for a single content item (e.g. response body).
MAX_OUTPUT_CHARS = int(os.environ.get("HTTP_REQUEST_MAX_OUTPUT_CHARS", 20_000))
# Total limit: max chars across all content items combined.
MAX_TOTAL_OUTPUT_CHARS = int(os.environ.get("HTTP_REQUEST_MAX_TOTAL_OUTPUT_CHARS", 30_000))


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

        # Phase 1: truncate individual items that exceed per-item limit
        truncated_any = False
        truncated_content = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                text = item["text"]
                if len(text) > MAX_OUTPUT_CHARS:
                    removed = len(text) - MAX_OUTPUT_CHARS
                    text = text[:MAX_OUTPUT_CHARS] + f"\n[truncated: {removed} chars removed]"
                    truncated_any = True
                truncated_content.append({**item, "text": text})
            else:
                truncated_content.append(item)

        # Phase 2: if total still exceeds total limit, proportionally reduce items
        total_after = sum(
            len(item.get("text", ""))
            for item in truncated_content
            if isinstance(item, dict) and isinstance(item.get("text"), str)
        )
        if total_after > MAX_TOTAL_OUTPUT_CHARS:
            ratio = MAX_TOTAL_OUTPUT_CHARS / total_after
            final_content = []
            for item in truncated_content:
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    text = item["text"]
                    item_limit = max(int(len(text) * ratio), 0)
                    if len(text) > item_limit:
                        removed = len(text) - item_limit
                        text = text[:item_limit] + f"\n[truncated: {removed} chars removed]"
                        truncated_any = True
                    final_content.append({**item, "text": text})
                else:
                    final_content.append(item)
            truncated_content = final_content

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
