#!/usr/bin/env python3
"""Shared helpers for tool output size logging."""

from typing import Any


def log_tool_output_size(tool_name: str, result: Any) -> None:
    try:
        content = result.get("content", []) if isinstance(result, dict) else []
        total_text = 0
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                total_text += len(item["text"])
            elif isinstance(item, dict) and "json" in item:
                try:
                    total_text += len(str(item["json"]))
                except Exception:
                    pass
        if total_text:
            print(f"[{tool_name}] Output size: {total_text} chars")
    except Exception:
        pass
