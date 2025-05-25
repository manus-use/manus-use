"""Tools for ManusUse agents."""

from typing import Any, List, Optional

from strands.types.tools import AgentTool

from .file_operations import file_read, file_write, file_list, file_delete, file_move
from .code_execute import code_execute
from .web_search import web_search
from .browser_tools import (
    browser_navigate,
    browser_click,
    browser_type,
    browser_extract,
    browser_screenshot,
    browser_scroll,
    browser_get_state,
    browser_close,
)

# Collect all tools
ALL_TOOLS = {
    "file_read": file_read,
    "file_write": file_write,
    "file_list": file_list,
    "file_delete": file_delete,
    "file_move": file_move,
    "code_execute": code_execute,
    "web_search": web_search,
    "browser_navigate": browser_navigate,
    "browser_click": browser_click,
    "browser_type": browser_type,
    "browser_extract": browser_extract,
    "browser_screenshot": browser_screenshot,
    "browser_scroll": browser_scroll,
    "browser_get_state": browser_get_state,
    "browser_close": browser_close,
}


def get_tools_by_names(
    names: List[str], 
    config: Optional[Any] = None
) -> List[AgentTool]:
    """Get tools by their names.
    
    Args:
        names: List of tool names to retrieve
        config: Optional configuration object
        
    Returns:
        List of tool instances
    """
    tools = []
    for name in names:
        if name in ALL_TOOLS:
            tool = ALL_TOOLS[name]
            # Some tools might need configuration
            if hasattr(tool, "set_config") and config:
                tool.set_config(config)
            tools.append(tool)
    return tools


__all__ = [
    "file_read",
    "file_write",
    "file_list",
    "file_delete",
    "file_move",
    "code_execute",
    "web_search",
    "browser_navigate",
    "browser_click",
    "browser_type",
    "browser_extract",
    "browser_screenshot",
    "browser_scroll",
    "browser_get_state",
    "browser_close",
    "get_tools_by_names",
    "ALL_TOOLS",
]