"""Tools for ManusUse agents."""

from typing import Any, List, Optional

from strands.types.tools import AgentTool

from .file_operations import file_read, file_write, file_list, file_delete, file_move
from .code_execute import code_execute
from .web_search import web_search
from .browser_tools import (
    browser_do,
    browser_cleanup,
    # Individual browser actions
    browser_navigate,
    browser_search_google,
    browser_go_back,
    browser_wait,
    browser_click_element,
    browser_input_text,
    browser_save_pdf,
    browser_switch_tab,
    browser_open_tab,
    browser_close_tab,
    browser_extract_content,
    browser_get_page_info,
    browser_scroll_down,
    browser_scroll_up,
    browser_scroll_to_text,
    browser_send_keys,
    browser_select_dropdown,
    browser_drag_drop,
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
    "browser_do": browser_do,
    "browser_cleanup": browser_cleanup,
    # Individual browser actions
    "browser_navigate": browser_navigate,
    "browser_search_google": browser_search_google,
    "browser_go_back": browser_go_back,
    "browser_wait": browser_wait,
    "browser_click_element": browser_click_element,
    "browser_input_text": browser_input_text,
    "browser_save_pdf": browser_save_pdf,
    "browser_switch_tab": browser_switch_tab,
    "browser_open_tab": browser_open_tab,
    "browser_close_tab": browser_close_tab,
    "browser_extract_content": browser_extract_content,
    "browser_get_page_info": browser_get_page_info,
    "browser_scroll_down": browser_scroll_down,
    "browser_scroll_up": browser_scroll_up,
    "browser_scroll_to_text": browser_scroll_to_text,
    "browser_send_keys": browser_send_keys,
    "browser_select_dropdown": browser_select_dropdown,
    "browser_drag_drop": browser_drag_drop,
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
    "browser_do",
    "browser_cleanup",
    # Individual browser actions
    "browser_navigate",
    "browser_search_google",
    "browser_go_back",
    "browser_wait",
    "browser_click_element",
    "browser_input_text",
    "browser_save_pdf",
    "browser_switch_tab",
    "browser_open_tab",
    "browser_close_tab",
    "browser_extract_content",
    "browser_get_page_info",
    "browser_scroll_down",
    "browser_scroll_up",
    "browser_scroll_to_text",
    "browser_send_keys",
    "browser_select_dropdown",
    "browser_drag_drop",
    "get_tools_by_names",
    "ALL_TOOLS",
]