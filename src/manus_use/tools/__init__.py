"""Tools for ManusUse agents."""

from typing import Any, List, Optional

from strands.types.tools import AgentTool

from strands_tools import (
                file_read, file_write, python_repl, shell,
                http_request, editor, environment, retrieve,
                generate_image, current_time, calculator
            )
# Collect all tools
ALL_TOOLS = {
    "file_read": file_read,
    "file_write": file_write,
    "python_repl": python_repl,
    "shell": shell,
    "http_request": http_request,
    "editor": editor,
    "environment": environment,
    #"web_search": retrieve.retrieve,  # Using retrieve for web search
    "generate_image": generate_image,
    "current_time": current_time,
    "calculator": calculator
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
    "python_repl",
    "shell",
    "http_request",
    "editor",
    "environment",
    #"web_search": retrieve.retrieve,  # Using retrieve for web search
    "generate_image",
    "current_time",
    "calculator"
]