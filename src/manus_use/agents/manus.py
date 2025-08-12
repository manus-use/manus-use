"""Manus-style agent implementation."""

from typing import Any, List, Optional

from strands.types.tools import AgentTool

from manus_use.agents.base import BaseManusAgent
from manus_use.config import Config
from typing import Dict, List, Optional

from mcp.client.sse import sse_client
from strands.tools.mcp import MCPClient
from strands.tools import tool
import manus_use.tools.web_search as web_search  
import manus_use.tools.code_execute as code_execute

from strands_tools import (
    file_read, file_write, python_repl, shell,
    http_request, editor, environment, retrieve,
    generate_image, current_time, calculator
)
# Connect to an MCP server using SSE transport
class ManusAgent(BaseManusAgent):
    """Manus-style agent with comprehensive tool support."""
    
    def __init__(
        self,
        tools: Optional[List[AgentTool]] = None,
        model: Optional[Any] = None,
        config: Optional[Config] = None,
        enable_sandbox: bool = True,
        **kwargs
    ):
        """Initialize Manus agent.
        
        Args:
            tools: List of tools to use
            model: Model instance or None to use config
            config: Configuration object
            enable_sandbox: Whether to enable sandbox for code execution
            **kwargs: Additional arguments for Agent
        """
        # Example of loading MCP server URL from config
        #mcp_url = config.mcp.server_url if config and hasattr(config, 'mcp') and getattr(config.mcp, 'server_url', None) else None
        #self.sse_mcp_client = MCPClient(lambda: sse_client(mcp_url))
        self.thread_pool_wrapper = None
        self.enable_sandbox = enable_sandbox
        
        # Get default tools if none provided
        if tools is None:
            tools = self._get_default_tools(config)
        tools.append(code_execute)
        tools.append(http_request)
        #self.sse_mcp_client.start()
            # Get the tools from the MCP server
        #tools.extend(self.sse_mcp_client.list_tools_sync())
        
        # Remove system_prompt from kwargs if present to avoid duplicate argument
        system_prompt = kwargs.pop('system_prompt', '')
        print(f'xxxxxx: {system_prompt}')
            
        super().__init__(
            tools=tools,
            model=model,
            config=config,
            system_prompt=system_prompt + '\n' + self._get_default_system_prompt(),
            **kwargs
        )
        
    def __del__(self):
        """Ensure proper cleanup."""
        # Properly handle cleanup by checking if parent class has __del__
        if hasattr(super(), '__del__'):
            super().__del__()
        # self.sse_mcp_client.stop(None, None, None)
        
    def _get_default_system_prompt(self) -> str:
        """Get Manus-style system prompt."""
        return """You are Manus, an advanced AI assistant capable of:
- Writing and executing code
- Working with files and directories
- Searching the web for information
- Analyzing data and creating visualizations
- Breaking down complex tasks into manageable steps

You should be proactive in using tools to accomplish tasks. When given a task:
1. Break it down into clear steps
2. Use appropriate tools to complete each step
3. Verify your work and handle errors gracefully
4. Provide clear explanations of what you're doing

Always strive for accuracy and completeness in your responses."""
        
    def _get_default_tools(self, config: Optional[Config] = None) -> List[AgentTool]:
        """Get default tools based on configuration."""
        try:
            config = config or Config.from_file()
            tool_names = config.tools.enabled
            
            # Map of tool names to actual tool functions from strands_tools
            available_tools = {
                #"file_read": file_read,
                #"file_write": file_write,
                #"python_repl": python_repl,
                #"shell": shell,
                "http_request": http_request,
                #"editor": editor,
                "environment": environment,
                #"web_search": retrieve.retrieve,  # Using retrieve for web search
                #"generate_image": generate_image,
                "current_time": current_time,
                "calculator": calculator
            }
            
            # Always include basic tools
            default_tool_names = ["file_read", "file_write", "current_time"]
            
            # Add configured tools
            for name in tool_names:
                if name == "file_operations":
                    default_tool_names.extend(["file_read", "file_write", "editor"])
                elif name == "web_search":
                    default_tool_names.append("web_search")
                elif name == "shell":
                    default_tool_names.append("shell")
                elif name == "environment":
                    default_tool_names.append("environment")
                elif name == "visualization":
                    default_tool_names.extend(["generate_image"])
                elif name == "utilities":
                    default_tool_names.extend(["calculator"])
                    
            # Remove duplicates while preserving order
            seen = set()
            unique_tool_names = []
            for tool in default_tool_names:
                if tool not in seen:
                    seen.add(tool)
                    unique_tool_names.append(tool)
            
            # Return the actual tool functions
            tools = []
            for tool_name in unique_tool_names:
                if tool_name in available_tools:
                    tools.append(available_tools[tool_name])
            
            return tools
            
        except ImportError:
            # Fallback to original tools if strands_tools is not available
            from manus_use.tools import get_tools_by_names
            
            config = config or Config.from_file()
            tool_names = config.tools.enabled
            
            # Always include basic tools
            default_tool_names = ["file_read", "file_write", "current_time"]
            
            # Add configured tools
            for name in tool_names:
                if name == "file_operations":
                    default_tool_names.extend(["file_read", "file_write", "editor"])
                elif name == "web_search":
                    default_tool_names.append("web_search")
                elif name == "shell":
                    default_tool_names.append("shell")
                elif name == "environment":
                    default_tool_names.append("environment")
                elif name == "visualization":
                    default_tool_names.extend(["generate_image"])
                elif name == "utilities":
                    default_tool_names.extend(["calculator"])
                    
            # Remove duplicates while preserving order
            seen = set()
            unique_tools = []
            for tool in default_tool_names:
                if tool not in seen:
                    seen.add(tool)
                    unique_tools.append(tool)
                    
            return get_tools_by_names(unique_tools, config=config)