"""MCP (Model Context Protocol) agent implementation."""

from typing import Any, List, Optional

from strands.types.tools import AgentTool
from strands.tools.mcp import MCPClient

from .base import BaseManusAgent
from ..config import Config


class MCPAgent(BaseManusAgent):
    """Agent that uses MCP tools."""
    
    def __init__(
        self,
        mcp_servers: Optional[List[MCPClient]] = None,
        tools: Optional[List[AgentTool]] = None,
        model: Optional[Any] = None,
        config: Optional[Config] = None,
        **kwargs
    ):
        """Initialize MCP agent.
        
        Args:
            mcp_servers: List of MCP server clients
            tools: Additional tools to use
            model: Model instance or None to use config
            config: Configuration object
            **kwargs: Additional arguments for Agent
        """
        # Collect tools from MCP servers
        all_tools = tools or []
        
        if mcp_servers:
            for server in mcp_servers:
                if hasattr(server, "list_tools_sync"):
                    server_tools = server.list_tools_sync()
                    all_tools.extend(server_tools)
                    
        super().__init__(
            tools=all_tools,
            model=model,
            config=config,
            system_prompt=self._get_default_system_prompt(),
            **kwargs
        )
        
        self.mcp_servers = mcp_servers or []
        
    def _get_default_system_prompt(self) -> str:
        """Get MCP agent system prompt."""
        return """You are an AI assistant with access to various MCP (Model Context Protocol) tools.

These tools may include:
- File system operations
- Database queries
- API integrations
- Custom business logic
- External services

Use the available tools to help accomplish user tasks efficiently. Always check what tools are available before attempting a task."""
        
    def add_mcp_server(self, server: MCPClient) -> None:
        """Add an MCP server to the agent's list of servers."""
        self.mcp_servers.append(server)
        # Tools from this server will not be dynamically added to the agent.
        # The agent should be initialized with all necessary MCP servers and their tools.