"""Manus-style agent implementation."""

from typing import Any, List, Optional

from strands.types.tools import AgentTool

from .base import BaseManusAgent
from ..config import Config


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
        self.enable_sandbox = enable_sandbox
        
        # Get default tools if none provided
        if tools is None:
            tools = self._get_default_tools(config)
            
        super().__init__(
            tools=tools,
            model=model,
            config=config,
            system_prompt=self._get_default_system_prompt(),
            **kwargs
        )
        
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
        from ..tools import get_tools_by_names
        
        config = config or Config.from_file()
        tool_names = config.tools.enabled
        
        # Always include basic tools
        default_tools = ["file_read", "file_write", "code_execute"]
        
        # Add configured tools
        for name in tool_names:
            if name == "file_operations":
                default_tools.extend(["file_list", "file_delete", "file_move"])
            elif name == "web_search":
                default_tools.append("web_search")
            elif name == "browser":
                default_tools.append("browser_navigate")
            elif name == "visualization":
                default_tools.extend(["create_chart", "data_analyze"])
                
        # Remove duplicates while preserving order
        seen = set()
        unique_tools = []
        for tool in default_tools:
            if tool not in seen:
                seen.add(tool)
                unique_tools.append(tool)
                
        return get_tools_by_names(unique_tools, config=config)