"""Base agent implementation for ManusUse."""

from typing import Any, Dict, List, Optional, Union

from strands import Agent
from strands.types.tools import AgentTool

from ..config import Config


class BaseManusAgent(Agent):
    """Base agent with ManusUse enhancements."""
    
    def __init__(
        self,
        tools: Optional[List[AgentTool]] = None,
        model: Optional[Any] = None,
        config: Optional[Config] = None,
        system_prompt: Optional[str] = None,
        **kwargs
    ):
        """Initialize base agent.
        
        Args:
            tools: List of tools to use
            model: Model instance or None to use config
            config: Configuration object
            system_prompt: System prompt for the agent
            **kwargs: Additional arguments for Agent
        """
        self.config = config or Config.from_file()
        
        # Use provided model or create from config
        if model is None:
            model = self.config.get_model()
            
        # Initialize base agent
        super().__init__(
            model=model,
            tools=tools or [],
            system_prompt=system_prompt or self._get_default_system_prompt(),
            **kwargs
        )
        
    def _get_default_system_prompt(self) -> str:
        """Get default system prompt for this agent type."""
        return "You are a helpful AI assistant."
        
    def add_tools(self, tools: List[AgentTool]) -> None:
        """Add tools to the agent."""
        if hasattr(self, "_tools"):
            self._tools.extend(tools)
        else:
            # For compatibility with different Strands versions
            current_tools = list(self.tools) if hasattr(self, "tools") else []
            current_tools.extend(tools)
            self._update_tools(current_tools)
            
    def _update_tools(self, tools: List[AgentTool]) -> None:
        """Update agent tools."""
        # This method handles the actual tool update
        # Implementation depends on Strands SDK internals
        self._tools = tools