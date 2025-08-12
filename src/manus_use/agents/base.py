"""Base agent implementation for ManusUse."""

from typing import Any, Dict, List, Optional, Union

from strands import Agent
from strands.types.tools import AgentTool

from manus_use.config import Config


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
    def __del__(self):
        """Ensure proper cleanup."""
        # Properly handle cleanup by checking if parent class has __del__
        if hasattr(super(), '__del__'):
            super().__del__()
    def _get_default_system_prompt(self) -> str:
        """Get default system prompt for this agent type."""
        return "You are a helpful AI assistant."