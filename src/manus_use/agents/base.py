"""Base agent implementation for ManusUse."""

from typing import Any

from strands import Agent
from strands.types.tools import AgentTool

from manus_use.config import Config


class BaseManusAgent(Agent):
    """Base agent with ManusUse enhancements."""

    def __init__(
        self,
        tools: list[AgentTool] | None = None,
        model: Any | None = None,
        config: Config | None = None,
        system_prompt: str | None = None,
        context_manager: str | Any = "auto",
        **kwargs
    ):
        """Initialize base agent.

        Args:
            tools: List of tools to use
            model: Model instance or None to use config
            config: Configuration object
            system_prompt: System prompt for the agent
            context_manager: Strands context manager mode.  ``"auto"`` (default)
                composes a SummarizingConversationManager + ContextOffloader
                with tuned defaults.  ``"agentic"`` lets the model manage its
                own context via summarize_context / truncate_context /
                pin_context tools.  Pass an explicit conversation manager
                instance for full control.
            **kwargs: Additional arguments for Agent
        """
        self.config = config or Config.from_file()
        # Keep an explicit, stable reference for unit tests and callers.
        # The upstream `strands.Agent` does not guarantee a public `tools` attribute.
        self.tools: list[AgentTool] = list(tools or [])
        self._tools: list[AgentTool] = self.tools

        # Use provided model or create from config
        if model is None:
            model = self.config.get_model()

        # Respect config-level context_manager override; caller kwarg wins.
        if context_manager == "auto" and hasattr(self.config, "agent"):
            context_manager = self.config.agent.context_manager

        # Initialize base agent
        super().__init__(
            model=model,
            tools=self.tools,
            system_prompt=system_prompt or self._get_default_system_prompt(),
            context_manager=context_manager,
            **kwargs,
        )
    def __del__(self):
        """Ensure proper cleanup."""
        # Properly handle cleanup by checking if parent class has __del__
        if hasattr(super(), '__del__'):
            super().__del__()
    def _get_default_system_prompt(self) -> str:
        """Get default system prompt for this agent type."""
        return "You are a helpful AI assistant."
