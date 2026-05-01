"""Agent implementations for ManusUse."""

from typing import Any, Optional

from manus_use.agents.base import BaseManusAgent
from manus_use.agents.browser_use_agent import BrowserUseAgent
from manus_use.agents.data_analysis import DataAnalysisAgent
from manus_use.agents.manus import ManusAgent
from manus_use.agents.mcp import MCPAgent
from manus_use.config import Config

try:
    from strands_tools import use_browser as _use_browser
except Exception:
    _use_browser = None


class BrowserAgent(BaseManusAgent):
    """Lightweight browser agent (no `browser-use` dependency).

    This agent exists for CLI/tests and basic browsing workflows via
    `strands_tools.use_browser`.
    """

    def __init__(
        self,
        *,
        config: Optional[Config] = None,
        headless: Optional[bool] = None,
        model: Optional[Any] = None,
        **kwargs: Any,
    ):
        resolved_config = config or Config.from_file()
        self.headless = (
            headless
            if headless is not None
            else bool(getattr(resolved_config.tools, "browser_headless", True))
        )

        tools = []
        if _use_browser is not None:
            tools.append(_use_browser)

        super().__init__(
            tools=tools,
            model=model,
            config=resolved_config,
            system_prompt=self._get_default_system_prompt(),
            **kwargs,
        )

    def _get_default_system_prompt(self) -> str:
        return (
            "You are a helpful AI assistant specialized in web browsing and page extraction. "
            "Use browser tools to navigate, extract relevant content, and summarize findings."
        )

__all__ = [
    "ManusAgent",
    "BrowserAgent",
    "BrowserUseAgent",
    "DataAnalysisAgent",
    "MCPAgent",
]
