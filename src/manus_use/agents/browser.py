"""Browser agent implementation."""

from typing import Any, List, Optional

from strands.types.tools import AgentTool

from .base import BaseManusAgent
from ..config import Config


class BrowserAgent(BaseManusAgent):
    """Agent specialized for web browsing and interaction."""
    
    def __init__(
        self,
        tools: Optional[List[AgentTool]] = None,
        model: Optional[Any] = None,
        config: Optional[Config] = None,
        headless: Optional[bool] = None,
        **kwargs
    ):
        """Initialize browser agent.
        
        Args:
            tools: List of tools to use
            model: Model instance or None to use config
            config: Configuration object
            headless: Whether to run browser in headless mode
            **kwargs: Additional arguments for Agent
        """
        config = config or Config.from_file()
        
        # Set headless mode from config if not specified
        if headless is None:
            headless = config.tools.browser_headless
            
        self.headless = headless
        
        # Get browser-specific tools if none provided
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
        """Get browser agent system prompt."""
        return """You are a web browsing agent using browser-use for automation. You can:
- Navigate to websites and extract information
- Click on elements using their index numbers
- Fill out forms by typing into indexed input fields
- Take screenshots of web pages
- Search the web for information
- Extract structured data from websites
- Scroll up and down on pages
- Get the current browser state with interactive elements

IMPORTANT: When interacting with web pages:
1. Always call browser_get_state first to see the current page and available elements
2. Elements are referenced by index numbers [0], [1], [2], etc.
3. Use browser_click with the index to click elements
4. Use browser_type with the index to fill input fields
5. Be respectful of robots.txt and rate limits
6. Extract only the necessary information
7. Handle errors gracefully (pages may not load, elements may not exist)
8. Clean up browser sessions when done

Available browser tools:
- browser_navigate: Navigate to URLs
- browser_get_state: Get current page state with clickable elements
- browser_click: Click on elements by index
- browser_type: Type text into input fields by index
- browser_extract: Extract content based on a goal
- browser_screenshot: Take screenshots
- browser_scroll: Scroll up or down
- browser_close: Close browser session
- web_search: Search the web for information

Your goal is to efficiently gather information from the web to answer user queries."""
        
    def _get_default_tools(self, config: Config) -> List[AgentTool]:
        """Get default tools for browser agent."""
        from ..tools import get_tools_by_names
        
        # Browser-specific tools
        tool_names = [
            "web_search",
            "browser_navigate",
            "browser_click",
            "browser_type",
            "browser_extract",
            "browser_screenshot",
            "browser_wait",
            "browser_execute_js",
            "browser_close",
            "file_write",  # To save extracted data
            "file_read",   # To read saved data
        ]
        
        return get_tools_by_names(tool_names, config=config)