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
        return """You are a web browsing agent powered by browser-use. You can autonomously browse websites, 
extract information, fill forms, and complete complex web-based tasks.

Your primary tool is browser_do, which allows you to give natural language instructions to the browser-use agent.
The browser-use agent will handle all the low-level interactions like clicking, typing, scrolling, etc.

Examples of how to use browser_do:
- browser_do(task="Go to Wikipedia and search for 'artificial intelligence', then summarize the first paragraph")
- browser_do(task="Navigate to example.com and fill out the contact form with test data") 
- browser_do(task="Find the latest news about Python programming on Hacker News")
- browser_do(task="Go to GitHub and find the most starred Python repositories this week")

For simple web searches, you can also use web_search which is faster:
- web_search(query="Python tutorials", max_results=5)

Tips for effective browser tasks:
1. Be specific about what information you want to extract
2. Break down complex tasks into clear steps in your instructions
3. Specify expected output format when needed
4. The browser-use agent is intelligent - trust it to figure out the details
5. Use browser_cleanup() when done with multiple browser tasks

Your goal is to efficiently complete web-based tasks by delegating to the browser-use agent."""
        
    def _get_default_tools(self, config: Config) -> List[AgentTool]:
        """Get default tools for browser agent."""
        from ..tools import get_tools_by_names
        
        # Simplified browser tools - let browser-use handle the complexity
        tool_names = [
            "browser_do",      # Main browser automation tool
            "browser_cleanup", # Cleanup browser resources
            "web_search",      # Quick web search without full browser
            "file_write",      # To save extracted data
            "file_read",       # To read saved data
        ]
        
        return get_tools_by_names(tool_names, config=config)