"""Browser automation using browser-use as an agent."""

import asyncio
import os
from typing import Dict, Any, Optional

from strands.tools.decorator import tool

try:
    from browser_use import Agent as BrowserUseAgent
    from browser_use.browser.profile import BrowserProfile
    from browser_use.controller.service import Controller
    from langchain_aws import ChatBedrock
    BROWSER_USE_AVAILABLE = True
except ImportError:
    BROWSER_USE_AVAILABLE = False
    BrowserUseAgent = None
    BrowserProfile = None
    Controller = None
    ChatBedrock = None


class BrowserAgentSession:
    """Manages a browser-use agent session."""
    
    def __init__(self, headless: Optional[bool] = None, config: Optional[Any] = None):
        self.config = config
        # Use browser_use config if available, otherwise fall back to parameter or default
        if headless is not None:
            self.headless = headless
        elif config and hasattr(config, 'browser_use'):
            self.headless = config.browser_use.headless  # pylint: disable=no-member
        else:
            self.headless = True
    
    def _get_llm(self):
        """Get LLM instance from config."""
        # Check if browser_use config has provider/model overrides
        if self.config and hasattr(self.config, 'browser_use'):
            browser_config = self.config.browser_use
            provider = browser_config.provider or self.config.llm.provider
            model_id = browser_config.model or self.config.llm.model
            temperature = browser_config.temperature
            max_tokens = browser_config.max_tokens
        elif self.config:
            # Fall back to main LLM config
            provider = self.config.llm.provider
            model_id = self.config.llm.model
            temperature = self.config.llm.temperature
            max_tokens = self.config.llm.max_tokens
        else:
            # Default settings
            provider = 'bedrock'
            model_id = 'us.anthropic.claude-3-5-sonnet-20241022-v2:0'
            temperature = 0.0
            max_tokens = 4096
        
        if provider == 'bedrock':
            region = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
            return ChatBedrock(
                model_id=model_id,
                model_kwargs={
                    "temperature": temperature,
                    "max_tokens": max_tokens
                },
                region_name=region
            )
        else:
            raise ValueError(f"Unsupported provider for browser tools: {provider}")
    
    async def run_task(self, task: str) -> str:
        """Run a browser task."""
        if not BROWSER_USE_AVAILABLE:
            raise ImportError(
                "browser-use and langchain-aws packages are required. "
                "Install with: pip install browser-use langchain-aws"
            )
            
        # For browser-use, we need to create a new agent for each task
        # because the task is set during initialization
        
        # Create browser profile
        browser_profile = BrowserProfile(
            headless=self.headless
        )
        
        # Get LLM from config
        llm = self._get_llm()
        
        # Create browser-use agent with the specific task
        agent = BrowserUseAgent(
            task=task,  # Set the task here
            llm=llm,
            browser_profile=browser_profile,
            controller=Controller(),
            enable_memory=False,  # Disable memory to avoid warning
            validate_output=False
        )
        
        # Run the agent
        result = await agent.run()
        
        # Extract the result text
        if hasattr(result, 'extracted_content'):
            # Check if it's a method and call it
            extracted = result.extracted_content
            if callable(extracted):
                return extracted()
            return extracted
        elif hasattr(result, 'all_results') and result.all_results:
            # Get the last "done" result text
            for res in reversed(result.all_results):
                if res.is_done and res.extracted_content:
                    return res.extracted_content
        
        return str(result)
            
    async def cleanup(self):
        """Cleanup browser resources."""
        # browser-use handles its own cleanup per instance
        pass


# Global session instance
_browser_session: Optional[BrowserAgentSession] = None


def get_browser_session(headless: bool = True, config: Optional[Any] = None) -> BrowserAgentSession:
    """Get or create browser session singleton."""
    global _browser_session
    
    if _browser_session is None:
        _browser_session = BrowserAgentSession(headless=headless, config=config)
    
    return _browser_session


@tool
async def browser_do(
    task: str,
    headless: Optional[bool] = None
) -> Dict[str, Any]:
    """Execute a browser task using browser-use agent.
    
    This tool uses the browser-use agent to autonomously complete web browsing tasks.
    The agent can navigate, click, type, extract information, and perform complex
    multi-step operations based on natural language instructions.
    
    Args:
        task: Natural language description of what to do in the browser
        headless: Whether to run browser in headless mode (default: from config)
        
    Returns:
        Dictionary containing:
        - success: Whether the task completed successfully
        - result: The result/output from browser-use
        - task: The task that was executed
        - error: Error message if failed
        
    Examples:
        - "Go to OpenAI's website and find their pricing for GPT-4"
        - "Search for 'Python tutorials' on Google and summarize the top 3 results"
        - "Navigate to GitHub, search for 'strands sdk', and get the star count"
        - "Fill out the contact form on example.com with test data"
    """
    try:
        # Get config
        from ..config import Config
        config = Config.from_file()
        
        # Determine headless mode - use browser_use config if available
        if headless is None:
            if hasattr(config, 'browser_use'):
                headless = config.browser_use.headless  # pylint: disable=no-member
            else:
                headless = config.tools.browser_headless  # pylint: disable=no-member
            
        # Get or create session
        session = get_browser_session(headless=headless, config=config)
        
        # Run the task
        result = await session.run_task(task)
        
        return {
            "success": True,
            "result": result,
            "task": task
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "task": task
        }


@tool
async def browser_cleanup() -> Dict[str, Any]:
    """Close the browser and cleanup resources.
    
    Call this when done with browser tasks to free up resources.
    
    Returns:
        Dictionary with cleanup status
    """
    global _browser_session
    
    try:
        if _browser_session:
            await _browser_session.cleanup()
            _browser_session = None
            
        return {
            "success": True,
            "message": "Browser session cleaned up"
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


# Keep web_search as a separate tool since it doesn't need full browser
@tool
async def web_search(
    query: str,
    max_results: int = 5
) -> Dict[str, Any]:
    """Search the web using the configured search engine.
    
    This is a lightweight alternative to browser_do for simple searches.
    
    Args:
        query: Search query
        max_results: Maximum number of results to return
        
    Returns:
        Dictionary with search results
    """
    try:
        from ..config import Config
        from .web_search import web_search as search_impl
        
        # Use the existing web_search implementation
        return await search_impl(query=query, max_results=max_results)
        
    except Exception as e:
        # Fallback to browser_do if web_search fails
        task = f"Search the web for '{query}' and return the top {max_results} results with titles, URLs, and descriptions"
        return await browser_do(task=task)


# Individual browser actions from browser-use
# These provide more fine-grained control compared to browser_do

@tool
async def browser_navigate(url: str) -> Dict[str, Any]:
    """Navigate to a specific URL in the current tab.
    
    Args:
        url: The URL to navigate to
        
    Returns:
        Dictionary with navigation status
    """
    return await browser_do(task=f"Navigate to {url}")


@tool
async def browser_search_google(query: str) -> Dict[str, Any]:
    """Search Google with a specific query.
    
    Args:
        query: Search query (should be concrete, not vague or super long)
        
    Returns:
        Dictionary with search results
    """
    return await browser_do(task=f"Search Google for: {query}")


@tool
async def browser_go_back() -> Dict[str, Any]:
    """Go back to the previous page in browser history.
    
    Returns:
        Dictionary with status
    """
    return await browser_do(task="Go back to the previous page")


@tool
async def browser_wait(seconds: int = 3) -> Dict[str, Any]:
    """Wait for a specified number of seconds.
    
    Args:
        seconds: Number of seconds to wait (default: 3)
        
    Returns:
        Dictionary with status
    """
    return await browser_do(task=f"Wait for {seconds} seconds")


@tool
async def browser_click_element(
    element_description: str,
    index: Optional[int] = None
) -> Dict[str, Any]:
    """Click on an element on the page.
    
    Args:
        element_description: Description of the element to click
        index: Optional index if multiple matching elements
        
    Returns:
        Dictionary with click status
    """
    if index is not None:
        task = f"Click on element with index {index}: {element_description}"
    else:
        task = f"Click on: {element_description}"
    return await browser_do(task=task)


@tool
async def browser_input_text(
    text: str,
    field_description: str,
    index: Optional[int] = None
) -> Dict[str, Any]:
    """Input text into a field on the page.
    
    Args:
        text: Text to input
        field_description: Description of the input field
        index: Optional index if multiple matching fields
        
    Returns:
        Dictionary with input status
    """
    if index is not None:
        task = f"Input '{text}' into field with index {index}: {field_description}"
    else:
        task = f"Input '{text}' into: {field_description}"
    return await browser_do(task=task)


@tool
async def browser_save_pdf(filename: Optional[str] = None) -> Dict[str, Any]:
    """Save the current page as a PDF file.
    
    Args:
        filename: Optional filename for the PDF
        
    Returns:
        Dictionary with save status
    """
    if filename:
        task = f"Save the current page as PDF with filename: {filename}"
    else:
        task = "Save the current page as PDF"
    return await browser_do(task=task)


@tool
async def browser_switch_tab(tab_id: int) -> Dict[str, Any]:
    """Switch to a specific browser tab.
    
    Args:
        tab_id: ID of the tab to switch to
        
    Returns:
        Dictionary with switch status
    """
    return await browser_do(task=f"Switch to tab number {tab_id}")


@tool
async def browser_open_tab(url: str) -> Dict[str, Any]:
    """Open a new browser tab with a specific URL.
    
    Args:
        url: URL to open in the new tab
        
    Returns:
        Dictionary with tab open status
    """
    return await browser_do(task=f"Open a new tab with URL: {url}")


@tool
async def browser_close_tab(tab_id: int) -> Dict[str, Any]:
    """Close a specific browser tab.
    
    Args:
        tab_id: ID of the tab to close
        
    Returns:
        Dictionary with close status
    """
    return await browser_do(task=f"Close tab number {tab_id}")


@tool
async def browser_extract_content(
    goal: str,
    include_links: bool = False
) -> Dict[str, Any]:
    """Extract specific content from the current page.
    
    Args:
        goal: What information to extract (e.g., "all company names", "contact information")
        include_links: Whether to include links in the extraction
        
    Returns:
        Dictionary with extracted content
    """
    task = f"Extract from the page: {goal}"
    if include_links:
        task += " (include links)"
    return await browser_do(task=task)


@tool
async def browser_get_page_info() -> Dict[str, Any]:
    """Get information about the current page including title, URL, and content summary.
    
    Returns:
        Dictionary with page information
    """
    return await browser_do(task="Get the page title, URL, and a brief summary of the content")


@tool
async def browser_scroll_down(pixels: Optional[int] = None) -> Dict[str, Any]:
    """Scroll down the page.
    
    Args:
        pixels: Number of pixels to scroll (if None, scrolls one page)
        
    Returns:
        Dictionary with scroll status
    """
    if pixels:
        task = f"Scroll down {pixels} pixels"
    else:
        task = "Scroll down one page"
    return await browser_do(task=task)


@tool
async def browser_scroll_up(pixels: Optional[int] = None) -> Dict[str, Any]:
    """Scroll up the page.
    
    Args:
        pixels: Number of pixels to scroll (if None, scrolls one page)
        
    Returns:
        Dictionary with scroll status
    """
    if pixels:
        task = f"Scroll up {pixels} pixels"
    else:
        task = "Scroll up one page"
    return await browser_do(task=task)


@tool
async def browser_scroll_to_text(text: str) -> Dict[str, Any]:
    """Scroll to specific text on the page.
    
    Args:
        text: Text to scroll to
        
    Returns:
        Dictionary with scroll status
    """
    return await browser_do(task=f"Scroll to the text: '{text}'")


@tool
async def browser_send_keys(keys: str) -> Dict[str, Any]:
    """Send keyboard keys or shortcuts.
    
    Args:
        keys: Keys to send (e.g., "Escape", "Enter", "Control+S")
        
    Returns:
        Dictionary with key send status
    """
    return await browser_do(task=f"Press keyboard keys: {keys}")


@tool
async def browser_select_dropdown(
    option_text: str,
    dropdown_description: str
) -> Dict[str, Any]:
    """Select an option from a dropdown menu.
    
    Args:
        option_text: Text of the option to select
        dropdown_description: Description of the dropdown
        
    Returns:
        Dictionary with selection status
    """
    return await browser_do(task=f"Select '{option_text}' from the dropdown: {dropdown_description}")


@tool
async def browser_drag_drop(
    source_description: str,
    target_description: str
) -> Dict[str, Any]:
    """Drag and drop an element to another location.
    
    Args:
        source_description: Description of the element to drag
        target_description: Description of where to drop it
        
    Returns:
        Dictionary with drag-drop status
    """
    return await browser_do(task=f"Drag '{source_description}' and drop it on '{target_description}'")