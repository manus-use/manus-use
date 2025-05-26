"""Browser automation tools using browser-use."""

import asyncio
import base64
import os
from typing import Dict, Optional, Any, Literal

from strands.tools.decorator import tool

try:
    from browser_use import Agent as BrowserUseAgent
    from browser_use import Browser
    from browser_use.browser.browser import BrowserConfig
    from browser_use.controller.service import Controller
    from langchain_aws import ChatBedrock
    BROWSER_USE_AVAILABLE = True
except ImportError:
    BROWSER_USE_AVAILABLE = False
    BrowserUseAgent = None
    Browser = None
    BrowserConfig = None
    Controller = None
    ChatBedrock = None


class BrowserSession:
    """Manages a browser session across tool calls."""
    
    def __init__(self, headless: bool = True, config: Optional[Any] = None):
        self.headless = headless
        self.config = config
        self.browser = None
        self.agent = None
        self.controller = None
        self._initialized = False
        
    async def initialize(self):
        """Initialize browser session."""
        if not BROWSER_USE_AVAILABLE:
            raise ImportError("browser-use and langchain-aws packages are required. Install with: pip install browser-use langchain-aws")
            
        if not self._initialized:
            # Get LLM from config
            llm = self._get_llm()
            
            # Configure browser
            self.browser = Browser(
                config=BrowserConfig(
                    headless=self.headless
                )
            )
            
            # Create controller
            self.controller = Controller()
            
            # Create browser-use agent (without task)
            self.agent = BrowserUseAgent(
                task="",  # We'll set task per action
                llm=llm,
                controller=self.controller,
                browser=self.browser,
                validate_output=False
            )
            
            self._initialized = True
    
    def _get_llm(self):
        """Get LLM instance from config."""
        if self.config and self.config.llm.provider == 'bedrock':
            # Use config settings for Bedrock
            model_id = self.config.llm.model
            region = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
            temperature = self.config.llm.temperature
            max_tokens = self.config.llm.max_tokens
        else:
            # Default to demo settings
            model_id = 'us.anthropic.claude-3-7-sonnet-20250219-v1:0'
            region = 'us-east-1'
            temperature = 0.0
            max_tokens = 4096
            
        return ChatBedrock(
            model_id=model_id,
            model_kwargs={
                "temperature": temperature,
                "max_tokens": max_tokens
            },
            region_name=region
        )
            
    async def cleanup(self):
        """Cleanup browser resources."""
        if self._initialized:
            if self.browser:
                await self.browser.close()
            self._initialized = False
            self.browser = None
            self.agent = None
            self.controller = None


# Global browser session
_browser_session: Optional[BrowserSession] = None


def get_browser_session(headless: bool = True, config: Optional[Any] = None) -> BrowserSession:
    """Get or create browser session."""
    global _browser_session
    if _browser_session is None:
        _browser_session = BrowserSession(headless=headless, config=config)
    return _browser_session


@tool
async def browser_navigate(url: str) -> Dict[str, Any]:
    """Navigate to a URL in the browser.
    
    Args:
        url: URL to navigate to
        
    Returns:
        Dictionary with navigation result and page info
    """
    from ..config import Config
    config = Config.from_file()
    session = get_browser_session(headless=config.tools.browser_headless, config=config)
    await session.initialize()
    
    try:
        # Update agent task and navigate
        session.agent.task = f"Navigate to {url}"
        await session.agent.page.goto(url)
        await session.agent.page.wait_for_load_state()
        
        # Get page info
        title = await session.agent.page.title()
        current_url = session.agent.page.url
        
        return {
            "success": True,
            "url": current_url,
            "title": title,
            "message": f"Successfully navigated to {url}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": f"Failed to navigate to {url}"
        }


@tool
async def browser_click(index: int) -> Dict[str, Any]:
    """Click an element on the page by its index.
    
    Args:
        index: Element index from the browser state
        
    Returns:
        Dictionary with click result
    """
    from ..config import Config
    config = Config.from_file()
    session = get_browser_session(headless=config.tools.browser_headless, config=config)
    
    if not session._initialized:
        return {
            "success": False,
            "error": "Browser not initialized",
            "message": "Please navigate to a page first"
        }
        
    try:
        # Update task and perform action
        session.agent.task = f"Click element at index {index}"
        action = f"click({index})"
        result = await session.controller.perform_action(action, session.agent.page)
        
        return {
            "success": True,
            "index": index,
            "message": f"Clicked element at index {index}",
            "result": str(result) if result else None
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": f"Failed to click element at index {index}"
        }


@tool
async def browser_type(index: int, text: str) -> Dict[str, Any]:
    """Type text into an input field by its index.
    
    Args:
        index: Element index for the input field
        text: Text to type
        
    Returns:
        Dictionary with typing result
    """
    from ..config import Config
    config = Config.from_file()
    session = get_browser_session(headless=config.tools.browser_headless, config=config)
    
    if not session._initialized:
        return {
            "success": False,
            "error": "Browser not initialized",
            "message": "Please navigate to a page first"
        }
        
    try:
        # Update task and perform action
        session.agent.task = f"Type '{text}' into element at index {index}"
        action = f"type({index}, '{text}')"
        result = await session.controller.perform_action(action, session.agent.page)
        
        return {
            "success": True,
            "index": index,
            "text": text,
            "message": f"Successfully typed text into element at index {index}",
            "result": str(result) if result else None
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": f"Failed to type into element at index {index}"
        }


@tool
async def browser_extract(goal: str) -> Dict[str, Any]:
    """Extract content from the current page based on a goal.
    
    Args:
        goal: Description of what to extract from the page
        
    Returns:
        Dictionary with extracted content
    """
    from ..config import Config
    config = Config.from_file()
    session = get_browser_session(headless=config.tools.browser_headless, config=config)
    
    if not session._initialized:
        return {
            "success": False,
            "error": "Browser not initialized",
            "message": "Please navigate to a page first"
        }
        
    try:
        # Update task to extract content
        session.agent.task = f"Extract content from the page: {goal}"
        
        # Get page content
        import markdownify
        content = markdownify.markdownify(await session.agent.page.content())
        
        # Use the agent's LLM to extract based on goal
        extraction_prompt = f"""Given the following web page content, extract information based on this goal: {goal}

Page content:
{content[:3000]}

Extracted information:"""
        
        messages = [{"role": "user", "content": extraction_prompt}]
        response = await session.agent.llm.ainvoke(messages)
        extracted = response.content if hasattr(response, 'content') else str(response)
        
        return {
            "success": True,
            "goal": goal,
            "content": extracted,
            "message": "Successfully extracted content from page"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": "Failed to extract content"
        }


@tool
async def browser_screenshot(path: Optional[str] = None, full_page: bool = True) -> Dict[str, Any]:
    """Take a screenshot of the current page.
    
    Args:
        path: Path to save screenshot (None for base64 return)
        full_page: Whether to capture full page
        
    Returns:
        Dictionary with screenshot result
    """
    from ..config import Config
    config = Config.from_file()
    session = get_browser_session(headless=config.tools.browser_headless, config=config)
    
    if not session._initialized:
        return {
            "success": False,
            "error": "Browser not initialized",
            "message": "Please navigate to a page first"
        }
        
    try:
        screenshot_options = {
            "full_page": full_page,
            "type": "jpeg",
            "quality": 80
        }
        
        if path:
            screenshot_options["path"] = path
            
        screenshot_bytes = await session.agent.page.screenshot(**screenshot_options)
        
        result = {
            "success": True,
            "message": "Screenshot captured successfully"
        }
        
        if path:
            result["path"] = path
        else:
            # Return base64 encoded
            result["screenshot"] = base64.b64encode(screenshot_bytes).decode('utf-8')
            result["format"] = "base64"
            
        return result
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": "Failed to capture screenshot"
        }


@tool
async def browser_scroll(direction: Literal["up", "down"], amount: Optional[int] = None) -> Dict[str, Any]:
    """Scroll the page up or down.
    
    Args:
        direction: Direction to scroll ("up" or "down")
        amount: Pixels to scroll (None for one viewport height)
        
    Returns:
        Dictionary with scroll result
    """
    from ..config import Config
    config = Config.from_file()
    session = get_browser_session(headless=config.tools.browser_headless, config=config)
    
    if not session._initialized:
        return {
            "success": False,
            "error": "Browser not initialized",
            "message": "Please navigate to a page first"
        }
        
    try:
        # Default amount if not specified
        if amount is None:
            amount = 500
            
        # Perform scroll action
        session.agent.task = f"Scroll {direction} by {amount} pixels"
        action = f"scroll({direction}, {amount})"
        await session.controller.perform_action(action, session.agent.page)
        
        return {
            "success": True,
            "direction": direction,
            "amount": amount,
            "message": f"Scrolled {direction} by {amount} pixels"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": f"Failed to scroll {direction}"
        }


@tool
async def browser_get_state() -> Dict[str, Any]:
    """Get the current browser state including URL, title, and interactive elements.
    
    Returns:
        Dictionary with browser state information
    """
    from ..config import Config
    config = Config.from_file()
    session = get_browser_session(headless=config.tools.browser_headless, config=config)
    
    if not session._initialized:
        return {
            "success": False,
            "error": "Browser not initialized",
            "message": "Please navigate to a page first"
        }
        
    try:
        # Get current page info
        url = session.agent.page.url
        title = await session.agent.page.title()
        
        # Take screenshot
        screenshot = await session.agent.page.screenshot(
            full_page=False,
            type="jpeg",
            quality=80
        )
        screenshot_base64 = base64.b64encode(screenshot).decode('utf-8')
        
        # Get page elements using browser-use's element detection
        # This would normally show indexed elements like [0], [1], etc.
        elements_action = "get_elements()"
        elements = await session.controller.perform_action(elements_action, session.agent.page)
        
        # Build state info
        state_info = {
            "url": url,
            "title": title,
            "elements": str(elements) if elements else "No interactive elements found",
            "screenshot": screenshot_base64,
            "help": "Elements are indexed as [0], [1], [2], etc. Use these indices with browser_click and browser_type."
        }
        
        return {
            "success": True,
            "state": state_info,
            "message": "Successfully retrieved browser state"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "message": "Failed to get browser state"
        }


@tool
def browser_close() -> Dict[str, Any]:
    """Close the browser session.
    
    Returns:
        Dictionary with close result
    """
    global _browser_session
    
    if _browser_session and _browser_session._initialized:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_browser_session.cleanup())
            _browser_session = None
            return {
                "success": True,
                "message": "Browser session closed"
            }
        finally:
            loop.close()
    else:
        return {
            "success": True,
            "message": "No active browser session"
        }


# Export all tools
__all__ = [
    "browser_navigate",
    "browser_click",
    "browser_type",
    "browser_extract",
    "browser_screenshot",
    "browser_scroll",
    "browser_get_state",
    "browser_close",
]