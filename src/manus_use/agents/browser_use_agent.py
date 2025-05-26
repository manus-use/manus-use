"""Browser-use as a Strands Agent."""

import asyncio
import os
from typing import Any, Optional, List, Union, Coroutine

from strands import Agent
from strands.types.tools import AgentTool

from ..config import Config

try:
    from browser_use import Agent as BrowserUse
    from browser_use.browser.profile import BrowserProfile
    from browser_use.controller.service import Controller
    from langchain_aws import ChatBedrock
    BROWSER_USE_AVAILABLE = True
except ImportError:
    BROWSER_USE_AVAILABLE = False
    BrowserUse = None
    BrowserProfile = None
    Controller = None
    ChatBedrock = None


class BrowserUseAgent(Agent):
    """Strands Agent wrapper for browser-use.
    
    This agent delegates all browser tasks to the browser-use agent,
    treating it as the underlying execution engine rather than a tool.
    """
    
    def __init__(
        self,
        config: Optional[Config] = None,
        headless: Optional[bool] = None,
        **kwargs
    ):
        """Initialize BrowserUseAgent.
        
        Args:
            config: Configuration object
            headless: Whether to run browser in headless mode
            **kwargs: Additional arguments for Agent
        """
        if not BROWSER_USE_AVAILABLE:
            raise ImportError(
                "browser-use and langchain-aws packages are required. "
                "Install with: pip install browser-use langchain-aws"
            )
            
        self.config = config or Config.from_file()
        self.headless = headless if headless is not None else self.config.tools.browser_headless
        
        
        # Initialize Strands Agent with minimal setup
        # We don't need tools since we delegate everything to browser-use
        super().__init__(
            model=self._get_dummy_model(),  # browser-use has its own LLM
            tools=[],  # No tools needed
            system_prompt="",  # browser-use handles prompting
            **kwargs
        )
    
    def _get_dummy_model(self):
        """Get a dummy model for Strands Agent initialization.
        
        Since browser-use has its own LLM, we just need something
        to satisfy Strands Agent requirements.
        """
        return self.config.get_model()
    
    
    def _get_browser_llm(self):
        """Get LLM for browser-use."""
        if self.config.llm.provider == 'bedrock':
            model_id = self.config.llm.model
            region = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
            temperature = self.config.llm.temperature
            max_tokens = self.config.llm.max_tokens
        else:
            # Default settings
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
    
    def __call__(self, task: Union[str, List[dict]]) -> Union[str, Coroutine[Any, Any, str]]:
        """Execute a browser task.
        
        This overrides the Strands Agent __call__ to delegate
        directly to browser-use instead of using the normal
        Strands agent loop.
        
        Args:
            task: Task description (string) or message list
            
        Returns:
            Result from browser-use (string) or coroutine if in async context
        """
        # Convert to string if needed
        if isinstance(task, list):
            # Extract user message from message list
            task_str = task[-1].get("content", "") if task else ""
        else:
            task_str = task
            
        # Check if we're already in an event loop
        try:
            asyncio.get_running_loop()
            # We're in an async context, return a coroutine
            return self._run_browser_task(task_str)
        except RuntimeError:
            # No event loop, we can use asyncio.run
            return asyncio.run(self._run_browser_task(task_str))
    
    async def _run_browser_task(self, task: str) -> str:
        """Run browser task asynchronously."""
        # Create browser profile with headless setting
        browser_profile = BrowserProfile(
            headless=self.headless
        )
        
        # Create a new browser-use agent for this task
        browser_use_agent = BrowserUse(
            task=task,
            llm=self._get_browser_llm(),
            browser_profile=browser_profile,
            controller=Controller(),
            enable_memory=False,  # Disable memory to avoid warning
            validate_output=False
        )
        
        # Run the agent
        result = await browser_use_agent.run()
        
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
        """Clean up browser resources."""
        # browser-use handles its own cleanup per instance
        pass
    
    def __del__(self):
        """Ensure cleanup on deletion."""
        # No cleanup needed since we create/destroy agents per task
        pass
                
    # Override stream methods if needed
    async def stream_async(self, *args, **kwargs):
        """browser-use doesn't support streaming, so we return the full result."""
        result = self.__call__(*args, **kwargs)
        yield {"type": "text", "text": result}