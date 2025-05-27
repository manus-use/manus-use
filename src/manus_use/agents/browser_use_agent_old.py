"""Browser-use as a Strands Agent.

This module provides a Strands Agent wrapper around the `browser_use` library.
It allows the main application to delegate browser-based tasks to an autonomous
`browser_use.Agent` instance.
"""

import asyncio
import logging
import os
from typing import Any, Optional, List, Union, Coroutine

from strands import Agent
# from strands.types.tools import AgentTool # Not used directly by BrowserUseAgent

from ..config import Config

try:
    from browser_use import Agent as BrowserUse
    from browser_use.browser.profile import BrowserProfile
    from browser_use.controller.service import Controller
    from langchain_aws import ChatBedrock
    from langchain_openai import ChatOpenAI
    BROWSER_USE_AVAILABLE = True
except ImportError:
    BROWSER_USE_AVAILABLE = False
    BrowserUse = None
    BrowserProfile = None
    Controller = None
    ChatBedrock = None
    ChatOpenAI = None


class BrowserUseAgent(Agent):
    """A Strands Agent that wraps the `browser_use` library's agent.

    This agent acts as a bridge between a Strands-based application and the
    `browser_use` library. It is designed to receive a task (typically a natural
    language instruction for web interaction), pass it to a fresh instance of
    `browser_use.Agent`, and return the result.

    It does not use Strands tools in the traditional sense; instead, its primary
    function is to manage and invoke the `browser_use.Agent`. The underlying
    `browser_use.Agent` handles its own LLM interactions (configured via this
    wrapper) and browser control.
    """
    
    def __init__(
        self,
        config: Optional[Config] = None,
        headless: Optional[bool] = None,
        enable_memory: Optional[bool] = None,
        **kwargs
    ):
        """Initialize the BrowserUseAgent.

        Args:
            config: A `Config` object containing application settings, including
                LLM provider (used by `_get_browser_llm`) and tool configurations. 
                If None, it loads from the default configuration file.
            headless: Specifies whether the browser controlled by `browser-use`
                should run in headless mode. If None, defaults to the value in
                `config.tools.browser_headless`.
            enable_memory: If True, enables the memory feature of the underlying
                `browser_use.Agent`. Defaults to False.
            **kwargs: Additional keyword arguments passed to the base `strands.Agent`
                constructor.
        """
        # Ensure config is loaded to check llm.provider for ImportError message
        loaded_config = config or Config.from_file()

        if not BROWSER_USE_AVAILABLE:
            missing_packages = ["browser-use"]
            # Check if specific langchain libraries are missing based on config
            if loaded_config and loaded_config.llm.provider == 'bedrock' and not ChatBedrock:
                missing_packages.append("langchain-aws")
            if loaded_config and loaded_config.llm.provider == 'openai' and not ChatOpenAI:
                missing_packages.append("langchain-openai")
            
            # If a provider is configured but its library is missing, the list will be more specific.
            # If no provider is configured or a generic import failed, it might list both.
            # A more targeted check could be done in _get_browser_llm if provider is known.
            if "langchain-aws" not in missing_packages and "langchain-openai" not in missing_packages:
                 if not ChatBedrock: missing_packages.append("langchain-aws")
                 if not ChatOpenAI: missing_packages.append("langchain-openai")

            raise ImportError(
                f"Required package(s) for BrowserUseAgent missing or failed to import: {', '.join(missing_packages)}. "
                f"Please install them (e.g., pip install {' '.join(missing_packages)})."
            )
            
        self.config = loaded_config # Use the loaded_config
        self.headless = headless if headless is not None else self.config.tools.browser_headless
        self.enable_memory = enable_memory if enable_memory is not None else False
        
        # Initialize base Strands Agent.
        # A dummy model is provided as browser-use uses its own internal LLM (configured via _get_browser_llm).
        # No tools are registered as this agent's role is to delegate tasks to browser_use.Agent.
        super().__init__(
            model=self._get_dummy_model(),
            tools=[], 
            system_prompt="", # System prompt is handled by the browser_use.Agent internally.
            **kwargs
        )
    
    def _get_dummy_model(self) -> Any:
        """Provides a dummy model instance for base `strands.Agent` initialization.

        The `BrowserUseAgent` itself doesn't use this model directly for its core
        logic. The actual LLM used for browser tasks is configured and returned by
        `_get_browser_llm` for the `browser_use.Agent`. This dummy model, however,
        is obtained from the main application's configuration and fulfills the
        `strands.Agent` base class requirement for a model instance.
        """
        return self.config.get_model()
    
    
    def _get_browser_llm(self) -> Any:
        """Dynamically selects and configures the LLM for the `browser_use.Agent`.

        Based on the `llm.provider` setting in `self.config` (which is the main
        application's configuration), this method instantiates and returns the
        appropriate Langchain LLM client (e.g., `ChatBedrock` or `ChatOpenAI`).
        The specific model name, temperature, and max tokens are also sourced from
        `self.config.llm`.

        This LLM instance is then passed to the `browser_use.Agent` when it's
        created for each task.

        Raises:
            ImportError: If the required Langchain package for the configured
                         LLM provider (e.g., `langchain-aws` for Bedrock)
                         is not installed.
            ValueError: If the configured `llm.provider` in `self.config` is not
                        supported (currently 'bedrock' or 'openai').

        Returns:
            An instance of a Langchain LLM client.
        """
        provider = self.config.llm.provider
        model_name = self.config.llm.model
        temperature = self.config.llm.temperature
        max_tokens = self.config.llm.max_tokens

        if provider == 'bedrock':
            if not ChatBedrock:
                raise ImportError("langchain-aws package is missing. Install with: pip install langchain-aws")
            region = os.getenv('AWS_DEFAULT_REGION', self.config.llm.aws_region or 'us-east-1')
            return ChatBedrock(
                model_id=model_name,
                model_kwargs={"temperature": temperature, "max_tokens": max_tokens},
                region_name=region,
            )
        elif provider == 'openai':
            if not ChatOpenAI:
                raise ImportError("langchain-openai package is missing. Install with: pip install langchain-openai")
            # ChatOpenAI typically picks up OPENAI_API_KEY from environment variables.
            # It can also be passed explicitly:
            # openai_api_key=self.config.llm.openai_api_key or os.getenv("OPENAI_API_KEY")
            return ChatOpenAI(
                model_name=model_name,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        else:
            raise ValueError(
                f"Unsupported LLM provider for BrowserUseAgent: {provider}. "
                "Supported providers are 'bedrock' and 'openai'."
            )
    
    def __call__(self, task: Union[str, List[dict]]) -> Union[str, Coroutine[Any, Any, str]]:
        """Executes a browser-based task using a new `browser_use.Agent` instance.

        This method overrides the default `strands.Agent.__call__`. It receives a
        task, typically a natural language instruction. It then determines if it's
        running in an asynchronous context to decide whether to run `_run_browser_task`
        directly (if async) or wrap it with `asyncio.run` (if sync).

        A fresh `browser_use.Agent` is instantiated for each call to ensure that
        each task is handled in isolation, with its own browser session and memory state
        (if enabled).

        Args:
            task: The task description. This can be a plain string (e.g., "Search
                  for AI on Wikipedia") or a list of Strands-compatible message
                  dictionaries. If a list, the content of the last user message
                  is extracted as the task string.

        Returns:
            The result from the `browser_use.Agent` as a string. If called in an
            asynchronous context, it returns a coroutine that will yield the
            string result.
        """
        if isinstance(task, list):
            # Extract the task string from the last message if a list is provided
            task_str = task[-1].get("content", "") if task else ""
        else:
            task_str = task
            
        # Determine if currently in an async event loop
        try:
            asyncio.get_running_loop()
            # If yes, return the coroutine directly
            return self._run_browser_task(task_str)
        except RuntimeError:
            # If no, run the async task using asyncio.run
            return asyncio.run(self._run_browser_task(task_str))
    
    async def _run_browser_task(self, task: str) -> str:
        """Run browser task asynchronously using browser-use.
        
        Instantiates a browser-use.Agent for the given task and executes it,
        then processes the result to return a summary string.
        """
        # Create browser profile with headless setting
        browser_profile = BrowserProfile(
            headless=self.headless
        )
        
        # Create a new browser-use agent for this task
        # Ensure Controller is imported or defined
        # from browser_use.controller.service import Controller # Assuming it's available
        browser_use_agent_instance = BrowserUse( # Renamed from browser_use_agent to avoid confusion
            task=task,
            llm=self._get_browser_llm(),
            browser_profile=browser_profile,
            controller=Controller(), 
            enable_memory=self.enable_memory,
            validate_output=False # Kept from original
        )
        
        # Run the agent
        result = await browser_use_agent_instance.run() # result is likely AgentHistoryList
        
        if hasattr(result, 'extracted_content') and callable(result.extracted_content):
            extracted_items = result.extracted_content() # This should return a list
            if isinstance(extracted_items, list):
                # Join multiple pieces of extracted content with newlines.
                # Convert all items to string in case they are not already.
                return "\n".join(str(item) for item in extracted_items)
            elif extracted_items is not None:
                # If it's not a list but some other single value
                return str(extracted_items)
            else:
                # extracted_content() returned None
                logging.info("BrowserUseAgent: result.extracted_content() returned None.")
                return "" # Return empty string if no content was extracted
        else:
            # Fallback if the result object doesn't match AgentHistoryList structure
            # or if extracted_content is not available as expected.
            logging.warning(
                "BrowserUseAgent: Could not find 'extracted_content' method on result or it's not callable. "
                f"Falling back to str(result). Result type: {type(result)}, Result: {result}"
            )
            return str(result)
    
    async def cleanup(self):
        """Cleans up browser resources.
        
        Note: `browser_use.Agent` instances are created per-task within `_run_browser_task`.
        The `browser_use` library is expected to handle the cleanup of its own
        resources (e.g., browser instances) when the `BrowserUse` object is
        garbage collected after each task. This method is provided for API
        consistency with the `strands.Agent` base class but may not require
        specific actions if `browser_use` manages its resources effectively
        per instance.
        """
        # `browser_use.Agent` instances are created per-task and are expected
        # to manage their own cleanup. No explicit agent-wide cleanup needed here.
        pass
    
    def __del__(self):
        """Ensures cleanup on deletion of the BrowserUseAgent instance.
        
        Note: Similar to `cleanup`, actual resource release for browsers is primarily
        the responsibility of the per-task `browser_use.Agent` instances.
        """
        # No specific cleanup needed here, as browser_use.Agent instances are per-task.
        pass
                
    async def stream_async(self, *args, **kwargs):
        """Provides results from the `browser_use.Agent` execution.

        This method is part of the `strands.Agent` interface. However, the
        underlying `browser_use` library, as currently integrated, executes a
        task to completion and returns the full result rather than streaming
        partial outputs.

        Therefore, this method first executes the task by calling `self.__call__`
        (which internally handles both synchronous and asynchronous invocation of
        `_run_browser_task`). Once the complete result is obtained (and awaited if
        necessary), it is yielded as a single event dictionary conforming to
        Strands' streaming format.

        Args:
            *args: Positional arguments to be passed to `self.__call__`.
            **kwargs: Keyword arguments to be passed to `self.__call__`.

        Yields:
            A dictionary of the form `{"type": "text", "text": final_result}`,
            containing the complete result from the browser task.
        """
        # Get the full result from the __call__ method (which handles sync/async execution)
        result_value = self.__call__(*args, **kwargs)

        # If __call__ returned a coroutine (meaning it was called in an async context), await it.
        if asyncio.iscoroutine(result_value):
            final_result = await result_value
        else:
            # If __call__ returned a direct result (sync context), use it.
            final_result = result_value
            
        yield {"type": "text", "text": final_result}

# Example usage (illustrative, not for direct execution without proper setup)
# if __name__ == '__main__':
#     # This requires a ManusUse Config setup and relevant environment variables.
#     # Example for OpenAI:
#     # Ensure OPENAI_API_KEY is set in your environment.
#     # Create or load a manus_use.config.Config object where llm.provider = "openai"
#     # config = Config() # Or Config.from_file('path/to/your/config.yaml')
#     # config.llm.provider = "openai"
#     # config.llm.model = "gpt-3.5-turbo" # Or your preferred model
#     #
#     # agent = BrowserUseAgent(config=config, headless=True, enable_memory=False)
#     # try:
#     #     result = agent(task="Go to example.com and find the title of the page.")
#     #     print(f"Result: {result}")
#     # except Exception as e:
#     #     print(f"An error occurred: {e}")

#     # Example for Bedrock (requires AWS credentials and Bedrock model access configured):
#     # config_bedrock = Config() # Ensure this config points to Bedrock provider & model
#     # config_bedrock.llm.provider = "bedrock"
#     # config_bedrock.llm.model = "anthropic.claude-v2" # Or your preferred Bedrock model
#     #
#     # agent_bedrock = BrowserUseAgent(config=config_bedrock, headless=True)
#     # try:
#     #     bedrock_result = agent_bedrock(task="Search Wikipedia for 'Artificial Intelligence'")
#     #     print(f"Bedrock Result: {bedrock_result}")
#     # except Exception as e:
#     #     print(f"An error occurred with Bedrock: {e}")
#     pass