import asyncio
import logging
import os
from typing import (
    Any,
    Optional,
    List,
    Union,
    Coroutine,
    Dict,
    AsyncGenerator,
    Type,
)

from pydantic import BaseModel
from strands import Agent
from strands.types.tools import AgentTool # Though not used directly, often part of agent modules

from ..config import Config

# Attempt to import browser_use and its dependencies
try:
    from browser_use import Agent as BrowserUse
    from browser_use.agent.views import (
        AgentHistoryList,
        AgentOutput,
    ) # Assuming AgentOutput is what model_output is
    from browser_use.browser.profile import BrowserProfile
    from browser_use.browser.views import (
        BrowserStateSummary,
    ) # Assuming this is what browser_state_summary is
    from browser_use.controller.service import Controller
    from langchain_aws import ChatBedrock
    from langchain_openai import ChatOpenAI
    from langchain_core.language_models.chat_models import BaseChatModel

    BROWSER_USE_AVAILABLE = True
    IMPORTED_MODULES = {
        "browser_use": True,
        "langchain_aws": True,
        "langchain_openai": True,
    }
    MISSING_PACKAGES = []

except ImportError as e:
    BROWSER_USE_AVAILABLE = False
    IMPORTED_MODULES = {
        "browser_use": False,
        "langchain_aws": False,
        "langchain_openai": False,
    }
    if "browser_use" in str(e).lower():
        IMPORTED_MODULES["browser_use"] = False
    if "langchain_aws" in str(e).lower() or "bedrock" in str(e).lower():
        IMPORTED_MODULES["langchain_aws"] = False
    if "langchain_openai" in str(e).lower() or "openai" in str(e).lower():
        IMPORTED_MODULES["langchain_openai"] = False
    
    MISSING_PACKAGES = [pkg for pkg, imported in IMPORTED_MODULES.items() if not imported]

    # Define placeholders for type hints if imports fail
    BrowserUse = None
    AgentHistoryList = None
    AgentOutput = None
    BrowserProfile = None
    BrowserStateSummary = None
    Controller = None
    ChatBedrock = None
    ChatOpenAI = None
    BaseChatModel = None


class BrowserUseAgent(Agent):
    """
    Strands Agent wrapper for the 'browser-use' library.

    This agent delegates browser automation tasks to an instance of 
    `browser_use.Agent`. It manages the lifecycle of the `browser_use.Agent`,
    configures it based on the main application's settings, and translates
    Strands Agent calls to `browser-use` operations.

    The underlying `browser_use.Agent` handles its own LLM interactions (configured
    via this wrapper) and browser control using Playwright. This wrapper agent
    itself does not use Strands tools directly for browser tasks, but rather
    treats `browser-use` as the execution engine.
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        headless: Optional[bool] = None,
        enable_memory: Optional[bool] = None,
        output_model: Optional[Type[BaseModel]] = None,
        **kwargs: Any,
    ):
        """Initialize BrowserUseAgent.

        Args:
            config: Configuration object for LLM and other settings.
            headless: Whether to run the browser in headless mode. 
                      Overrides config if set.
            enable_memory: Whether to enable memory for the browser-use agent.
                           Overrides config if set, defaults to False.
            output_model: Optional Pydantic model to define structured output
                          for the browser-use agent. If provided, the agent
                          will attempt to return JSON conforming to this model.
            **kwargs: Additional arguments for the base Strands Agent.
        """
        if not BROWSER_USE_AVAILABLE:
            error_message = "BrowserUseAgent requirements missing: "
            if not IMPORTED_MODULES["browser_use"]:
                error_message += "Required package 'browser-use' is not installed. "
            
            missing_llm_support = []
            if not IMPORTED_MODULES["langchain_aws"]:
                missing_llm_support.append("'langchain-aws' (for Bedrock)")
            if not IMPORTED_MODULES["langchain_openai"]:
                missing_llm_support.append("'langchain-openai' (for OpenAI)")
            
            if missing_llm_support:
                error_message += f"LLM support packages missing: {', '.join(missing_llm_support)}. "
            
            error_message += "Please install them (e.g., pip install browser-use langchain-aws langchain-openai)."
            raise ImportError(error_message)

        self.config = config or Config.from_file()
        
        # Get browser_use specific config
        browser_config = self.config.browser_use

        print("==================================")

        print(browser_config)
        
        # Use parameters if provided, otherwise fall back to browser_use config
        self.headless = (
            headless
            if headless is not None
            else browser_config.headless
        )
        self.enable_memory = (
            enable_memory
            if enable_memory is not None
            else browser_config.enable_memory
        )
        self.output_model = output_model
        
        # Store other browser_use settings
        self.max_steps = browser_config.max_steps
        self.max_actions_per_step = browser_config.max_actions_per_step
        self.use_vision = browser_config.use_vision
        self.save_conversation_path = browser_config.save_conversation_path
        self.max_error_length = browser_config.max_error_length
        self.tool_calling_method = browser_config.tool_calling_method
        self.keep_alive = browser_config.keep_alive
        self.disable_security = browser_config.disable_security
        self.extra_chromium_args = browser_config.extra_chromium_args
        self.timeout = browser_config.timeout
        self.retry_count = browser_config.retry_count
        self.debug = browser_config.debug
        self.save_screenshots = browser_config.save_screenshots
        self.screenshot_path = browser_config.screenshot_path
        
        # Initialize Strands Agent with a dummy model and no tools,
        # as browser-use handles its own LLM and actions.
        super().__init__(
            model=self._get_dummy_model(),
            tools=[], # No Strands tools for this agent
            system_prompt="", # browser-use handles its own prompting
            **kwargs,
        )

    def _get_dummy_model(self) -> Any:
        """
        Get a dummy model instance for base Strands Agent initialization.
        Since browser-use uses its own configured LLM, the base Agent's model
        is not directly used for browser tasks. This provides a valid model
        object from the main application's config to satisfy base class requirements.
        """
        return self.config.get_model()

    def _get_browser_llm(self) -> BaseChatModel:
        """
        Get the LangChain BaseChatModel for the browser-use agent.
        Uses browser_use config section if available, otherwise falls back to main LLM config.
        Raises ImportError if required LLM packages are missing, or ValueError for
        unsupported providers.
        """
        # Use browser_use config if provider is specified, otherwise fall back to main LLM config
        browser_config = self.config.browser_use
        provider = browser_config.provider or self.config.llm.provider
        model_name = browser_config.model or self.config.llm.model
        temperature = browser_config.temperature
        max_tokens = browser_config.max_tokens
        api_key = browser_config.api_key or self.config.llm.api_key
        
        # Get AWS region from environment for Bedrock
        aws_region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

        if provider == "bedrock":
            if not ChatBedrock:
                raise ImportError(
                    "langchain-aws package is missing. Please install with: pip install langchain-aws"
                )
            return ChatBedrock(
                model_id=model_name,
                model_kwargs={"temperature": temperature, "max_tokens": max_tokens},
                region_name=aws_region,
            )
        elif provider == "openai":
            if not ChatOpenAI:
                raise ImportError(
                    "langchain-openai package is missing. Please install with: pip install langchain-openai"
                )
            kwargs = {
                "model_name": model_name,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            # Add API key if provided in config
            if api_key:
                kwargs["api_key"] = api_key
            return ChatOpenAI(**kwargs)
        else:
            raise ValueError(
                f"Unsupported LLM provider for BrowserUseAgent: {provider}. "
                "Supported providers are 'bedrock' and 'openai'."
            )

    async def _run_browser_task(self, task: str) -> str:
        """
        Run browser task asynchronously using browser-use for a non-streaming call.
        Instantiates a browser-use.Agent for the given task and executes it,
        then processes the result to return a summary string.
        Ensures the browser_use.Agent is closed after execution.
        """
        browser_use_agent_instance: Optional[BrowserUse] = None
        try:
            browser_profile = BrowserProfile(
                headless=self.headless,
                disable_security=self.disable_security,
                extra_chromium_args=self.extra_chromium_args,
                keep_alive=self.keep_alive,
            )
            
            controller_kwargs = {}
            if self.output_model:
                controller_kwargs['output_model'] = self.output_model

            controller = Controller(**controller_kwargs)

            browser_use_agent_instance = BrowserUse(
                task=task,
                llm=self._get_browser_llm(),
                browser_profile=browser_profile,
                controller=controller,
                enable_memory=self.enable_memory,
                # Only pass parameters that browser-use actually supports
                # max_steps, max_actions_per_step, etc. are not supported in current version
                validate_output=False, # Kept from original implementation
            )

            result: AgentHistoryList = await browser_use_agent_instance.run()

            if self.output_model and hasattr(result, 'final_result') and callable(result.final_result):
                # If output_model is used, final_result() gives JSON string
                final_json_string = result.final_result()
                return final_json_string if final_json_string is not None else ""

            if hasattr(result, 'extracted_content') and callable(result.extracted_content):
                extracted_items = result.extracted_content()
                if isinstance(extracted_items, list):
                    return "\n".join(str(item) for item in extracted_items)
                elif extracted_items is not None:
                    return str(extracted_items)
                else:
                    logging.info("BrowserUseAgent: result.extracted_content() returned None.")
                    return ""
            else:
                logging.warning(
                    "BrowserUseAgent: Could not find 'extracted_content' method on result or it's not callable. "
                    f"Falling back to str(result). Result type: {type(result)}, Result: {result}"
                )
                return str(result)
        finally:
            if browser_use_agent_instance and hasattr(browser_use_agent_instance, 'close'):
                try:
                    logging.debug("Closing browser_use agent instance in _run_browser_task.")
                    await browser_use_agent_instance.close()
                except Exception as e_close:
                    logging.error(f"Error closing browser_use_agent_instance in _run_browser_task: {e_close}")
        return "" # Should be unreachable if try block returns

    def __call__(
        self, task: Union[str, List[dict]]
    ) -> Union[str, Coroutine[Any, Any, str]]:
        """
        Execute a browser task using browser-use.
        This method delegates directly to browser-use instead of using the
        normal Strands agent loop. It handles both synchronous and asynchronous invocation.

        Args:
            task: Task description (string) or a list of message dictionaries.
                  If a list, the content of the last user message is used as the task.

        Returns:
            Result from browser-use (string, potentially JSON if output_model is used)
            or a coroutine if called from an async context.
        """
        task_str: str
        if isinstance(task, list):
            task_str = task[-1].get("content", "") if task and task[-1].get("role") == "user" else ""
            if not task_str: # Fallback if last message isn't user or no content
                 task_str = str(task) # Or some other summarization
        else:
            task_str = task

        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                # We're in an async context, return a coroutine
                return self._run_browser_task(task_str)
            else: # Should not happen often in typical async frameworks
                return asyncio.run(self._run_browser_task(task_str))
        except RuntimeError:
            # No event loop, typically means a sync context
            return asyncio.run(self._run_browser_task(task_str))

    async def stream_async(
        self, task: Union[str, List[dict]], **kwargs: Any
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Execute a browser task using browser-use and stream intermediate updates.

        This method implements true incremental streaming by using callbacks from
        the underlying `browser_use.Agent`. It yields dictionaries representing
        step updates, final results, or errors.

        Args:
            task: Task description (string) or a list of message dictionaries.
            **kwargs: Additional arguments (currently not used but part of signature).

        Yields:
            Dictionaries representing streaming events (e.g., step updates, final results, errors).
        """
        task_str: str
        if isinstance(task, list):
            task_str = task[-1].get("content", "") if task and task[-1].get("role") == "user" else ""
            if not task_str:
                 task_str = str(task)
        else:
            task_str = task

        queue: asyncio.Queue[Optional[Dict[str, Any]]] = asyncio.Queue()
        browser_use_agent_instance: Optional[BrowserUse] = None
        run_task_bg = None

        async def step_callback(
            summary: BrowserStateSummary, model_out: AgentOutput, step_num: int
        ):
            try:
                event_data = {
                    "type": "step_update",
                    "step": step_num,
                    "url": summary.url if summary else None,
                    "title": summary.title if summary else None,
                    "planned_actions": [
                        action.model_dump(exclude_unset=True)
                        for action in model_out.action
                    ] if model_out and model_out.action else [],
                    "next_goal": model_out.current_state.next_goal
                    if model_out and model_out.current_state
                    else None,
                }
                await queue.put(event_data)
            except Exception as e_cb:
                logging.error(f"Error in stream_async step_callback: {e_cb}")
                # Attempt to put an error on the queue so the consumer knows something went wrong
                await queue.put({"type": "error", "message": f"Error in step_callback: {str(e_cb)}"})


        async def done_callback(history: AgentHistoryList):
            try:
                final_content_str = ""
                if self.output_model and hasattr(history, 'final_result') and callable(history.final_result):
                    final_content_str = history.final_result() or ""
                elif hasattr(history, 'extracted_content') and callable(history.extracted_content):
                    extracted_items = history.extracted_content()
                    if isinstance(extracted_items, list):
                        final_content_str = "\n".join(str(item) for item in extracted_items)
                    elif extracted_items is not None:
                        final_content_str = str(extracted_items)
                
                event_data = {
                    "type": "final_result",
                    "is_successful": history.is_successful() if hasattr(history, 'is_successful') else None,
                    "total_steps": len(history.history) if hasattr(history, 'history') else None, # More direct way
                    "content": final_content_str, # Unified content string
                    # Optionally include more from history if needed
                    # "full_history": history.model_dump(exclude_unset=True) # Could be very large
                }
                await queue.put(event_data)
            except Exception as e_cb:
                logging.error(f"Error in stream_async done_callback: {e_cb}")
                await queue.put({"type": "error", "message": f"Error in done_callback: {str(e_cb)}"})
            finally:
                await queue.put(None)  # End of stream marker

        try:
            browser_profile = BrowserProfile(
                headless=self.headless,
                disable_security=self.disable_security,
                extra_chromium_args=self.extra_chromium_args,
                keep_alive=self.keep_alive,
            )
            
            controller_kwargs = {}
            if self.output_model:
                controller_kwargs['output_model'] = self.output_model
            controller = Controller(**controller_kwargs)

            browser_use_agent_instance = BrowserUse(
                task=task_str,
                llm=self._get_browser_llm(),
                browser_profile=browser_profile,
                controller=controller,
                enable_memory=self.enable_memory,
                # Only pass parameters that browser-use actually supports
                validate_output=False, 
                register_new_step_callback=step_callback,
                register_done_callback=done_callback,
            )

            run_task_bg = asyncio.create_task(browser_use_agent_instance.run())

            while True:
                item = await queue.get()
                if item is None:
                    queue.task_done()
                    break
                yield item
                queue.task_done()
            
            # Await the background task to ensure it finishes and to catch any exceptions
            if run_task_bg: # Check if task was created
                 await run_task_bg

        except Exception as e:
            logging.error(f"Error during BrowserUseAgent stream_async execution: {e}", exc_info=True)
            yield {"type": "error", "message": f"Error during streaming task: {str(e)}"}
            # Ensure queue is unblocked if consumer is still waiting
            if queue.empty(): # Check if queue is empty before putting None
                await queue.put(None)
        finally:
            if run_task_bg and not run_task_bg.done():
                logging.debug("Cancelling background browser-use run task.")
                run_task_bg.cancel()
                try:
                    await run_task_bg # Await cancellation
                except asyncio.CancelledError:
                    logging.debug("Background browser-use run task was successfully cancelled.")
                except Exception as e_cancel:
                    logging.error(f"Error during cancellation of browser-use run task: {e_cancel}")
            
            if browser_use_agent_instance and hasattr(browser_use_agent_instance, 'close'):
                try:
                    logging.debug("Closing browser_use agent instance in stream_async.")
                    await browser_use_agent_instance.close()
                except Exception as e_close:
                    logging.error(f"Error closing browser_use_agent_instance in stream_async: {e_close}")

    async def cleanup(self):
        """
        Placeholder for cleanup logic if BrowserUseAgent itself held long-lived resources.
        Currently, browser_use.Agent instances are created per-task and are expected
        to manage their own resources via their `close()` method.
        """
        pass

    def __del__(self):
        """
        Placeholder for destructor logic.
        As `browser_use.Agent` instances are per-task, specific cleanup
        is handled via their `close()` method within `_run_browser_task` and `stream_async`.
        """
        pass

# Example usage (illustrative, typically not part of the agent file itself)
# if __name__ == "__main__":
#     # This example part would need to be adapted to your project's async setup
#     # and configuration loading.
#     async def main_example():
#         # Load config (ensure your Config class can be instantiated simply or mock it)
#         try:
#             # config = Config.from_file() # Or your project's way of getting config
#             # For testing, mock a simple config if Config.from_file() is complex
#             class MockConfig:
#                 class LLMConfig:
#                     provider="openai" # or "bedrock"
#                     model="gpt-3.5-turbo" # change as needed
#                     temperature=0.0
#                     max_tokens=2000
#                     aws_region=os.getenv("AWS_DEFAULT_REGION", "us-east-1")
#                 llm = LLMConfig()
#                 class ToolsConfig:
#                     browser_headless = True # or False
#                     browser_use_enable_memory = False
#                 tools = ToolsConfig()
#                 def get_model(self): # Dummy model for base Strands Agent
#                     return Mock() # from unittest.mock
            
#             config = MockConfig()

#         except Exception as e_conf:
#             logging.error(f"Failed to load config for example: {e_conf}")
#             return

#         # Ensure OPENAI_API_KEY (or Bedrock credentials) are set in your environment
#         if config.llm.provider == "openai" and not os.getenv("OPENAI_API_KEY"):
#             logging.warning("OPENAI_API_KEY not set, example might fail.")
        
#         agent = BrowserUseAgent(config=config, headless=True, enable_memory=False)

#         # --- Example for __call__ (non-streaming) ---
#         # task_description = "What is the main headline on bbc.com/news?"
#         # logging.info(f"Running non-streaming task: {task_description}")
#         # try:
#         #     result_str = await agent(task_description) # if in async context already
#         #     # result_str = agent(task_description) # if in sync context (test carefully)
#         #     logging.info(f"Non-streaming result:\n{result_str}")
#         # except Exception as e_call:
#         #     logging.error(f"Error in __call__ example: {e_call}", exc_info=True)


#         # --- Example for stream_async ---
#         streaming_task = "Find the weather in London and then the capital of France."
#         logging.info(f"\nRunning streaming task: {streaming_task}")
#         try:
#             async for event in agent.stream_async(task=streaming_task):
#                 logging.info(f"Streaming event: {event}")
#         except Exception as e_stream:
#             logging.error(f"Error in stream_async example: {e_stream}", exc_info=True)

#     # if sys.platform == "win32":
#     #     asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
#     # asyncio.run(main_example())