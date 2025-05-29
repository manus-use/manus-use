import asyncio
from typing import Optional

from strands import Agent, tool

from src.manus_use.agents.browser_use_agent import BrowserUseAgent
from src.manus_use.agents.manus import ManusAgent
from src.manus_use.config import Config

config_cache: Optional[Config] = None


def get_config() -> Config:
    """
    Retrieves the configuration, caching it to avoid multiple file reads.
    """
    global config_cache
    if config_cache is None:
        config_cache = Config.from_file()
    return config_cache


@tool
def manus_agent_tool_wrapper(query: str) -> str:
    """
    Use this agent for general tasks, coding, file operations, and web searching that doesn't require complex browser interaction or session persistence. Input is a natural language query.
    """
    try:
        config_instance = get_config()
        manus_agent_instance = ManusAgent(config=config_instance)
        response = manus_agent_instance(query)
        return str(response)
    except Exception as e:
        return f"Error during ManusAgent execution: {e}"


@tool
def browser_agent_tool_wrapper(query: str) -> str:
    """
    Use this agent for tasks requiring web browser interaction, such as navigating web pages, extracting structured information from complex sites, or when session persistence across multiple web steps is needed. Input is a natural language query describing the web task.
    """
    try:
        config_instance = get_config()
        browser_agent_instance = BrowserUseAgent(config=config_instance)
        response = browser_agent_instance(query)
        if asyncio.iscoroutine(response):
            response = asyncio.run(response)
        return str(response)
    except ImportError:
        return "BrowserUseAgent is not available due to missing dependencies. Please ensure 'browser-use' and its LLM support packages are installed."
    except Exception as e:
        return f"Error during BrowserUseAgent execution: {e}"


class NewOrchestrator(Agent):
    def __init__(self, config: Optional[Config] = None):
        config_instance = config if config is not None else get_config()

        system_prompt = """You are an orchestrator agent. Your role is to understand user requests and delegate them to the appropriate specialized agent. You have two specialized agents available as tools:

- `manus_agent_tool_wrapper`: Use this agent for general tasks, coding, file operations, and web searching that doesn't require complex browser interaction or session persistence.
- `browser_agent_tool_wrapper`: Use this agent for tasks requiring web browser interaction, such as navigating web pages, extracting structured information from complex sites, or when session persistence across multiple web steps is needed.

Analyze the user's query and determine which agent is best suited. If the query is simple and doesn't require specialized tools (e.g., a simple greeting or a very basic question you can answer directly), you can answer it yourself. Otherwise, invoke the appropriate agent tool.

If a task might require a sequence of interactions, like browsing to find information and then processing that information (e.g. writing it to a file), prefer to break it down if the tools allow, or route to the agent that can handle the sequence if one is clearly more appropriate for the overall goal. For instance, if it's mostly browsing with a final file write, `browser_agent_tool_wrapper` might be able to extract information, and then a subsequent call to `manus_agent_tool_wrapper` could handle the file writing if the browser agent cannot. If unsure, state what you can do.
"""
        super().__init__(
            model=config_instance.get_model(),
            tools=[manus_agent_tool_wrapper, browser_agent_tool_wrapper],
            system_prompt=system_prompt,
        )
