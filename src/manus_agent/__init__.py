"""manus-agent: A powerful framework for building advanced AI agents."""

from manus_agent.agents import (
    BrowserUseAgent,
    DataAnalysisAgent,
    ManusAgent,
    MCPAgent,
)
from manus_agent.config import Config
from manus_agent.multi_agents import WorkflowAgent

__version__ = "0.1.0"

__all__ = ["ManusAgent", "BrowserUseAgent", "DataAnalysisAgent", "MCPAgent", "Config", "WorkflowAgent"]
