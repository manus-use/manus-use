"""manus-use: A powerful framework for building advanced AI agents."""

from .agents import (
    ManusAgent,
    BrowserAgent,
    BrowserUseAgent,
    DataAnalysisAgent,
    MCPAgent,
)
from .multi_agents import Orchestrator, PlanningAgent, TaskPlan
from .config import Config

__version__ = "0.1.0"

__all__ = [
    "ManusAgent",
    "BrowserAgent",
    "BrowserUseAgent", 
    "DataAnalysisAgent",
    "MCPAgent",
    "Orchestrator",
    "PlanningAgent",
    "TaskPlan",
    "Config",
]