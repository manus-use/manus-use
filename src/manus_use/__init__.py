"""manus-use: A powerful framework for building advanced AI agents."""

from .agents import (
    ManusAgent,
    BrowserAgent,
    DataAnalysisAgent,
    MCPAgent,
)
from .multi_agents import FlowOrchestrator, PlanningAgent, TaskPlan
from .config import Config

__version__ = "0.1.0"

__all__ = [
    "ManusAgent",
    "BrowserAgent", 
    "DataAnalysisAgent",
    "MCPAgent",
    "FlowOrchestrator",
    "PlanningAgent",
    "TaskPlan",
    "Config",
]