"""Multi-agent coordination and task planning.

This module provides lightweight, import-stable types used by the CLI and tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .workflow_agent import WorkflowAgent


class AgentType(str, Enum):
    MANUS = "manus"
    BROWSER = "browser"
    DATA_ANALYSIS = "data_analysis"
    MCP = "mcp"


class ComplexityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class TaskPlan:
    task_id: str
    description: str
    agent_type: AgentType
    dependencies: List[str] = field(default_factory=list)
    inputs: Dict[str, Any] = field(default_factory=dict)
    expected_output: str = ""
    priority: int = 3
    estimated_complexity: ComplexityLevel = ComplexityLevel.MEDIUM


@dataclass
class OrchestratorResult:
    success: bool
    output: str = ""
    error: Optional[str] = None
    tasks: List[TaskPlan] = field(default_factory=list)


class Orchestrator:
    """Minimal multi-agent orchestrator used by the CLI.

    The full orchestration logic can evolve independently, but the public surface
    area (constructor, ``agents`` attribute, and ``run`` method) remains stable.
    """

    def __init__(self, *, config: Any = None, model_name: Optional[str] = None):
        self.config = config
        self.model_name = model_name
        self.agents: Dict[str, Any] = {}
        self._workflow_agent = WorkflowAgent(model_name=model_name) if model_name else WorkflowAgent()

    def run(self, request: str) -> OrchestratorResult:
        try:
            output = self._workflow_agent.handle_request(request)
            return OrchestratorResult(success=True, output=str(output))
        except Exception as exc:
            return OrchestratorResult(success=False, error=str(exc))


__all__ = [
    "WorkflowAgent",
    "AgentType",
    "ComplexityLevel",
    "TaskPlan",
    "Orchestrator",
    "OrchestratorResult",
]
