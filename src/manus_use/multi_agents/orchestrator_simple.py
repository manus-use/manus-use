"""Simplified orchestrator for multi-agent coordination."""

import asyncio
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

from ..agents import ManusAgent, BrowserUseAgent, DataAnalysisAgent, MCPAgent
from ..config import Config
from .planning_agent import PlanningAgent, TaskPlan


@dataclass
class FlowResult:
    """Result from flow execution."""
    success: bool
    output: str = ""
    error: Optional[str] = None


class SimpleOrchestrator:
    """Simplified orchestrator that directly uses agents."""
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize orchestrator."""
        self.config = config or Config.from_file()
        self.agents: Dict[str, Any] = {}
        self.results: Dict[str, Any] = {}
        
        # Create planning agent
        self.planner = PlanningAgent(config=self.config)
        
    def get_agent(self, agent_type: str) -> Any:
        """Get or create an agent of the specified type."""
        # Check if we already have an agent of this type
        if agent_type in self.agents:
            return self.agents[agent_type]
            
        # Create new agent based on type
        if agent_type == "manus":
            agent = ManusAgent(config=self.config)
        elif agent_type == "browser":
            agent = BrowserUseAgent(config=self.config)
        elif agent_type == "data_analysis":
            agent = DataAnalysisAgent(config=self.config)
        elif agent_type == "mcp":
            agent = MCPAgent(config=self.config)
        else:
            # Default to Manus agent
            agent = ManusAgent(config=self.config)
            
        self.agents[agent_type] = agent
        return agent
        
    async def execute_task(self, task: TaskPlan) -> Any:
        """Execute a single task."""
        # Wait for dependencies
        for dep_id in task.dependencies:
            while dep_id not in self.results:
                await asyncio.sleep(0.1)
                
        # Get agent for this task
        agent = self.get_agent(task.agent_type.value)
        
        # Prepare inputs (include dependency results)
        inputs = task.inputs.copy()
        for dep_id in task.dependencies:
            inputs[f"result_{dep_id}"] = self.results.get(dep_id, "")
            
        # Create prompt with context
        prompt = task.description
        if inputs:
            prompt += "\n\nContext/Inputs:"
            for key, value in inputs.items():
                prompt += f"\n- {key}: {value}"
                
        # Execute task
        result = agent(prompt)
        if asyncio.iscoroutine(result):
            result = await result
            
        # Store result
        self.results[task.task_id] = result
        return result
        
    async def execute_plan(self, plan: List[TaskPlan]) -> Dict[str, Any]:
        """Execute a plan with proper dependency handling."""
        # Group tasks by their dependencies
        completed = set()
        
        while len(completed) < len(plan):
            # Find tasks that can be executed
            ready_tasks = [
                task for task in plan 
                if task.task_id not in completed 
                and all(dep in completed for dep in task.dependencies)
            ]
            
            if not ready_tasks:
                # No tasks ready, might be circular dependency
                break
                
            # Execute ready tasks concurrently
            tasks = [self.execute_task(task) for task in ready_tasks]
            await asyncio.gather(*tasks)
            
            # Mark as completed
            for task in ready_tasks:
                completed.add(task.task_id)
                
        return self.results
        
    async def run_async(self, request: str) -> FlowResult:
        """Run a complete flow from user request."""
        try:
            # Create plan using planning agent
            plan = self.planner.create_plan(request)
            
            if not plan:
                return FlowResult(success=False, error="No plan created")
                
            # Execute plan
            results = await self.execute_plan(plan)
            
            # Return the final result
            if plan:
                output = results.get(plan[-1].task_id, "No result")
                return FlowResult(success=True, output=str(output))
                
            return FlowResult(success=True, output="No tasks in plan")
            
        except Exception as e:
            return FlowResult(success=False, error=str(e))
            
    def run(self, request: str) -> FlowResult:
        """Synchronous version of run."""
        return asyncio.run(self.run_async(request))