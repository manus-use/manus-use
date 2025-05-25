"""Flow orchestrator for multi-agent coordination."""

import asyncio
from typing import Any, Dict, List, Optional

from ..agents import ManusAgent, BrowserAgent, DataAnalysisAgent, MCPAgent
from ..config import Config
from .task_planner import PlanningAgent, TaskPlan


class FlowOrchestrator:
    """Orchestrates multi-agent workflows."""
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize flow orchestrator.
        
        Args:
            config: Configuration object
        """
        self.config = config or Config.from_file()
        self.agents: Dict[str, Any] = {}
        self.results: Dict[str, Any] = {}
        
        # Add default planning agent
        self.add_agent("planner", PlanningAgent(config=self.config))
        
    def add_agent(self, name: str, agent: Any) -> None:
        """Add an agent to the orchestrator.
        
        Args:
            name: Unique name for the agent
            agent: Agent instance
        """
        self.agents[name] = agent
        
    def get_agent(self, agent_type: str) -> Any:
        """Get or create an agent of the specified type.
        
        Args:
            agent_type: Type of agent (manus, browser, data_analysis, mcp)
            
        Returns:
            Agent instance
        """
        # Check if we already have an agent of this type
        if agent_type in self.agents:
            return self.agents[agent_type]
            
        # Create new agent based on type
        if agent_type == "manus":
            agent = ManusAgent(config=self.config)
        elif agent_type == "browser":
            agent = BrowserAgent(config=self.config)
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
        """Execute a single task.
        
        Args:
            task: Task to execute
            
        Returns:
            Task result
        """
        # Wait for dependencies
        for dep_id in task.dependencies:
            while dep_id not in self.results:
                await asyncio.sleep(0.1)
                
        # Get agent for this task
        agent = self.get_agent(task.agent_type)
        
        # Prepare inputs (include dependency results)
        inputs = task.inputs.copy()
        for dep_id in task.dependencies:
            inputs[f"result_{dep_id}"] = self.results[dep_id]
            
        # Create prompt with context
        prompt = task.description
        if inputs:
            prompt += "\n\nContext/Inputs:"
            for key, value in inputs.items():
                prompt += f"\n- {key}: {value}"
                
        # Execute task
        result = agent(prompt)
        
        # Store result
        self.results[task.task_id] = result
        
        return result
        
    async def execute_plan(self, plan: List[TaskPlan]) -> Dict[str, Any]:
        """Execute a plan concurrently.
        
        Args:
            plan: List of tasks to execute
            
        Returns:
            Dictionary of task results
        """
        # Create tasks for concurrent execution
        tasks = []
        for task in plan:
            tasks.append(self.execute_task(task))
            
        # Execute all tasks
        await asyncio.gather(*tasks)
        
        return self.results
        
    def run(self, request: str) -> Any:
        """Run a complete flow from user request.
        
        Args:
            request: User's request
            
        Returns:
            Final result
        """
        # Get planning agent
        planner = self.agents.get("planner")
        if not planner:
            raise ValueError("No planning agent configured")
            
        # Create plan
        plan = planner.create_plan(request)
        
        # Execute plan
        loop = asyncio.new_event_loop()
        try:
            results = loop.run_until_complete(self.execute_plan(plan))
            
            # Return the final result (last task's output)
            if plan:
                return results.get(plan[-1].task_id, "No result")
            return "No tasks in plan"
            
        finally:
            loop.close()
            
    async def run_async(self, request: str) -> Any:
        """Async version of run."""
        planner = self.agents.get("planner")
        if not planner:
            raise ValueError("No planning agent configured")
            
        plan = planner.create_plan(request)
        results = await self.execute_plan(plan)
        
        if plan:
            return results.get(plan[-1].task_id, "No result")
        return "No tasks in plan"