"""Advanced orchestration strategies for multi-agent collaboration."""

from typing import List, Dict, Any, Optional
from enum import Enum
from pydantic import BaseModel

from .task_planner import TaskPlan


class ExecutionStrategy(Enum):
    """Different strategies for executing multi-agent workflows."""
    
    SEQUENTIAL = "sequential"  # Execute tasks one by one
    PARALLEL = "parallel"      # Execute independent tasks concurrently
    ADAPTIVE = "adaptive"      # Dynamically adjust based on results
    HIERARCHICAL = "hierarchical"  # Parent-child task relationships


class OrchestrationMetrics(BaseModel):
    """Metrics for monitoring orchestration performance."""
    
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    average_task_duration: float = 0.0
    total_duration: float = 0.0
    parallel_efficiency: float = 0.0  # How well we utilized parallelism


class TaskDependencyGraph:
    """Manages task dependencies and execution order."""
    
    def __init__(self, tasks: List[TaskPlan]):
        self.tasks = {task.task_id: task for task in tasks}
        self.graph = self._build_dependency_graph()
        
    def _build_dependency_graph(self) -> Dict[str, List[str]]:
        """Build adjacency list representation of dependencies."""
        graph = {task_id: [] for task_id in self.tasks}
        
        for task_id, task in self.tasks.items():
            for dep in task.dependencies:
                if dep in graph:
                    graph[dep].append(task_id)
                    
        return graph
        
    def get_execution_levels(self) -> List[List[str]]:
        """Get tasks grouped by execution level (tasks in same level can run in parallel)."""
        levels = []
        completed = set()
        
        while len(completed) < len(self.tasks):
            current_level = []
            
            for task_id, task in self.tasks.items():
                if task_id not in completed:
                    # Check if all dependencies are completed
                    if all(dep in completed for dep in task.dependencies):
                        current_level.append(task_id)
                        
            if not current_level:
                # Circular dependency or error
                raise ValueError("Circular dependency detected in task graph")
                
            levels.append(current_level)
            completed.update(current_level)
            
        return levels
        
    def get_critical_path(self) -> List[str]:
        """Find the critical path (longest dependency chain)."""
        memo = {}
        
        def dfs(task_id: str) -> int:
            if task_id in memo:
                return memo[task_id]
                
            task = self.tasks[task_id]
            if not task.dependencies:
                memo[task_id] = 1
                return 1
                
            max_depth = 0
            for dep in task.dependencies:
                if dep in self.tasks:
                    max_depth = max(max_depth, dfs(dep))
                    
            memo[task_id] = max_depth + 1
            return max_depth + 1
            
        # Find task with maximum depth
        max_depth = 0
        critical_task = None
        
        for task_id in self.tasks:
            depth = dfs(task_id)
            if depth > max_depth:
                max_depth = depth
                critical_task = task_id
                
        # Reconstruct critical path
        path = []
        current = critical_task
        
        while current:
            path.append(current)
            task = self.tasks[current]
            
            # Find dependency with maximum depth
            next_task = None
            max_dep_depth = 0
            
            for dep in task.dependencies:
                if dep in self.tasks and dep in memo:
                    if memo[dep] > max_dep_depth:
                        max_dep_depth = memo[dep]
                        next_task = dep
                        
            current = next_task
            
        return list(reversed(path))


class AgentLoadBalancer:
    """Balances work across multiple agents of the same type."""
    
    def __init__(self):
        self.agent_queues: Dict[str, List[str]] = {}
        self.agent_workload: Dict[str, int] = {}
        
    def assign_task(self, task: TaskPlan, available_agents: List[str]) -> str:
        """Assign task to the least loaded agent of the appropriate type."""
        agent_type = task.agent_type
        
        # Filter agents by type
        suitable_agents = [a for a in available_agents if a.startswith(agent_type)]
        
        if not suitable_agents:
            # No suitable agent available, use default
            return agent_type
            
        # Find least loaded agent
        min_load = float('inf')
        selected_agent = suitable_agents[0]
        
        for agent in suitable_agents:
            load = self.agent_workload.get(agent, 0)
            if load < min_load:
                min_load = load
                selected_agent = agent
                
        # Update workload
        self.agent_workload[selected_agent] = self.agent_workload.get(selected_agent, 0) + 1
        
        return selected_agent
        
    def task_completed(self, agent: str):
        """Mark task as completed for load balancing."""
        if agent in self.agent_workload:
            self.agent_workload[agent] = max(0, self.agent_workload[agent] - 1)


class AdaptiveOrchestrator:
    """Orchestrator that adapts execution strategy based on results."""
    
    def __init__(self, initial_strategy: ExecutionStrategy = ExecutionStrategy.ADAPTIVE):
        self.strategy = initial_strategy
        self.metrics = OrchestrationMetrics()
        self.task_history: List[Dict[str, Any]] = []
        
    def should_retry_task(self, task: TaskPlan, error: Exception) -> bool:
        """Determine if a failed task should be retried."""
        # Simple retry logic - can be enhanced
        task_attempts = sum(1 for h in self.task_history 
                          if h['task_id'] == task.task_id and h['status'] == 'failed')
        
        # Retry up to 3 times for high priority tasks
        if task.priority == 1 and task_attempts < 3:
            return True
            
        # Retry once for medium priority
        if task.priority == 2 and task_attempts < 2:
            return True
            
        return False
        
    def adjust_strategy(self, task_results: Dict[str, Any]):
        """Adjust execution strategy based on performance metrics."""
        # Calculate success rate
        success_rate = (self.metrics.completed_tasks / 
                       max(1, self.metrics.completed_tasks + self.metrics.failed_tasks))
        
        # If high failure rate, switch to sequential for better debugging
        if success_rate < 0.7 and self.strategy == ExecutionStrategy.PARALLEL:
            self.strategy = ExecutionStrategy.SEQUENTIAL
            
        # If high success rate and currently sequential, try parallel
        elif success_rate > 0.9 and self.strategy == ExecutionStrategy.SEQUENTIAL:
            self.strategy = ExecutionStrategy.PARALLEL
            
    def get_fallback_agent(self, task: TaskPlan) -> Optional[str]:
        """Get a fallback agent if the primary agent fails."""
        fallback_map = {
            "browser": "manus",  # Manus can do basic web search
            "data_analysis": "manus",  # Manus can do basic analysis
            "mcp": "manus",  # Manus as general fallback
        }
        
        return fallback_map.get(task.agent_type)


def optimize_task_plan(tasks: List[TaskPlan]) -> List[TaskPlan]:
    """Optimize task plan for better execution efficiency."""
    # Create dependency graph
    graph = TaskDependencyGraph(tasks)
    
    # Get execution levels
    levels = graph.get_execution_levels()
    
    # Assign priorities based on level and critical path
    critical_path = graph.get_critical_path()
    
    optimized_tasks = []
    for task in tasks:
        # Higher priority for tasks on critical path
        if task.task_id in critical_path:
            task.priority = 1
        else:
            # Priority based on execution level
            for level_idx, level_tasks in enumerate(levels):
                if task.task_id in level_tasks:
                    task.priority = min(3, level_idx + 1)
                    break
                    
        optimized_tasks.append(task)
        
    return optimized_tasks