"""Enhanced task planning agent with additional Strands SDK best practices."""

import json
import re
import hashlib
import logging
from typing import Any, Dict, List, Optional, Union, Callable
from enum import Enum
from functools import lru_cache
from datetime import datetime

from pydantic import BaseModel, Field, field_validator
from strands.tools import tool

from ..agents.base import BaseManusAgent
from ..config import Config


class AgentType(str, Enum):
    """Available agent types for task routing."""
    MANUS = "manus"
    BROWSER = "browser"
    DATA_ANALYSIS = "data_analysis"
    MCP = "mcp"


AGENT_SYSTEM_PROMPTS = {
    AgentType.MANUS: (
        "You are a helpful AI assistant. Perform general computation, "
        "file operations, or code execution as requested."
    ),
    AgentType.BROWSER: (
        "You are an expert web browsing agent. "
        "Perform the requested web task autonomously."
    ),
    AgentType.DATA_ANALYSIS: (
        "You are a data analysis expert. Analyze the provided data "
        "and generate insights or visualizations."
    ),
    AgentType.MCP: (
        "You are an agent that interacts with external tools "
        "via the Model Context Protocol."
    )
}


class ComplexityLevel(str, Enum):
    """Task complexity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TaskStatus(str, Enum):
    """Task execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class TaskPlan(BaseModel):
    """Task plan with validation and smart defaults."""
    
    task_id: str = Field(..., description="Unique task identifier")
    description: str = Field(..., min_length=1, description="Clear task description")
    agent_type: AgentType = Field(..., description="Agent type for this task")
    dependencies: List[str] = Field(default_factory=list, description="Task dependencies")
    inputs: Dict[str, Any] = Field(default_factory=dict, description="Task inputs")
    expected_output: str = Field(..., description="Expected output description")
    priority: int = Field(default=1, ge=1, le=10, description="Task priority (1-10)")
    estimated_complexity: ComplexityLevel = Field(default=ComplexityLevel.MEDIUM)
    status: TaskStatus = Field(default=TaskStatus.PENDING, description="Current task status")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    @field_validator('task_id')
    @classmethod
    def validate_task_id(cls, v: str) -> str:
        """Ensure task_id follows naming convention."""
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError("task_id must contain only alphanumeric, dash, or underscore")
        return v
    
    @field_validator('dependencies')
    @classmethod
    def validate_dependencies(cls, v: List[str], info) -> List[str]:
        """Ensure no self-dependencies."""
        if 'task_id' in info.data and info.data['task_id'] in v:
            raise ValueError("Task cannot depend on itself")
        return v
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode='json')
    
    def can_execute(self, completed_tasks: List[str]) -> bool:
        """Check if task can be executed based on dependencies."""
        return all(dep in completed_tasks for dep in self.dependencies)


class PlanningMetrics(BaseModel):
    """Metrics for plan execution."""
    
    request_length: int
    task_count: int
    parallel_tasks: int
    max_depth: int
    planning_time_ms: float
    timestamp: datetime = Field(default_factory=datetime.now)


class PlanningAgent(BaseManusAgent):
    """Enhanced task planning agent with monitoring and optimization."""
    
    def __init__(
        self,
        model: Optional[Any] = None,
        config: Optional[Config] = None,
        max_tasks_per_plan: int = 20,
        enable_parallel_optimization: bool = True,
        enable_caching: bool = True,
        enable_metrics: bool = True,
        event_handler: Optional[Callable] = None,
        **kwargs
    ):
        """Initialize enhanced planning agent.
        
        Args:
            model: Language model instance
            config: Configuration object
            max_tasks_per_plan: Maximum tasks allowed in a single plan
            enable_parallel_optimization: Whether to optimize for parallel execution
            enable_caching: Whether to cache query analysis
            enable_metrics: Whether to collect planning metrics
            event_handler: Optional event handler for monitoring
            **kwargs: Additional arguments for base agent
        """
        self.max_tasks_per_plan = max_tasks_per_plan
        self.enable_parallel_optimization = enable_parallel_optimization
        self.enable_caching = enable_caching
        self.enable_metrics = enable_metrics
        self.event_handler = event_handler
        self._metrics_history: List[PlanningMetrics] = []
        
        # Initialize without tools - planning agent uses reasoning only
        super().__init__(
            tools=[],
            model=model,
            config=config,
            system_prompt=self._get_enhanced_system_prompt(),
            **kwargs
        )
    
    def _emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Emit an event for monitoring."""
        if self.event_handler:
            self.event_handler(event_type, data)
    
    def _get_enhanced_system_prompt(self) -> str:
        """Enhanced system prompt with detailed guidelines."""
        return f"""You are an expert task planning agent that orchestrates complex workflows by intelligently routing tasks to specialized agents.

## Core Responsibilities:
1. **Decompose**: Break complex requests into atomic, focused tasks
2. **Route**: Match each task to the most suitable agent based on expertise
3. **Optimize**: Identify dependencies and enable parallel execution
4. **Validate**: Ensure tasks are well-defined with clear inputs/outputs

## Available Agents:

### Manus Agent (type: "manus")
**Capabilities**: General computation, file operations, code execution, calculations
**Best for**: File I/O, running scripts, math operations, data processing
**Example tasks**: Write code, read files, execute Python, perform calculations

### Browser Agent (type: "browser") - Powered by browser-use
**Capabilities**: Autonomous web browsing, complex multi-step web tasks, intelligent form filling, dynamic content handling
**Best for**: Any web-based task, research, data extraction, complex web interactions
**Example tasks**: Research topics across multiple sites, fill complex forms, extract data from dynamic pages, navigate multi-step workflows

### Data Analysis Agent (type: "data_analysis")
**Capabilities**: Statistical analysis, visualization, ML operations, reporting
**Best for**: Data insights, chart creation, statistical tests, predictions
**Example tasks**: Analyze CSV, create plots, statistical summary, ML models

### MCP Agent (type: "mcp")
**Capabilities**: External tool integration via Model Context Protocol
**Best for**: Specialized tools, external services, custom integrations
**Example tasks**: Database queries, API calls, custom tool usage

## Planning Principles:

1. **Atomicity**: Each task should do ONE thing well
2. **Dependencies**: Only add dependencies when output of one task is needed as input for another
3. **Parallelism**: Tasks without dependencies can run simultaneously
4. **Clarity**: Task descriptions must be specific and actionable
5. **Efficiency**: Minimize total execution time through smart parallelization
6. **Idempotency**: Tasks should be safe to retry if they fail

## Output Format:

Generate a JSON array with max {self.max_tasks_per_plan} tasks:

```json
[
  {{
    "task_id": "unique_id",
    "description": "Specific action to perform",
    "agent_type": "manus|browser|data_analysis|mcp",
    "dependencies": [],
    "inputs": {{"param": "value"}},
    "expected_output": "What this task produces",
    "priority": 1,
    "estimated_complexity": "low|medium|high",
    "metadata": {{"retry_count": 0, "timeout_seconds": 300}}
  }}
]
```

## Important Rules:
- task_id must be unique and descriptive (e.g., "fetch_data", "analyze_results")
- dependencies array contains task_ids that must complete before this task
- inputs can reference outputs from dependencies using {{task_id.output}}
- priority: 1 (highest) to 10 (lowest), affects scheduling
- complexity helps estimate resource allocation
- metadata can include retry policies, timeouts, or other execution hints

Remember: The goal is to create an efficient, parallelizable plan that leverages each agent's strengths while ensuring reliability and clarity."""
    
    def create_plan(self, request: str) -> List[TaskPlan]:
        """Create an optimized execution plan with monitoring.
        
        Args:
            request: User's request or task description
            
        Returns:
            List of validated TaskPlan objects
        """
        start_time = datetime.now()
        
        # Emit planning started event
        self._emit_event("planning_started", {"request": request})
        
        # Check cache if enabled
        if self.enable_caching:
            cached_plan = self._get_cached_plan(request)
            if cached_plan:
                self._emit_event("planning_completed", {"source": "cache", "task_count": len(cached_plan)})
                return cached_plan
        
        prompt = f"""Analyze this request and create an optimal execution plan:

REQUEST: {request}

Requirements:
1. Decompose into specific, atomic tasks (max {self.max_tasks_per_plan})
2. Choose the best agent type for each task based on required capabilities
3. Identify true dependencies (only when output is needed as input)
4. Enable parallel execution where possible
5. Ensure each task has a clear, measurable output
6. Add appropriate metadata for execution hints

Generate the plan as a JSON array following the specified format."""

        # Get response from model
        response = self(prompt)
        
        # Extract and parse the plan
        tasks = self._parse_plan_response(response)
        
        # Validate plan coherence
        if not self._validate_plan_coherence(tasks):
            self._emit_event("planning_warning", {"reason": "coherence_check_failed"})
        
        # Collect metrics if enabled
        if self.enable_metrics:
            self._collect_planning_metrics(request, tasks, start_time)
        
        # Cache the plan if enabled
        if self.enable_caching and len(tasks) > 1:
            self._cache_plan(request, tasks)
        
        # Emit planning completed event
        self._emit_event("planning_completed", {
            "source": "generated",
            "task_count": len(tasks),
            "parallel_tasks": len([t for t in tasks if not t.dependencies])
        })
        
        return tasks
    
    def _parse_plan_response(self, response: Union[str, Any]) -> List[TaskPlan]:
        """Parse model response into TaskPlan objects with enhanced validation."""
        try:
            # Extract content from response
            content = response.content if hasattr(response, 'content') else str(response)
            
            # Find JSON array in response
            json_match = re.search(r'\[[\s\S]*\]', content)
            if not json_match:
                raise ValueError("No JSON array found in response")
            
            # Parse JSON
            tasks_data = json.loads(json_match.group())
            
            # Validate task count
            if len(tasks_data) > self.max_tasks_per_plan:
                self._emit_event("planning_warning", {
                    "reason": "task_limit_exceeded",
                    "requested": len(tasks_data),
                    "limit": self.max_tasks_per_plan
                })
                tasks_data = tasks_data[:self.max_tasks_per_plan]
            
            # Convert to TaskPlan objects with validation
            tasks = []
            task_ids = set()
            
            for i, task_data in enumerate(tasks_data):
                # Ensure unique task_id
                task_id = task_data.get('task_id', f'task_{i+1}')
                if task_id in task_ids:
                    task_id = f"{task_id}_{i+1}"
                task_ids.add(task_id)
                
                # Add default metadata if not present
                if 'metadata' not in task_data:
                    task_data['metadata'] = {
                        'retry_count': 0,
                        'timeout_seconds': 300
                    }
                
                # Create TaskPlan with validation
                task = TaskPlan(
                    task_id=task_id,
                    description=task_data.get('description', 'No description'),
                    agent_type=task_data.get('agent_type', AgentType.MANUS),
                    dependencies=task_data.get('dependencies', []),
                    inputs=task_data.get('inputs', {}),
                    expected_output=task_data.get('expected_output', 'Task output'),
                    priority=task_data.get('priority', 1),
                    estimated_complexity=task_data.get('estimated_complexity', ComplexityLevel.MEDIUM),
                    metadata=task_data.get('metadata', {})
                )
                
                # Validate dependencies exist
                invalid_deps = [d for d in task.dependencies if d not in task_ids]
                if invalid_deps:
                    self._emit_event("planning_warning", {
                        "reason": "invalid_dependencies",
                        "task_id": task_id,
                        "invalid_deps": invalid_deps
                    })
                    task.dependencies = [d for d in task.dependencies if d in task_ids]
                
                tasks.append(task)
            
            # Optimize if enabled
            if self.enable_parallel_optimization:
                tasks = self._optimize_for_parallel_execution(tasks)
            
            return tasks
            
        except Exception as e:
            self._emit_event("planning_error", {"error": str(e)})
            # Fallback to single task
            return self._create_fallback_plan(str(response))
    
    def _validate_plan_coherence(self, tasks: List[TaskPlan]) -> bool:
        """Validate that the plan is coherent and executable.
        
        Args:
            tasks: List of tasks to validate
            
        Returns:
            True if plan is coherent, False otherwise
        """
        # Check for circular dependencies
        def has_circular_deps(task_id: str, visited: set, rec_stack: set) -> bool:
            visited.add(task_id)
            rec_stack.add(task_id)
            
            task = next((t for t in tasks if t.task_id == task_id), None)
            if task:
                for dep in task.dependencies:
                    if dep not in visited:
                        if has_circular_deps(dep, visited, rec_stack):
                            return True
                    elif dep in rec_stack:
                        return True
            
            rec_stack.remove(task_id)
            return False
        
        visited = set()
        rec_stack = set()
        
        for task in tasks:
            if task.task_id not in visited:
                if has_circular_deps(task.task_id, visited, rec_stack):
                    return False
        
        return True
    
    def _optimize_for_parallel_execution(self, tasks: List[TaskPlan]) -> List[TaskPlan]:
        """Optimize task priorities for parallel execution with enhanced logic."""
        # Create dependency graph
        dep_graph = {task.task_id: task.dependencies for task in tasks}
        
        # Calculate depth and critical path
        depths = {}
        critical_paths = {}
        
        def get_depth_and_path(task_id: str) -> tuple[int, int]:
            if task_id in depths:
                return depths[task_id], critical_paths[task_id]
            
            deps = dep_graph.get(task_id, [])
            if not deps:
                depths[task_id] = 0
                critical_paths[task_id] = 1
            else:
                dep_depths = [get_depth_and_path(dep) for dep in deps]
                depths[task_id] = max(d[0] for d in dep_depths) + 1
                critical_paths[task_id] = max(d[1] for d in dep_depths) + 1
            
            return depths[task_id], critical_paths[task_id]
        
        # Update priorities based on depth and critical path
        for task in tasks:
            depth, path_length = get_depth_and_path(task.task_id)
            
            # Higher priority for tasks on critical path
            if path_length == max(critical_paths.values()):
                task.priority = 1
            else:
                # Prioritize by depth (earlier tasks get higher priority)
                task.priority = min(1 + depth, 10)
            
            # Add optimization metadata
            task.metadata['optimization'] = {
                'depth': depth,
                'critical_path_length': path_length,
                'is_critical': path_length == max(critical_paths.values())
            }
        
        return tasks
    
    def _get_cached_plan(self, request: str) -> Optional[List[TaskPlan]]:
        """Get cached plan for a request."""
        # Simple hash-based cache key
        cache_key = hashlib.md5(request.encode()).hexdigest()
        # In a real implementation, this would use a proper cache backend
        # For now, return None (no cache hit)
        return None
    
    def _cache_plan(self, request: str, tasks: List[TaskPlan]) -> None:
        """Cache a plan for future use."""
        # In a real implementation, this would store in a cache backend
        pass
    
    def _collect_planning_metrics(self, request: str, tasks: List[TaskPlan], start_time: datetime) -> None:
        """Collect metrics about the planning process."""
        planning_time = (datetime.now() - start_time).total_seconds() * 1000
        
        metrics = PlanningMetrics(
            request_length=len(request),
            task_count=len(tasks),
            parallel_tasks=len([t for t in tasks if not t.dependencies]),
            max_depth=max(t.metadata.get('optimization', {}).get('depth', 0) for t in tasks) if tasks else 0,
            planning_time_ms=planning_time
        )
        
        self._metrics_history.append(metrics)
        self._emit_event("metrics_collected", metrics.model_dump())
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of collected metrics."""
        if not self._metrics_history:
            return {"message": "No metrics collected yet"}
        
        return {
            "total_plans": len(self._metrics_history),
            "avg_task_count": sum(m.task_count for m in self._metrics_history) / len(self._metrics_history),
            "avg_planning_time_ms": sum(m.planning_time_ms for m in self._metrics_history) / len(self._metrics_history),
            "max_task_count": max(m.task_count for m in self._metrics_history),
            "total_tasks_planned": sum(m.task_count for m in self._metrics_history)
        }
    
    def _create_fallback_plan(self, request: str) -> List[TaskPlan]:
        """Create a simple fallback plan when parsing fails."""
        return [
            TaskPlan(
                task_id="fallback_task",
                description=request[:200] + "..." if len(request) > 200 else request,
                agent_type=AgentType.MANUS,
                dependencies=[],
                inputs={},
                expected_output="Completed the requested task",
                priority=1,
                estimated_complexity=ComplexityLevel.MEDIUM,
                metadata={"is_fallback": True}
            )
        ]
    
    @lru_cache(maxsize=100)
    def analyze_query_complexity(self, query: str) -> Dict[str, Any]:
        """Analyze the complexity and requirements of a query with caching."""
        if not self.enable_caching:
            return self._analyze_query_complexity_impl(query)
        
        return self._analyze_query_complexity_impl(query)
    
    def _analyze_query_complexity_impl(self, query: str) -> Dict[str, Any]:
        """Implementation of query complexity analysis."""
        prompt = f"""Analyze this query and provide insights:

QUERY: {query}

Provide:
1. Overall complexity (low/medium/high)
2. Required agent types
3. Estimated number of tasks
4. Key challenges
5. Recommended approach
6. Potential parallelization opportunities

Format as JSON."""

        response = self(prompt)
        
        try:
            content = response.content if hasattr(response, 'content') else str(response)
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                return json.loads(json_match.group())
        except Exception as e:
            logging.error(f"Error during query complexity analysis: {e}")
            pass
        
        return {
            "complexity": "medium",
            "required_agents": ["manus"],
            "estimated_tasks": 1,
            "challenges": ["Unable to analyze"],
            "approach": "Direct execution",
            "parallelization": "none"
        }


@tool
def create_task_plan_tool(request: str) -> List[Dict]:
    """Generates a structured task plan based on a user request.
    
    Args:
        request: The user's request or task description.
        
    Returns:
        A list of dictionaries, where each dictionary represents a task 
        with details like task_id, description, agent_type, dependencies, 
        inputs, and expected_output.
    """
    planning_agent = PlanningAgent()
    task_plans_pydantic = planning_agent.create_plan(request)
    
    processed_tasks = []
    for plan in task_plans_pydantic:
        task_dict = plan.model_dump()
        
        # Get system prompt for the agent type, defaulting to MANUS
        system_prompt_for_agent = AGENT_SYSTEM_PROMPTS.get(plan.agent_type, AGENT_SYSTEM_PROMPTS[AgentType.MANUS])
        task_dict['system_prompt'] = system_prompt_for_agent
        
        # Ensure description is populated (it should be from plan.description)
        # task_dict['description'] is already plan.description via model_dump()

        # Remove agent_type and inputs as per requirements
        if 'agent_type' in task_dict:
            del task_dict['agent_type']
        if 'inputs' in task_dict:
            del task_dict['inputs']
            
        processed_tasks.append(task_dict)
        
    return processed_tasks