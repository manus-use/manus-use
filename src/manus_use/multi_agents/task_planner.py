"""Planning agent for task decomposition - acts as intelligent orchestrator."""

import json
import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from ..agents.base import BaseManusAgent
from ..config import Config


class TaskPlan(BaseModel):
    """Represents a task plan with metadata for orchestration."""
    
    task_id: str
    description: str
    agent_type: str  # manus, browser, data_analysis, etc.
    dependencies: List[str] = []  # IDs of tasks this depends on
    inputs: Dict[str, Any] = {}
    expected_output: str
    priority: int = 1  # For prioritizing parallel tasks
    estimated_complexity: str = "medium"  # low, medium, high
    

class PlanningAgent(BaseManusAgent):
    """Intelligent orchestrator that routes tasks to specialized agents."""
    
    def __init__(
        self,
        model: Optional[Any] = None,
        config: Optional[Config] = None,
        **kwargs
    ):
        """Initialize planning agent."""
        super().__init__(
            tools=[],  # Planning agent doesn't need tools
            model=model,
            config=config,
            system_prompt=self._get_default_system_prompt(),
            **kwargs
        )
        
    def _get_default_system_prompt(self) -> str:
        """Get orchestrator system prompt."""
        return """You are an intelligent orchestrator agent responsible for analyzing complex queries and routing tasks to specialized agents. Your role is to:

1. **Analyze the Query**: Break down complex requests into discrete, manageable tasks
2. **Identify Required Expertise**: Determine which specialized agents are needed
3. **Plan Task Sequence**: Create an optimal execution plan with proper dependencies
4. **Route to Specialists**: Assign each task to the most appropriate agent

## Available Specialized Agents:

### 1. Manus Agent (agent_type: "manus")
- **Expertise**: General purpose, file operations, code execution, calculations
- **Use for**: Writing/reading files, running code, mathematical computations, general tasks

### 2. Browser Agent (agent_type: "browser")
- **Expertise**: Web browsing, information retrieval, web scraping
- **Use for**: Searching the web, extracting data from websites, online research

### 3. Data Analysis Agent (agent_type: "data_analysis")
- **Expertise**: Statistical analysis, data visualization, pattern recognition
- **Use for**: Analyzing datasets, creating charts, statistical computations

### 4. MCP Agent (agent_type: "mcp")
- **Expertise**: Integration with external MCP tools and services
- **Use for**: When specific MCP tools are required

## Planning Guidelines:

1. Break complex requests into atomic, focused tasks
2. Choose the agent whose expertise best matches each task
3. Identify task dependencies and enable parallel execution where possible
4. Ensure proper data flow between dependent tasks

## Output Format:

Create a JSON array of task plans with this structure:
```json
[
  {
    "task_id": "unique_identifier",
    "description": "Clear, specific description of what to do",
    "agent_type": "manus|browser|data_analysis|mcp",
    "dependencies": ["list", "of", "task_ids"],
    "inputs": {"key": "value"},
    "expected_output": "Description of expected result",
    "priority": 1,
    "estimated_complexity": "low|medium|high"
  }
]
```"""
        
    def create_plan(self, request: str) -> List[TaskPlan]:
        """Create an intelligent execution plan for the given request.
        
        Args:
            request: User's request/task description
            
        Returns:
            List of TaskPlan objects with proper routing and dependencies
        """
        # Use the agent to generate a plan
        prompt = f"""Analyze this request and create an execution plan:

REQUEST: {request}

Create a detailed plan that:
1. Breaks down the request into specific tasks
2. Routes each task to the most appropriate specialized agent
3. Identifies dependencies between tasks
4. Optimizes for parallel execution where possible

Output the plan as a JSON array following the format specified in your instructions."""

        response = self(prompt)
        
        # Parse the response to extract tasks
        try:
            content = response.content if hasattr(response, 'content') else str(response)
            
            # Find JSON array in the response
            json_match = re.search(r'\[[\s\S]*\]', content)
            if json_match:
                tasks_data = json.loads(json_match.group())
                
                # Convert to TaskPlan objects
                tasks = []
                for task_data in tasks_data:
                    task = TaskPlan(
                        task_id=task_data.get('task_id', f'task_{len(tasks)}'),
                        description=task_data.get('description', ''),
                        agent_type=task_data.get('agent_type', 'manus'),
                        dependencies=task_data.get('dependencies', []),
                        inputs=task_data.get('inputs', {}),
                        expected_output=task_data.get('expected_output', ''),
                        priority=task_data.get('priority', 1),
                        estimated_complexity=task_data.get('estimated_complexity', 'medium')
                    )
                    tasks.append(task)
                
                return tasks
                
        except Exception as e:
            print(f"Failed to parse plan: {e}")
            
        # Fallback to simple single-task plan
        return [
            TaskPlan(
                task_id="task_1",
                description=request,
                agent_type="manus",
                dependencies=[],
                inputs={},
                expected_output="Completed request"
            )
        ]