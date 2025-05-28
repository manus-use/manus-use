"""Refactored flow orchestrator for multi-agent coordination using Strands SDK patterns."""

import asyncio
import hashlib
import json
import re # Added for TaskPlan validation
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
import traceback # Import for detailed error logging
from enum import Enum # Added for new enums

from pydantic import BaseModel, Field, field_validator # Added for TaskPlan
from strands import Agent as StrandsAgentAlias
from strands_tools.workflow import workflow
from ..config import Config
# create_task_plan_tool removed as it's no longer used directly


# Copied from planning_agent.py
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


# End of copied components

@dataclass
class FlowResult:
    """Result from flow execution."""
    success: bool
    output: str = ""
    error: Optional[str] = None

class Orchestrator:
    """Orchestrates multi-agent workflows using StrandsAgent and workflow tool."""
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize orchestrator.
        
        Args:
            config: Configuration object
        """
        self.config = config or Config.from_file()
        self.max_tasks_per_plan = 20 # Max tasks per plan
        
        # pylint: disable=no-member 
        # The main_agent is used for its LLM, not for its tools here.
        # Tools for the workflow are called directly.
        self.main_agent = StrandsAgentAlias(
            tools=[], # No tools needed for this agent's direct LLM call
            model=self.config.get_model() 
        )

    async def _generate_plan_with_llm(self, request: str) -> List[Dict]:
        """Generates a task plan using the LLM."""
        system_prompt = f"""You are an expert task planning agent that orchestrates complex workflows by intelligently routing tasks to specialized agents.

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
- inputs can reference outputs from dependencies using {{{{task_id.output}}}} (double curly braces for JSON string)
- priority: 1 (highest) to 10 (lowest), affects scheduling
- complexity helps estimate resource allocation
- metadata can include retry policies, timeouts, or other execution hints

Remember: The goal is to create an efficient, parallelizable plan that leverages each agent's strengths while ensuring reliability and clarity."""

        full_prompt = f"{system_prompt}\n\nAnalyze this request and create an optimal execution plan:\n\nREQUEST: {request}"
        
        import logging # Local import for logging within this method
        logging.info("Generating plan with LLM...")

        try:
            # pylint: disable=not-callable
            llm_response = self.main_agent(full_prompt)
            if asyncio.iscoroutine(llm_response):
                llm_response = await llm_response
            # pylint: enable=not-callable
            
            response_content = llm_response.content if hasattr(llm_response, 'content') else str(llm_response)
            
            json_match = re.search(r'\[[\s\S]*\]', response_content)
            if not json_match:
                logging.error("No JSON array found in LLM response.")
                # Fallback: create a single task for the entire request
                return [
                    {
                        'task_id': f"fallback_task_{hashlib.md5(request.encode()).hexdigest()[:6]}",
                        'description': request,
                        'dependencies': [],
                        'system_prompt': AGENT_SYSTEM_PROMPTS[AgentType.MANUS], # Default to MANUS
                        'priority': 1,
                        'metadata': {"fallback": True}
                    }
                ]
            
            parsed_tasks_data = json.loads(json_match.group())
            
            if not isinstance(parsed_tasks_data, list):
                logging.error("Parsed JSON is not a list.")
                return []

            if len(parsed_tasks_data) > self.max_tasks_per_plan:
                logging.warning(f"LLM generated too many tasks ({len(parsed_tasks_data)}), truncating to {self.max_tasks_per_plan}.")
                parsed_tasks_data = parsed_tasks_data[:self.max_tasks_per_plan]

            workflow_tasks = []
            for task_data in parsed_tasks_data:
                if not isinstance(task_data, dict):
                    logging.warning(f"Skipping invalid task data (not a dict): {task_data}")
                    continue

                # Validate with TaskPlan pydantic model (optional, but good practice)
                try:
                    # Fill in missing enum defaults if string is provided by LLM
                    if isinstance(task_data.get('agent_type'), str) and not isinstance(task_data.get('agent_type'), AgentType):
                         task_data['agent_type'] = AgentType(task_data['agent_type'].lower())
                    if isinstance(task_data.get('estimated_complexity'), str) and not isinstance(task_data.get('estimated_complexity'), ComplexityLevel):
                        task_data['estimated_complexity'] = ComplexityLevel(task_data['estimated_complexity'].lower())
                    
                    task_plan = TaskPlan(**task_data)
                except Exception as e: # Catch Pydantic validation error or other issues
                    logging.warning(f"Skipping task due to validation error: {e}. Task data: {task_data}")
                    continue
                
                task_id = task_plan.task_id
                if not task_id: # Should be caught by pydantic, but as a safeguard
                    task_id = f"gen_task_{hashlib.md5(task_plan.description.encode()).hexdigest()[:6]}"
                
                system_prompt_for_agent = AGENT_SYSTEM_PROMPTS.get(
                    task_plan.agent_type, 
                    AGENT_SYSTEM_PROMPTS[AgentType.MANUS] # Default if unknown
                )
                
                workflow_task_dict = {
                    'task_id': task_id,
                    'description': task_plan.description,
                    'dependencies': task_plan.dependencies,
                    'system_prompt': system_prompt_for_agent,
                    'priority': task_plan.priority,
                    'metadata': task_plan.metadata
                }
                workflow_tasks.append(workflow_task_dict)
            
            return workflow_tasks

        except json.JSONDecodeError as e:
            logging.error(f"JSON parsing failed: {e}. Response content: {response_content[:500]}") # Log first 500 chars
            return []
        except Exception as e:
            logging.error(f"Error generating plan with LLM: {e}\n{traceback.format_exc()}")
            return []


    async def run_async(self, request: str) -> FlowResult:
        """Async version of run, using StrandsAgent and workflow tool."""
        try:
            # Step 1: Generate the plan using the new LLM-based method
            import logging # Ensure logging is imported if not already global
            logging.info(f"Orchestrator: Generating plan for request: {request[:100]}...")
            task_list = await self._generate_plan_with_llm(request)
            
            if not task_list:
                logging.error("Plan generation failed or returned an empty plan.")
                return FlowResult(success=False, error="LLM failed to generate a valid task plan.")

            logging.info(f"Orchestrator: Plan generated with {len(task_list)} tasks.")
            workflow_id = "wf_async_" + hashlib.md5(request.encode()).hexdigest()[:10]

            # Import the workflow tool directly
            from strands_tools.workflow import workflow as workflow_tool

            # Create the workflow - construct the tool use object
            create_tool_use = {
                "toolUseId": f"create_{workflow_id}",
                "input": {
                    "action": "create",
                    "workflow_id": workflow_id,
                    "tasks": task_list
                }
            }
            
            # Ensure workflow_tool is treated as a function that might be async or sync
            # Forcing it to be async for now, as workflow operations can be I/O bound
            create_action_result_maybe_coro = workflow_tool(tool=create_tool_use)
            if asyncio.iscoroutine(create_action_result_maybe_coro):
                create_action_result = await create_action_result_maybe_coro
            else:
                create_action_result = create_action_result_maybe_coro # Assuming it's already a result
                
            if isinstance(create_action_result, dict) and create_action_result.get("status") == "error":
                error_msg = create_action_result.get('content', [{}])[0].get('text', 'Unknown error creating workflow')
                logging.error(f"Failed to create workflow: {error_msg}")
                return FlowResult(success=False, error=f"Failed to create workflow: {error_msg}")
            elif not (isinstance(create_action_result, dict) and create_action_result.get("status") == "success"):
                 logging.error(f"Workflow creation returned unexpected result: {str(create_action_result)[:200]}")
                 return FlowResult(success=False, error=f"Workflow creation returned unexpected result: {str(create_action_result)[:200]}")


            logging.info(f"Orchestrator: Workflow {workflow_id} created. Starting execution...")
            # Step 2: Start the workflow AND AWAIT ITS COMPLETION
            start_tool_use = {
                "toolUseId": f"start_{workflow_id}",
                "input": {
                    "action": "start", # This should ideally be 'run' or 'execute_and_poll'
                    "workflow_id": workflow_id
                }
            }
            
            final_status_result_maybe_coro = workflow_tool(tool=start_tool_use)
            if asyncio.iscoroutine(final_status_result_maybe_coro):
                final_status_result = await final_status_result_maybe_coro
            else:
                final_status_result = final_status_result_maybe_coro


            if not isinstance(final_status_result, dict):
                logging.error(f"Workflow execution returned unexpected result type: {str(final_status_result)[:200]}")
                return FlowResult(success=False, error=f"Workflow execution returned unexpected result type: {str(final_status_result)[:200]}")

            logging.info(f"Orchestrator: Workflow {workflow_id} execution finished. Final status: {final_status_result.get('workflow_status')}")
            
            current_workflow_status = final_status_result.get("workflow_status")
            tasks_status_list = final_status_result.get("tasks", [])

            if current_workflow_status == "completed":
                final_task_id_in_plan = task_list[-1]['task_id'] if task_list else None
                result_content = "Workflow completed. Final result not found or plan was empty."
                if final_task_id_in_plan:
                    for task_s in tasks_status_list:
                        if task_s.get('task_id') == final_task_id_in_plan and task_s.get('status') == 'completed':
                            result_content = str(task_s.get('result', 'Result not available for the final task.'))
                            break
                logging.info(f"Orchestrator: Workflow {workflow_id} completed successfully. Output: {result_content[:100]}")
                return FlowResult(success=True, output=result_content)
            
            elif current_workflow_status == "failed":
                failed_tasks_details = [
                    f"Task '{t.get('task_id', 'Unknown_ID')}' failed: {t.get('error', 'Unknown error')}" 
                    for t in tasks_status_list if t.get('status') == 'failed'
                ]
                error_msg = f"Workflow failed. Details: {'; '.join(failed_tasks_details) if failed_tasks_details else 'Unknown error.'}"
                logging.error(f"Orchestrator: Workflow {workflow_id} failed. Error: {error_msg}")
                return FlowResult(success=False, error=error_msg)
            else: 
                logging.warning(f"Orchestrator: Workflow {workflow_id} ended with unhandled status: {current_workflow_status}. Full status: {str(final_status_result)[:500]}")
                return FlowResult(success=False, error=f"Workflow {workflow_id} ended with status: {current_workflow_status}. Full status: {str(final_status_result)[:500]}")

        except Exception as e:
            logging.error(f"An unexpected error occurred in run_async: {str(e)}\n{traceback.format_exc()}")
            return FlowResult(success=False, error=f"An unexpected error occurred in run_async: {str(e)}\n{traceback.format_exc()}")

    def run(self, request: str) -> FlowResult:
        """Synchronous version of run.
        
        This will execute the async workflow and block until completion.
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                raise RuntimeError("Current event loop is closed.")
        except RuntimeError: 
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(self.run_async(request))