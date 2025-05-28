"""Refactored flow orchestrator for multi-agent coordination using Strands SDK patterns."""

import asyncio
import hashlib
import json 
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
import traceback # Import for detailed error logging

from strands import Agent as StrandsAgentAlias
from strands_tools.workflow import workflow
from ..config import Config
from .planning_agent import create_task_plan_tool 
# TaskPlan import removed as it's not directly used in this file's type hints anymore.
# create_task_plan_tool is assumed to return List[Dict]

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
        
        # pylint: disable=no-member 
        self.main_agent = StrandsAgentAlias(
            tools=[create_task_plan_tool, workflow],
            model=self.config.get_model() 
        )

    async def run_async(self, request: str) -> FlowResult:
        """Async version of run, using StrandsAgent and workflow tool.
        Assumes workflow_async(action='start',...) can be awaited for completion 
        and returns the final status object.
        """
        try:
            # Step 1: Generate the plan
            plan_generation_prompt = (
                f"You MUST use the create_task_plan_tool to generate a task plan for this request. "
                f"Do NOT respond with text, only call the tool. "
                f"Request: {request}"
            )
            # pylint: disable=not-callable
            # Check if the agent call returns a coroutine or a result directly
            plan_response = self.main_agent(plan_generation_prompt)
            if asyncio.iscoroutine(plan_response):
                plan_response = await plan_response
            # pylint: enable=not-callable

            # Extract content from the response
            task_list = None
            
            # Debug: log the response type and attributes
            import logging
            logging.info(f"Response type: {type(plan_response)}")
            logging.info(f"Response attributes: {dir(plan_response)}")
            
            # Since the agent is not properly storing tool results in state,
            # we'll call the planning tool directly
            from .planning_agent import create_task_plan_tool
            logging.info("Calling create_task_plan_tool directly...")
            task_list = create_task_plan_tool(request)
            logging.info(f"Got task list with {len(task_list)} tasks")

            if not task_list: # Ensure task_list is not empty after parsing
                return FlowResult(success=False, error="Planning tool returned an empty plan.")

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
            
            create_action_result = workflow_tool(tool=create_tool_use)
            if asyncio.iscoroutine(create_action_result):
                create_action_result = await create_action_result
                
            if isinstance(create_action_result, dict) and create_action_result.get("status") == "error":
                error_msg = create_action_result.get('content', [{}])[0].get('text', 'Unknown error')
                return FlowResult(success=False, error=f"Failed to create workflow: {error_msg}")

            # Step 2: Start the workflow AND AWAIT ITS COMPLETION
            start_tool_use = {
                "toolUseId": f"start_{workflow_id}",
                "input": {
                    "action": "start",
                    "workflow_id": workflow_id
                }
            }
            
            final_status_result = workflow_tool(tool=start_tool_use)
            if asyncio.iscoroutine(final_status_result):
                final_status_result = await final_status_result

            if not isinstance(final_status_result, dict):
                return FlowResult(success=False, error=f"Workflow execution returned unexpected result type: {str(final_status_result)[:200]}")

            # Get workflow status from the result
            if final_status_result.get("status") == "success":
                # The workflow completed successfully
                content = final_status_result.get("content", [{}])[0].get("text", "")
                return FlowResult(success=True, output=content)
            
            current_workflow_status = final_status_result.get("workflow_status")
            tasks_status_list = final_status_result.get("tasks", [])

            if current_workflow_status == "completed":
                final_task_id_in_plan = task_list[-1]['task_id'] if task_list else None
                result_content = "Workflow completed. No tasks in plan or result for last task not found."
                if final_task_id_in_plan:
                    for task_s in tasks_status_list:
                        if task_s.get('task_id') == final_task_id_in_plan and task_s.get('status') == 'completed':
                            result_content = str(task_s.get('result', 'Result not available for the final task.'))
                            break
                return FlowResult(success=True, output=result_content)
            
            elif current_workflow_status == "failed":
                failed_tasks_details = [
                    f"Task '{t.get('task_id', 'Unknown_ID')}' failed: {t.get('error', 'Unknown error')}" 
                    for t in tasks_status_list if t.get('status') == 'failed'
                ]
                error_msg = f"Workflow failed. Details: {'; '.join(failed_tasks_details) if failed_tasks_details else 'Unknown error.'}"
                return FlowResult(success=False, error=error_msg)
            else: 
                return FlowResult(success=False, error=f"Workflow {workflow_id} ended with status: {current_workflow_status}. Full status: {str(final_status_result)[:500]}")

        except Exception as e:
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