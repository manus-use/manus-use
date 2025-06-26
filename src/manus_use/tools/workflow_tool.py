"""Custom workflow tool that supports ManusUse agent types."""

import asyncio
import json
import logging
import uuid
from typing import Any, Dict

from strands.types.tools import ToolResult, ToolUse
from strands_tools.workflow import (
    WorkflowManager,WORKFLOW_DIR, TOOL_SPEC as BASE_TOOL_SPEC
)

from manus_use.agents import ManusAgent, BrowserUseAgent, DataAnalysisAgent, MCPAgent
from manus_use.config import Config

logger = logging.getLogger(__name__)

# Copy the tool spec from base but customize description
TOOL_SPEC = json.loads(json.dumps(BASE_TOOL_SPEC))
TOOL_SPEC["name"] = "workflow_tool"
TOOL_SPEC["description"] = TOOL_SPEC["description"] + """
This version supports ManusUse agent types:
- manus: General computation and file operations
- browser: Web browsing using browser-use
- data_analysis: Data analysis and visualization
- mcp: Model Context Protocol tools
"""

# Add agent_type to the task schema
TOOL_SPEC["inputSchema"]["json"]["properties"]["tasks"]["items"]["properties"]["agent_type"] = {
    "type": "string",
    "enum": ["manus", "browser", "data_analysis", "mcp"],
    "description": "Agent type to use for executing this task (defaults to 'manus')",
    "default": "manus"
}

class ManusWorkflowManager(WorkflowManager):
    """Extended workflow manager that supports ManusUse agent types."""
    
    def __init__(self, tool_context: Dict[str, Any]):
        """Initialize with agent registry."""
        super().__init__(tool_context)
        
        # Get config from tool context
        self.config = Config.from_file()
        
        # Initialize agent registry
        self.agent_registry = {
            "manus": ManusAgent,
            "browser": BrowserUseAgent,
            "data_analysis": DataAnalysisAgent,
            "mcp": MCPAgent
        }
        
        # Cache for agent instances
        self.agent_instances = {}
        
    def get_agent_for_task(self, task: Dict) -> Any:
        """Get the appropriate agent for a task based on agent_type."""
        agent_type = task.get("agent_type", "manus")
        
        # Check cache first
        if agent_type in self.agent_instances:
            return self.agent_instances[agent_type]
            
        # Create new agent instance
        agent_class = self.agent_registry.get(agent_type)
        if not agent_class:
            logger.warning(f"Unknown agent type: {agent_type}, using ManusAgent")
            agent_class = ManusAgent
            
        # Create agent with system prompt if provided
        system_prompt = task.get("system_prompt")
        if system_prompt:
            agent = agent_class(config=self.config, system_prompt=system_prompt)
        else:
            agent = agent_class(config=self.config)
            
        # Cache the instance
        self.agent_instances[agent_type] = agent
        return agent
        
    def execute_task(self, task: Dict, workflow: Dict, tool_use_id: str) -> Dict:
        """Execute a single task using the appropriate agent."""
        try:
            # Build context from dependent tasks
            context = []
            if task.get("dependencies"):
                for dep_id in task["dependencies"]:
                    dep_result = workflow["task_results"].get(dep_id, {})
                    if dep_result.get("status") == "completed" and dep_result.get("result"):
                        # Format the dependency results
                        dep_content = [msg.get("text", "") for msg in dep_result["result"]]
                        context.append(f"Results from {dep_id}:\n" + "\n".join(dep_content))

            # Build comprehensive task prompt with context
            task_prompt = task["description"]
            if context:
                task_prompt = "Previous task results:\n" + "\n\n".join(context) + "\n\nTask:\n" + task_prompt

            # Get the appropriate agent for this task
            agent = self.get_agent_for_task(task)
            
            # Execute task using the agent
            potential_coroutine = agent(task_prompt) # This might be a coroutine or a direct result

            actual_result: Any # Define type for clarity
            if asyncio.iscoroutine(potential_coroutine):
                logger.info(f"Task {task.get('task_id', 'unknown')} returned a coroutine, running it to completion.")
                try:
                    loop = asyncio.get_running_loop()
                    # If loop is running, use run_until_complete.
                    # This will block execute_task until the coroutine is done.
                    actual_result = loop.run_until_complete(potential_coroutine)
                except RuntimeError:
                    # No event loop is currently running, or other asyncio.run() related issue.
                    # Use asyncio.run() to create one and run the coroutine.
                    logger.info(f"No running loop for task {task.get('task_id', 'unknown')}, using asyncio.run().")
                    actual_result = asyncio.run(potential_coroutine)
            else:
                logger.info(f"Task {task.get('task_id', 'unknown')} returned a direct result.")
                actual_result = potential_coroutine

            # Now 'actual_result' holds the actual result from the agent call.
            processed_content = []
            # Default stop_reason, can be overridden if actual_result provides it
            stop_reason_str = "completed"

            if isinstance(actual_result, str):
                logger.info(f"Task {task.get('task_id', 'unknown')} returned a string result. Wrapping it.")
                # Ensure actual_result is not None before assigning to text
                processed_content = [{"text": actual_result if actual_result is not None else ""}]
            elif hasattr(actual_result, "get"):  # Check if dict-like (e.g., a Strands ToolResult dict)
                logger.info(f"Task {task.get('task_id', 'unknown')} returned a dict-like result.")
                # Attempt to get 'content' which might be a list of message dicts, or a string, or other
                raw_content = actual_result.get("content")
                if isinstance(raw_content, list): # Expecting list of message dicts e.g. [{"text": "..."}]
                    processed_content = raw_content
                elif isinstance(raw_content, str): # If content itself is a string
                     processed_content = [{"text": raw_content if raw_content is not None else ""}]
                elif raw_content is None:
                    processed_content = []
                else: # Some other type, wrap its string representation
                    processed_content = [{"text": str(raw_content)}]

                stop_reason_str = actual_result.get("stop_reason", "completed")
            elif type(actual_result).__name__ == "AgentResult": # Explicitly check for AgentResult by class name
                logger.info(f"Task {task.get('task_id', 'unknown')} returned an AgentResult.")
                if hasattr(actual_result, "content") and isinstance(actual_result.content, list):
                    # Assuming .content is like [{'type': 'text', 'text': '...'}]
                    processed_content = actual_result.content
                elif hasattr(actual_result, "text") and isinstance(actual_result.text, str):
                    processed_content = [{"text": actual_result.text}]
                else:
                    # Fallback if AgentResult doesn't have .content as list or .text as string
                    processed_content = [{"text": str(actual_result)}]

                if hasattr(actual_result, "stop_reason") and actual_result.stop_reason is not None:
                    stop_reason_str = str(actual_result.stop_reason)

            elif hasattr(actual_result, "content"):  # Check if object with .content attribute (for other types)
                logger.info(f"Task {task.get('task_id', 'unknown')} returned an object with .content attribute.")
                raw_object_content = getattr(actual_result, "content", None)
                if isinstance(raw_object_content, list):
                    processed_content = raw_object_content
                elif isinstance(raw_object_content, str):
                    processed_content = [{"text": raw_object_content if raw_object_content is not None else ""}]
                elif raw_object_content is None:
                    processed_content = []
                else:
                    processed_content = [{"text": str(raw_object_content)}]

                if hasattr(actual_result, "stop_reason"): # Ensure stop_reason is checked for these types too
                    stop_reason_value = getattr(actual_result, "stop_reason", "completed")
                    stop_reason_str = str(stop_reason_value) if stop_reason_value is not None else "completed"
            elif actual_result is None:
                logger.info(f"Task {task.get('task_id', 'unknown')} returned None. Resulting in empty content.")
                processed_content = []
            else:
                # Fallback for truly unexpected result types
                logger.warning(f"Task {task.get('task_id', 'unknown')} returned an unhandled result type: {type(actual_result)}. Converting to string.")
                processed_content = [{"text": str(actual_result)}]

            # Determine status based on stop_reason_str or presence of error indicators
            # (This part of status determination can be refined if there are specific error formats)
            status = "error" if stop_reason_str == "error" else "success"
            # Example: if processed_content itself indicates error:
            # if any(item.get("type") == "error" for item in processed_content):
            #     status = "error"

            return {
                "toolUseId": tool_use_id, # Assuming tool_use_id is defined earlier in the method
                "status": status,
                "content": processed_content,
            }

        except Exception as e:
            error_msg = f"Error executing task {task['task_id']}: {str(e)}"
            logger.error(f"\nError: {error_msg}")
            return {"status": "error", "content": [{"text": error_msg}]}

def workflow_tool(tool: ToolUse, **kwargs: Any) -> ToolResult:
    """ManusUse-aware workflow tool implementation.
    
    This tool extends the base workflow tool with support for ManusUse agent types:
    - manus: General computation and file operations
    - browser: Web browsing using browser-use
    - data_analysis: Data analysis and visualization
    - mcp: Model Context Protocol tools
    
    Each task can specify an agent_type to route to the appropriate agent.
    """
    system_prompt = kwargs.get("system_prompt")
    inference_config = kwargs.get("inference_config")
    messages = kwargs.get("messages")
    tool_config = kwargs.get("tool_config")

    try:
        tool_use_id = tool.get("toolUseId", str(uuid.uuid4()))
        tool_input = tool.get("input", {})
        action = tool_input.get("action")

        print("==========================")
        print(tool_input)

        # Initialize workflow manager
        manager = ManusWorkflowManager(
            {
                "system_prompt": system_prompt,
                "inference_config": inference_config,
                "messages": messages,
                "tool_config": tool_config,
            }
        )

        if action == "create":
            workflow_id = tool_input.get("workflow_id", str(uuid.uuid4()))
            if not tool_input.get("tasks"):
                return {
                    "toolUseId": tool_use_id,
                    "status": "error",
                    "content": [{"text": "Tasks are required for create action"}],
                }

            result = manager.create_workflow(workflow_id, tool_input["tasks"], tool_use_id)

        elif action == "start":
            if not tool_input.get("workflow_id"):
                return {
                    "toolUseId": tool_use_id,
                    "status": "error",
                    "content": [{"text": "workflow_id is required for start action"}],
                }

            result = manager.start_workflow(tool_input["workflow_id"], tool_use_id)

        elif action == "list":
            result = manager.list_workflows(tool_use_id)

        elif action == "status":
            if not tool_input.get("workflow_id"):
                return {
                    "toolUseId": tool_use_id,
                    "status": "error",
                    "content": [{"text": "workflow_id is required for status action"}],
                }

            result = manager.get_workflow_status(tool_input["workflow_id"], tool_use_id)

        elif action == "delete":
            if not tool_input.get("workflow_id"):
                return {
                    "toolUseId": tool_use_id,
                    "status": "error",
                    "content": [{"text": "workflow_id is required for delete action"}],
                }

            result = manager.delete_workflow(tool_input["workflow_id"], tool_use_id)

        else:
            return {
                "toolUseId": tool_use_id,
                "status": "error",
                "content": [{"text": f"Unknown action: {action}"}],
            }

        return {
            "toolUseId": tool_use_id,
            "status": result["status"],
            "content": result["content"],
        }

    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        error_msg = f"Error: {str(e)}\n\nTraceback:\n{error_trace}"
        logger.error(f"\nError in workflow tool: {error_msg}")
        return {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": error_msg}],
        }