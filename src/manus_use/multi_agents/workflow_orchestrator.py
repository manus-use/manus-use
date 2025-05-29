import asyncio
import hashlib # Added
import logging
from typing import Any, Dict, Optional, List # Added List

from strands import Agent as StrandsAgent
from strands_tools.workflow import workflow # Added

from src.manus_use.agents.manus import ManusAgent
from src.manus_use.agents.browser_use_agent import BrowserUseAgent
from src.manus_use.config import Config
from src.manus_use.multi_agents.planning_agent import create_task_plan_tool, AgentType # Added


# Global config cache to avoid reloading config.toml multiple times
config_cache: Optional[Config] = None

def get_workflow_config() -> Config:
    """Retrieves and caches the global configuration for workflow tasks."""
    global config_cache
    if config_cache is None:
        logging.info("Loading configuration for workflow tasks...")
        config_cache = Config.from_file()
        if config_cache:
            logging.info(f"Config loaded. LLM provider: {config_cache.llm.provider}")
        else:
            logging.error("Failed to load configuration. Default config will be used by agents if they support it.")
            config_cache = Config() 
    return config_cache

def run_manus_agent_task(query: str, task_inputs: Optional[Dict[str, Any]] = None) -> str:
    """
    Callable function to execute a ManusAgent task.
    """
    logging.info(f"Executing ManusAgent task with query: {query}")
    if task_inputs:
        logging.info(f"Additional task inputs: {task_inputs}")
        # query = query.format(**task_inputs) # Example if query is a template

    try:
        cfg = get_workflow_config()
        manus_agent = ManusAgent(config=cfg) 
        response = manus_agent(query)
        
        if asyncio.iscoroutine(response):
            try:
                loop = asyncio.get_running_loop()
                response_str = loop.run_until_complete(response)
            except RuntimeError: 
                response_str = asyncio.run(response)
        else:
            response_str = str(response)

        logging.info(f"ManusAgent task completed. Result: {response_str[:200]}...")
        return response_str
    except Exception as e:
        logging.error(f"Error during ManusAgent task execution: {e}", exc_info=True)
        return f"Error in ManusAgent: {str(e)}"

def run_browser_agent_task(query: str, task_inputs: Optional[Dict[str, Any]] = None) -> str:
    """
    Callable function to execute a BrowserUseAgent task.
    """
    logging.info(f"Executing BrowserUseAgent task with query: {query}")
    if task_inputs:
        logging.info(f"Additional task inputs: {task_inputs}")
        # query = query.format(**task_inputs)

    try:
        cfg = get_workflow_config()
        browser_agent = BrowserUseAgent(config=cfg)
        response = browser_agent(query)

        if asyncio.iscoroutine(response):
            try:
                loop = asyncio.get_running_loop()
                response_str = loop.run_until_complete(response)
            except RuntimeError: 
                response_str = asyncio.run(response)
        else:
            response_str = str(response)

        logging.info(f"BrowserUseAgent task completed. Result: {response_str[:200]}...")
        return response_str
    except ImportError as e:
        logging.error(f"ImportError for BrowserUseAgent: {e}. 'browser-use' or its LLM dependencies might be missing.")
        return f"BrowserUseAgent is not available due to missing dependencies: {str(e)}"
    except Exception as e:
        logging.error(f"Error during BrowserUseAgent task execution: {e}", exc_info=True)
        return f"Error in BrowserUseAgent: {str(e)}"


class WorkflowOrchestrator(StrandsAgent):
    """
    Orchestrates multi-agent workflows using a planning agent to generate tasks
    and the Strands Workflow tool to execute them.
    Tasks are mapped to specific Python functions (run_manus_agent_task, run_browser_agent_task).
    """

    def __init__(self, config: Optional[Config] = None, **kwargs: Any):
        """
        Initialize WorkflowOrchestrator.

        Args:
            config: Configuration object. If None, loaded via get_workflow_config().
            **kwargs: Additional arguments for the base StrandsAgent.
        """
        self.config = config or get_workflow_config()
        
        agent_tools = [create_task_plan_tool, workflow]

        system_prompt = (
            "You are a workflow orchestrator. Your primary role is to take a user request, "
            "use the 'create_task_plan_tool' to generate a detailed plan of tasks, "
            "and then use the 'workflow' tool to execute this plan. "
            "Ensure the plan is created first, then initiate the workflow."
        )

        super().__init__(
            model=self.config.get_model(), 
            tools=agent_tools,
            system_prompt=system_prompt,
            **kwargs
        )

    def _adapt_planned_tasks_for_workflow(self, planned_tasks: List[Dict]) -> List[Dict]:
        """
        Adapts tasks from create_task_plan_tool to be compatible with a workflow
        tool that can execute specified Python callables.
        """
        adapted_tasks = []
        for task in planned_tasks:
            agent_type_str = task.get("agent_type", AgentType.MANUS.value) 
            description = task.get("description", "")
            
            callable_path = ""
            if agent_type_str == AgentType.MANUS.value:
                callable_path = "src.manus_use.multi_agents.workflow_orchestrator.run_manus_agent_task"
            elif agent_type_str == AgentType.BROWSER.value:
                callable_path = "src.manus_use.multi_agents.workflow_orchestrator.run_browser_agent_task"
            else:
                logging.warning(f"Unsupported agent_type '{agent_type_str}' for task '{task.get('task_id')}'. Skipping.")
                continue

            adapted_task = {
                "task_id": task.get("task_id", f"task_{hashlib.md5(description.encode()).hexdigest()[:6]}"),
                "description": description, 
                "dependencies": task.get("dependencies", []),
                "priority": task.get("priority", 1),
                "metadata": task.get("metadata", {}),
                "callable_path": callable_path,
                "arguments": { 
                    "query": description, 
                }
            }
            adapted_tasks.append(adapted_task)
        return adapted_tasks

    async def run_workflow_for_request(self, user_request: str) -> Dict[str, Any]:
        """
        Processes a user request by generating a task plan and executing it as a workflow.
        """
        logging.info(f"WorkflowOrchestrator: Received request: {user_request}")
        
        logging.info("Generating task plan directly using create_task_plan_tool...")
        # Directly call the tool function for planning for reliability
        raw_planned_tasks: List[Dict] = create_task_plan_tool(request=user_request)

        if not raw_planned_tasks:
            logging.error("Planning phase did not return any tasks.")
            return {"status": "error", "message": "No tasks generated by the planning phase."}
        
        logging.info(f"Raw planned tasks: {raw_planned_tasks}")

        adapted_tasks = self._adapt_planned_tasks_for_workflow(raw_planned_tasks)

        if not adapted_tasks:
            logging.error("No tasks could be adapted for workflow execution.")
            return {"status": "error", "message": "Failed to adapt planned tasks for workflow."}
        
        logging.info(f"Adapted tasks for workflow: {adapted_tasks}")

        workflow_id = "wf_" + hashlib.md5(user_request.encode()).hexdigest()[:10]
        
        create_workflow_input = {
            "action": "create",
            "workflow_id": workflow_id,
            "tasks": adapted_tasks
        }
        logging.info(f"Creating workflow '{workflow_id}' with tasks: {adapted_tasks}")
        
        # Directly call the workflow tool function
        create_response = workflow(tool={"toolUseId": "tool_create_wf", "input": create_workflow_input})
        if asyncio.iscoroutine(create_response):
            create_response = await create_response
            
        logging.info(f"Workflow creation response: {create_response}")

        # Check for errors in creation response (simplified check)
        # The actual structure of create_response from workflow tool might vary.
        # This assumes a dict with "status" or looks for known error indicators.
        if isinstance(create_response, dict) and (create_response.get("status") == "error" or "error" in str(create_response).lower()):
             # More robust error extraction if create_response is a list of content items
            error_message = "Unknown error during workflow creation"
            if isinstance(create_response.get("content"), list) and create_response["content"]:
                error_details = create_response["content"][0].get("text", error_message)
                if isinstance(error_details, dict): # If text itself is a dict
                    error_message = error_details.get("message", str(error_details))
                else:
                    error_message = str(error_details)
            elif "message" in create_response:
                 error_message = create_response["message"]
            logging.error(f"Failed to create workflow: {error_message}")
            return {"status": "error", "message": f"Workflow creation failed: {error_message}"}
        elif not isinstance(create_response, dict) or not create_response.get("workflow_id"): # Simple check for success
            logging.error(f"Workflow creation did not return expected success response: {create_response}")
            return {"status": "error", "message": "Workflow creation failed or returned unexpected response."}


        start_workflow_input = {
            "action": "start",
            "workflow_id": workflow_id
        }
        logging.info(f"Starting workflow '{workflow_id}'")
        
        run_response = workflow(tool={"toolUseId": "tool_start_wf", "input": start_workflow_input})
        if asyncio.iscoroutine(run_response):
            run_response = await run_response
            
        logging.info(f"Workflow run response: {run_response}")
        
        return run_response


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    print("WorkflowOrchestrator class defined. Callable task functions also defined.")
    print("Run this file directly with uncommented examples in main to test (requires setup).")
    
    # Example of how to test run_workflow_for_request (requires async context and setup)
    # async def test_orchestrator():
    #     orchestrator = WorkflowOrchestrator()
    #     test_request = "Research the capital of Germany and then find a good recipe for Black Forest cake."
    #     result = await orchestrator.run_workflow_for_request(test_request)
    #     print("\n--- WorkflowOrchestrator Test ---")
    #     print(f"Request: {test_request}")
    #     print(f"Result: {result}")

    # if True: # Set to true to run the test
    #    asyncio.run(test_orchestrator())
