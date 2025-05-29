import asyncio
import hashlib
import json
import logging
import re # Added
from typing import Any, Dict, Optional, List

from strands import Agent as StrandsAgent
from strands_tools.workflow import workflow

from src.manus_use.agents.manus import ManusAgent
from src.manus_use.agents.browser_use_agent import BrowserUseAgent
from src.manus_use.config import Config


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
    Orchestrates multi-agent workflows by using its own LLM to generate a task plan
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
        
        agent_tools = [workflow] 

        system_prompt = (
            "You are an expert planning agent. Your role is to analyze a user's request and decompose it "
            "into a sequence of tasks. These tasks can be executed by one of two types of specialized agents:\n"
            "- 'manus': for general tasks, coding, file operations, complex reasoning, or simple web lookups that don't require session persistence.\n"
            "- 'browser': for tasks requiring web browser interaction, such as navigating web pages, extracting structured information from complex sites, or when session persistence across multiple web steps is needed.\n\n"
            "For each task, you must define:\n"
            "- 'task_id': A unique string identifier for the task (e.g., 'task_1', 'fetch_data').\n"
            "- 'description': A clear and concise natural language query or instruction for the assigned agent. This description can use outputs from previous tasks using the template '{{dependency_task_id.output}}'. For example, if task 'task_1' fetches data, a subsequent task could have a description like 'Process the data found: {{task_1.output}} and save it to a file.'\n"
            "- 'agent_type': A string, either 'manus' or 'browser'.\n"
            "- 'dependencies': A list of string task_ids that this task depends on. If there are no dependencies, provide an empty list [].\n\n"
            "You must output ONLY a valid JSON list of these task objects. Do not include any other text, explanations, or markdown formatting outside the JSON list itself.\n"
            "Example JSON output format:\n"
            "```json\n"
            "[\n"
            "  {\n"
            "    \"task_id\": \"task1_unique_id\",\n"
            "    \"description\": \"Query for the first agent (e.g., search for something)\",\n"
            "    \"agent_type\": \"browser\",\n"
            "    \"dependencies\": []\n"
            "  },\n"
            "  {\n"
            "    \"task_id\": \"task2_another_id\",\n"
            "    \"description\": \"Process output from task1: {{task1_unique_id.output}} and save to file\",\n"
            "    \"agent_type\": \"manus\",\n"
            "    \"dependencies\": [\"task1_unique_id\"]\n"
            "  }\n"
            "]\n"
            "```\n"
            "Ensure your response is solely this JSON array."
        )

        super().__init__(
            model=self.config.get_model(), 
            tools=agent_tools,
            system_prompt=system_prompt,
            **kwargs
        )

    def _adapt_planned_tasks_for_workflow(self, planned_tasks: List[Dict]) -> List[Dict]:
        """
        Adapts tasks from the LLM's JSON plan to be compatible with the workflow tool.
        """
        adapted_tasks = []
        for task in planned_tasks:
            agent_type_str = task.get("agent_type", "manus").lower() 
            description = task.get("description", "")
            
            callable_path = ""
            if agent_type_str == "manus":
                callable_path = "src.manus_use.multi_agents.workflow_orchestrator.run_manus_agent_task"
            elif agent_type_str == "browser":
                callable_path = "src.manus_use.multi_agents.workflow_orchestrator.run_browser_agent_task"
            else:
                logging.warning(f"Unsupported agent_type '{agent_type_str}' for task '{task.get('task_id', 'N/A')}'. Defaulting to 'manus'. Consider revising the plan or prompt.")
                callable_path = "src.manus_use.multi_agents.workflow_orchestrator.run_manus_agent_task"

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
        Processes a user request by generating a task plan using its own LLM and executing it as a workflow.
        """
        logging.info(f"WorkflowOrchestrator: Received request: {user_request}")
        
        logging.info("Generating task plan using internal LLM...")
        
        llm_response_obj = await self(user_request) # LLM call
        
        raw_planned_tasks = None
        llm_had_direct_json = False
        llm_response_content_str = "" # Initialize to ensure it's always defined

        if isinstance(llm_response_obj, (list, dict)):
            logging.info("LLM response is already a list/dict. Using directly.")
            raw_planned_tasks = llm_response_obj
            llm_had_direct_json = True
        elif hasattr(llm_response_obj, 'content'):
            if isinstance(llm_response_obj.content, (list, dict)):
                logging.info("LLM response object's 'content' attribute is a list/dict. Using directly.")
                raw_planned_tasks = llm_response_obj.content
                llm_had_direct_json = True
            elif isinstance(llm_response_obj.content, str):
                llm_response_content_str = llm_response_obj.content
                logging.info(f"LLM response content is a string. Attempting to parse: {llm_response_content_str[:500]}")
            else:
                logging.warning(f"LLM response content is of unexpected type: {type(llm_response_obj.content)}. Attempting to stringify.")
                llm_response_content_str = str(llm_response_obj.content)
        elif isinstance(llm_response_obj, str):
            llm_response_content_str = llm_response_obj
            logging.info(f"LLM response is a string. Attempting to parse: {llm_response_content_str[:500]}")
        else:
            logging.error(f"Unexpected LLM response type: {type(llm_response_obj)}. Cannot extract JSON plan.")
            return {"status": "error", "message": f"Unexpected LLM response type: {type(llm_response_obj)}"}

        if not llm_had_direct_json:
            if not llm_response_content_str or not llm_response_content_str.strip():
                logging.error("LLM returned empty or whitespace-only content for the plan.")
                return {"status": "error", "message": "LLM returned empty content for the plan."}
            try:
                # Try direct parsing first
                raw_planned_tasks = json.loads(llm_response_content_str)
            except json.JSONDecodeError:
                logging.warning("Direct JSON parsing failed. Attempting to extract JSON from markdown code block...")
                # Attempt to extract JSON from ```json ... ``` or ``` ... ```
                match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", llm_response_content_str, re.MULTILINE)
                if match:
                    extracted_json_str = match.group(1).strip()
                    logging.info(f"Extracted JSON string from markdown: {extracted_json_str[:500]}")
                    try:
                        raw_planned_tasks = json.loads(extracted_json_str)
                    except json.JSONDecodeError as e:
                        logging.error(f"Failed to parse extracted JSON: {e}. Original content was: {llm_response_content_str[:500]}")
                        return {"status": "error", "message": f"Failed to parse JSON plan from LLM after extraction: {e}"}
                else:
                    # Fallback: if no markdown, try to find first '{' or '['
                    logging.warning("No JSON markdown code block found. Trying to find start of JSON object/array.")
                    json_start_object = llm_response_content_str.find('{')
                    json_start_array = llm_response_content_str.find('[')

                    if json_start_array != -1 and (json_start_object == -1 or json_start_array < json_start_object) :
                        potential_json_str = llm_response_content_str[json_start_array:]
                    elif json_start_object != -1 and (json_start_array == -1 or json_start_object < json_start_array) :
                        potential_json_str = llm_response_content_str[json_start_object:]
                    else:
                        potential_json_str = None
                    
                    if potential_json_str:
                        logging.info(f"Attempting to parse from potential JSON start: {potential_json_str[:500]}")
                        try:
                            raw_planned_tasks = json.loads(potential_json_str)
                        except json.JSONDecodeError as e:
                            logging.error(f"Failed to parse JSON plan from LLM (even after trying to find start): {e}. Original content was: {llm_response_content_str[:500]}")
                            return {"status": "error", "message": f"Failed to parse JSON plan from LLM (final attempt): {e}"}
                    else:
                        logging.error(f"Could not find any JSON structure in LLM response: {llm_response_content_str[:500]}")
                        return {"status": "error", "message": "No JSON structure found in LLM response."}

        # Ensure raw_planned_tasks is a list, as expected by _adapt_planned_tasks_for_workflow
        if raw_planned_tasks is None: # If all parsing attempts failed and it was not direct JSON
            logging.error("All parsing attempts for LLM response failed. Plan is None.")
            return {"status": "error", "message": "Failed to obtain a valid plan from LLM after all parsing attempts."}

        if not isinstance(raw_planned_tasks, list):
            logging.error(f"LLM plan is not a list as expected. Type: {type(raw_planned_tasks)}, Content: {str(raw_planned_tasks)[:500]}")
            if isinstance(raw_planned_tasks, dict) and all(k in raw_planned_tasks for k in ['task_id', 'description', 'agent_type']):
                logging.warning("LLM plan was a single dictionary, wrapping it in a list.")
                raw_planned_tasks = [raw_planned_tasks]
            else:
                return {"status": "error", "message": "LLM plan is not a list of tasks or a single task dictionary."}


        if not raw_planned_tasks: # This check is now after ensuring it's a list
            logging.error("Planning phase (LLM) did not return any tasks or parsing resulted in empty list.")
            return {"status": "error", "message": "No tasks generated or parsed from the LLM planning phase."}
        
        logging.info(f"Raw planned tasks from LLM: {raw_planned_tasks}")

        adapted_tasks = self._adapt_planned_tasks_for_workflow(raw_planned_tasks)

        if not adapted_tasks:
            logging.error("No tasks could be adapted for workflow execution.")
            return {"status": "error", "message": "Failed to adapt LLM-planned tasks for workflow."}
        
        logging.info(f"Adapted tasks for workflow: {adapted_tasks}")

        workflow_id = "wf_" + hashlib.md5(user_request.encode()).hexdigest()[:10]
        
        create_workflow_input = {
            "action": "create",
            "workflow_id": workflow_id,
            "tasks": adapted_tasks
        }
        logging.info(f"Creating workflow '{workflow_id}' with tasks: {adapted_tasks}")
        
        create_response = workflow(tool={"toolUseId": "tool_create_wf", "input": create_workflow_input})
        if asyncio.iscoroutine(create_response): 
            create_response = await create_response
            
        logging.info(f"Workflow creation response: {create_response}")

        if isinstance(create_response, dict) and (create_response.get("status") == "error" or "error" in str(create_response).lower()):
            error_message = create_response.get("message", "Unknown error during workflow creation")
            if isinstance(create_response.get("content"), list) and create_response["content"]:
                 error_details = create_response["content"][0].get("text", error_message)
                 if isinstance(error_details, dict): error_message = error_details.get("message", str(error_details))
                 else: error_message = str(error_details)
            logging.error(f"Failed to create workflow: {error_message}")
            return {"status": "error", "message": f"Workflow creation failed: {error_message}"}
        elif not isinstance(create_response, dict) or not create_response.get("workflow_id"):
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
    #     test_request = "What is the current weather in London, UK? Then, write this weather information into a file named 'london_weather.txt'."
    #     result = await orchestrator.run_workflow_for_request(test_request)
    #     print("\n--- WorkflowOrchestrator Test ---")
    #     print(f"Request: {test_request}")
    #     print(f"Result: {json.dumps(result, indent=2)}")

    # if True: 
    #    asyncio.run(test_orchestrator())
