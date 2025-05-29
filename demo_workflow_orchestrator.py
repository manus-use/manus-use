import asyncio
import logging
import os
import sys

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Ensure the script can find the src module
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '.'))
sys.path.insert(0, project_root)

from src.manus_use.multi_agents.workflow_orchestrator import WorkflowOrchestrator
from src.manus_use.config import Config # For pre-flight checks

async def main():
    logging.info("Starting WorkflowOrchestrator demo...")

    # --- Pre-flight checks (similar to demo_new_orchestrator.py) ---
    try:
        config = Config.from_file()
        logging.info(f"Loaded configuration. LLM provider: {config.llm.provider}, Model: {config.llm.model}")
        if config.browser_use.provider:
            logging.info(f"BrowserUseAgent LLM provider: {config.browser_use.provider}, Model: {config.browser_use.model}")
        else:
            logging.info("BrowserUseAgent will use main LLM settings if its specific config is not set.")

        # Check for BrowserUseAgent's critical dependencies
        try:
            from browser_use import Agent as BrowserUseCheck
            logging.info("'browser-use' package seems to be available.")
        except ImportError:
            logging.warning("'browser-use' package is NOT available. BrowserUseAgent tasks in workflow will fail.")
            logging.warning("Install it via: pip install browser-use")
        
        # Check for Langchain LLM support packages (if using BrowserUseAgent with these)
        try:
            from langchain_aws import ChatBedrock
            logging.info("'langchain-aws' (for Bedrock) is available.")
        except ImportError:
            logging.warning("'langchain-aws' (for Bedrock) is NOT available.")
        try:
            from langchain_openai import ChatOpenAI
            logging.info("'langchain-openai' (for OpenAI) is available.")
        except ImportError:
            logging.warning("'langchain-openai' (for OpenAI) is NOT available.")

    except Exception as e:
        logging.error(f"Error during configuration loading or dependency check: {e}")
        logging.warning("Proceeding with demo, but some functionalities might be affected.")
    # --- End of Pre-flight checks ---

    # Instantiate the orchestrator
    # The WorkflowOrchestrator's __init__ loads its own config via get_workflow_config()
    # if not provided, so passing config here is optional but can ensure consistency.
    orchestrator = WorkflowOrchestrator(config=config if 'config' in locals() else None)
    logging.info("WorkflowOrchestrator instantiated.")

    # Define a complex query that would benefit from a workflow
    # Example 1: Search and then write to file
    # query = "What is the current weather in London, UK? Then, write this weather information into a file named 'london_weather.txt'."
    
    # Example 2: A task that might primarily use ManusAgent (e.g., coding, simple search)
    # query = "Write a python script to list files in the current directory and save the list to 'file_list.txt'. Then print the content of 'file_list.txt'."

    # Example 3: A task that might primarily use BrowserUseAgent
    query = "Find the main headline on the BBC News website (bbc.com/news) and then summarize it in one sentence."

    logging.info(f"\nRunning workflow for query: '{query}'")
    
    final_result = None
    try:
        # run_workflow_for_request is an async method
        final_result = await orchestrator.run_workflow_for_request(query)
        logging.info("\n--- Workflow Execution Result ---")
        if final_result:
            logging.info(f"Status: {final_result.get('workflow_status', 'N/A')}")
            logging.info(f"Output/Message: {final_result.get('output', final_result.get('message', 'No detailed output/message'))}")
            
            tasks_info = final_result.get('tasks', [])
            if tasks_info:
                logging.info("\nTasks Summary:")
                for i, task_status in enumerate(tasks_info):
                    logging.info(
                        f"  Task {i+1} (ID: {task_status.get('task_id', 'N/A')}): "
                        f"Status: {task_status.get('status', 'N/A')}, "
                        f"Description: {task_status.get('description', 'N/A')[:50]}..., "
                        f"Result/Error: {str(task_status.get('result', task_status.get('error', 'N/A')))[:100]}..."
                    )
            else:
                # Fallback for older workflow status format or if tasks details are missing
                logging.info(f"Full Result Object: {final_result}")

        else:
            logging.warning("Workflow execution returned no result.")

    except Exception as e:
        logging.error(f"An error occurred while running the workflow demo: {e}", exc_info=True)

if __name__ == "__main__":
    # Ensure necessary environment variables (like OPENAI_API_KEY or AWS credentials) are set.
    # Example: os.environ["OPENAI_API_KEY"] = "your_key_here" (do not hardcode in production)
    
    asyncio.run(main())
