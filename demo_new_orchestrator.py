import asyncio
import logging
import os

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Ensure the script can find the src module.
# This might be necessary if running from the root directory.
import sys
# Add the project root to the Python path
# This assumes the script is run from the project root.
# Adjust if necessary based on your project structure.
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '.'))
sys.path.insert(0, project_root)
# Attempt to add src to path more robustly if needed, though direct import should work if in root
# sys.path.insert(0, os.path.join(project_root, 'src'))


from src.manus_use.multi_agents.new_orchestrator import NewOrchestrator
from src.manus_use.config import Config # To potentially pre-load/check config

async def main():
    logging.info("Starting NewOrchestrator demo...")

    # Optional: Pre-load and display part of the config to verify it's loading
    try:
        config = Config.from_file()
        logging.info(f"Loaded configuration. LLM provider: {config.llm.provider}, Model: {config.llm.model}")
        # Check browser-use specific LLM config if any
        if config.browser_use.provider:
            logging.info(f"BrowserUseAgent LLM provider: {config.browser_use.provider}, Model: {config.browser_use.model}")
        else:
            logging.info("BrowserUseAgent will use main LLM settings.")

        # Crucial check for BrowserUseAgent dependencies
        # This doesn't run the agent, just checks if the import within would fail
        try:
            from browser_use import Agent as BrowserUseCheck # Attempt the critical import
            logging.info("'browser-use' package seems to be available.")
        except ImportError:
            logging.warning("'browser-use' package is NOT available. BrowserUseAgent will not work.")
            logging.warning("Install it via: pip install browser-use")
        
        # Check for Langchain LLM support packages needed by BrowserUseAgent
        try:
            from langchain_aws import ChatBedrock
            logging.info("'langchain-aws' (for Bedrock) is available.")
        except ImportError:
            logging.warning("'langchain-aws' (for Bedrock) is NOT available. BrowserUseAgent with Bedrock will fail.")
        try:
            from langchain_openai import ChatOpenAI
            logging.info("'langchain-openai' (for OpenAI) is available.")
        except ImportError:
            logging.warning("'langchain-openai' (for OpenAI) is NOT available. BrowserUseAgent with OpenAI will fail.")


    except Exception as e:
        logging.error(f"Error loading configuration or checking dependencies: {e}")
        return

    orchestrator = NewOrchestrator()
    logging.info("NewOrchestrator instantiated.")

    # --- Test Case 1: Query likely for ManusAgent ---
    query1 = "What is the capital of France and can you write a short python script to print numbers from 1 to 5?"
    logging.info(f"\nRunning query 1: '{query1}'")
    try:
        response1 = await orchestrator(query1) # Use await if orchestrator call is async
        # response1 = orchestrator(query1) # If orchestrator call is sync (Strands Agent __call__ can be sync or async)
        # Strands Agent __call__ returns a coroutine if called from async context, else blocks.
        # So, await is correct here.
        logging.info(f"Response from orchestrator for query 1:\n{response1}")
    except Exception as e:
        logging.error(f"Error during query 1: {e}", exc_info=True)

    # --- Test Case 2: Query likely for BrowserUseAgent ---
    query2 = "What are the current top headlines on BBC News (bbc.com/news)?"
    logging.info(f"\nRunning query 2: '{query2}'")
    try:
        response2 = await orchestrator(query2)
        logging.info(f"Response from orchestrator for query 2:\n{response2}")
    except Exception as e:
        logging.error(f"Error during query 2: {e}", exc_info=True)
        
    # --- Test Case 3: Query likely for Orchestrator itself (simple) ---
    query3 = "Hello, how are you today?"
    logging.info(f"\nRunning query 3: '{query3}'")
    try:
        response3 = await orchestrator(query3)
        logging.info(f"Response from orchestrator for query 3:\n{response3}")
    except Exception as e:
        logging.error(f"Error during query 3: {e}", exc_info=True)
        
    # --- Test Case 4: Query that might involve BrowserUseAgent failing due to missing deps ---
    # This is more of an implicit test if 'browser-use' is not installed.
    # The browser_agent_tool_wrapper should catch the ImportError and return a message.
    query4 = "Find the main product listed on example.com."
    logging.info(f"\nRunning query 4 (potential browser task): '{query4}'")
    try:
        response4 = await orchestrator(query4)
        logging.info(f"Response from orchestrator for query 4:\n{response4}")
    except Exception as e:
        logging.error(f"Error during query 4: {e}", exc_info=True)


if __name__ == "__main__":
    # Ensure OPENAI_API_KEY is set if using OpenAI, or AWS credentials for Bedrock
    # e.g., os.environ["OPENAI_API_KEY"] = "your_key_here" 
    # (do not hardcode keys in production code)
    
    # On Windows, selector event loop policy might be needed for asyncio with Playwright
    # if sys.platform == "win32" and "playwright" in sys.modules: # Check if playwright is relevant
    #     asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    asyncio.run(main())
