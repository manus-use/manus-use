import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.agents.browser_use_agent import BrowserUseAgent
from manus_use.config import Config


async def test_browser_use_agent():
    """Test BrowserUseAgent functionality."""
    print("Testing BrowserUseAgent...")
    
    # Create config - use bedrock config
    config_path = Path(__file__).parent / "config" / "config.bedrock.toml"
    config = Config.from_file(config_path)
    
    # Create agent
    agent = BrowserUseAgent(config=config)
    
    # Test 1: Simple navigation and content extraction
    print("\n=== Test 1: Simple navigation ===")
    task = "Go to https://example.com and tell me the main heading"
    print(f"Task: {task}")
    
    try:
        result = await agent(task)
        print(f"Result: {result}")
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    
    # Test 2: More complex task
    print("\n=== Test 2: Complex browser task ===")
    task = "Go to https://www.wikipedia.org, search for 'Python programming', and tell me the first paragraph of the article"
    print(f"Task: {task}")
    
    try:
        result = await agent(task)
        print(f"Result: {result}")
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    
    # Clean up
    print("\nCleaning up...")
    await agent.cleanup()
    print("Done!")


if __name__ == "__main__":
    asyncio.run(test_browser_use_agent())