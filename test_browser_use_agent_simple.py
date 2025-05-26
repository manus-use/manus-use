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
    
    # Create agent with headless mode
    agent = BrowserUseAgent(config=config, headless=True)
    
    # Test: Simple navigation and content extraction
    print("\n=== Test: Simple navigation ===")
    task = "Go to https://example.com and tell me what the main heading says"
    print(f"Task: {task}")
    
    try:
        # Run with a timeout
        result = await asyncio.wait_for(agent(task), timeout=30.0)
        print(f"Result: {result}")
        print("\n✅ Test passed!")
    except asyncio.TimeoutError:
        print("⏱️ Test timed out after 30 seconds")
    except Exception as e:
        print(f"❌ Error: {type(e).__name__}: {e}")
    
    # Clean up
    print("\nCleaning up...")
    await agent.cleanup()
    print("Done!")


if __name__ == "__main__":
    asyncio.run(test_browser_use_agent())