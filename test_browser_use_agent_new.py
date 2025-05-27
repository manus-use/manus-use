"""Test the new BrowserUseAgent with all its features."""

import asyncio
import sys
import json
from pathlib import Path
from typing import Optional
from pydantic import BaseModel

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.agents.browser_use_agent import BrowserUseAgent
from manus_use.config import Config


# Define a Pydantic model for structured output testing
class WebPageInfo(BaseModel):
    """Structured output model for web page information."""
    title: str
    main_heading: Optional[str] = None
    url: str
    description: Optional[str] = None


async def test_basic_functionality():
    """Test basic browser automation functionality."""
    print("\n=== Test 1: Basic Functionality ===")
    
    # Create config
    config_path = Path(__file__).parent / "config" / "config.bedrock.toml"
    config = Config.from_file(config_path)
    
    # Create agent
    agent = BrowserUseAgent(config=config, headless=True, enable_memory=False)
    
    # Test simple task
    task = "Go to https://example.com and tell me what the main heading says"
    print(f"Task: {task}")
    
    try:
        result = await agent(task)
        print(f"✅ Success! Result:\n{result}")
    except Exception as e:
        print(f"❌ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()


async def test_streaming():
    """Test streaming functionality with callbacks."""
    print("\n\n=== Test 2: Streaming Functionality ===")
    
    # Create config
    config_path = Path(__file__).parent / "config" / "config.bedrock.toml"
    config = Config.from_file(config_path)
    
    # Create agent
    agent = BrowserUseAgent(config=config, headless=True, enable_memory=False)
    
    # Test streaming task
    task = "Go to https://www.python.org and find the latest Python version"
    print(f"Task: {task}")
    print("Streaming updates:")
    
    try:
        event_count = 0
        async for event in agent.stream_async(task):
            event_count += 1
            event_type = event.get("type", "unknown")
            
            if event_type == "step_update":
                print(f"\n📍 Step {event.get('step')}: {event.get('url', 'N/A')}")
                if event.get('next_goal'):
                    print(f"   Next goal: {event['next_goal']}")
                if event.get('planned_actions'):
                    print(f"   Actions: {len(event['planned_actions'])} planned")
                    
            elif event_type == "final_result":
                print(f"\n✅ Final Result:")
                print(f"   Success: {event.get('is_successful')}")
                print(f"   Total steps: {event.get('total_steps')}")
                print(f"   Content: {event.get('content', 'No content')[:200]}...")
                
            elif event_type == "error":
                print(f"\n❌ Error: {event.get('message')}")
                
        print(f"\nTotal events received: {event_count}")
        
    except Exception as e:
        print(f"\n❌ Streaming error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()


async def test_structured_output():
    """Test structured output with Pydantic model."""
    print("\n\n=== Test 3: Structured Output ===")
    
    # Create config
    config_path = Path(__file__).parent / "config" / "config.bedrock.toml"
    config = Config.from_file(config_path)
    
    # Create agent with output model
    agent = BrowserUseAgent(
        config=config, 
        headless=True, 
        enable_memory=False,
        output_model=WebPageInfo
    )
    
    # Test with structured output
    task = "Go to https://example.com and extract the page information including title, main heading, and URL"
    print(f"Task: {task}")
    print(f"Expected output model: WebPageInfo")
    
    try:
        result = await agent(task)
        print(f"\nRaw result type: {type(result)}")
        print(f"Raw result: {result}")
        
        # Try to parse as JSON
        try:
            parsed = json.loads(result)
            print(f"\n✅ Parsed JSON:")
            print(json.dumps(parsed, indent=2))
            
            # Validate against model
            page_info = WebPageInfo(**parsed)
            print(f"\n✅ Valid WebPageInfo object:")
            print(f"   Title: {page_info.title}")
            print(f"   URL: {page_info.url}")
            print(f"   Main heading: {page_info.main_heading}")
            print(f"   Description: {page_info.description}")
        except json.JSONDecodeError:
            print(f"\n⚠️ Result is not valid JSON: {result}")
        except Exception as e:
            print(f"\n⚠️ Could not validate as WebPageInfo: {e}")
            
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()


async def test_memory_enabled():
    """Test with memory enabled."""
    print("\n\n=== Test 4: Memory Enabled ===")
    
    # Create config
    config_path = Path(__file__).parent / "config" / "config.bedrock.toml"
    config = Config.from_file(config_path)
    
    # Create agent with memory
    agent = BrowserUseAgent(config=config, headless=True, enable_memory=True)
    
    # Test two related tasks
    task1 = "Go to https://www.wikipedia.org and remember the main page title"
    task2 = "What was the title of the Wikipedia page you just visited?"
    
    print(f"Task 1: {task1}")
    
    try:
        result1 = await agent(task1)
        print(f"✅ Result 1: {result1[:200]}...")
        
        print(f"\nTask 2: {task2}")
        result2 = await agent(task2)
        print(f"✅ Result 2: {result2[:200]}...")
        
        # Note: Memory in browser-use is per-agent instance, not across instances
        print("\nNote: Each task creates a new browser-use agent instance, so memory may not persist between tasks.")
        
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()


async def test_error_handling():
    """Test error handling."""
    print("\n\n=== Test 5: Error Handling ===")
    
    # Create config
    config_path = Path(__file__).parent / "config" / "config.bedrock.toml"
    config = Config.from_file(config_path)
    
    # Create agent
    agent = BrowserUseAgent(config=config, headless=True)
    
    # Test with invalid task
    task = "Go to https://this-definitely-does-not-exist-123456789.com and extract content"
    print(f"Task (expecting failure): {task}")
    
    try:
        result = await agent(task)
        print(f"Result: {result}")
        # Even if navigation fails, browser-use might handle it gracefully
        
    except Exception as e:
        print(f"❌ Expected error: {type(e).__name__}: {e}")


async def test_sync_context():
    """Test calling from synchronous context."""
    print("\n\n=== Test 6: Synchronous Context ===")
    
    # Create config
    config_path = Path(__file__).parent / "config" / "config.bedrock.toml"
    config = Config.from_file(config_path)
    
    # Create agent
    agent = BrowserUseAgent(config=config, headless=True)
    
    # Test calling from sync context (simulated)
    task = "What is 2+2?"
    print(f"Task: {task}")
    
    # This will use asyncio.run internally
    def sync_test():
        """Simulate synchronous calling context."""
        return agent(task)
    
    try:
        result = sync_test()
        print(f"✅ Sync call result: {result}")
    except Exception as e:
        print(f"❌ Error in sync context: {type(e).__name__}: {e}")


async def main():
    """Run all tests."""
    print("Testing new BrowserUseAgent implementation...")
    print("=" * 60)
    
    tests = [
        ("Basic Functionality", test_basic_functionality),
        ("Streaming", test_streaming),
        ("Structured Output", test_structured_output),
        ("Memory Enabled", test_memory_enabled),
        ("Error Handling", test_error_handling),
        ("Sync Context", test_sync_context),
    ]
    
    for test_name, test_func in tests:
        try:
            if asyncio.iscoroutinefunction(test_func):
                await test_func()
            else:
                test_func()
        except Exception as e:
            print(f"\n❌ Test '{test_name}' failed with unexpected error: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 60)
    print("All tests completed!")


if __name__ == "__main__":
    print("Starting BrowserUseAgent tests...")
    print("Note: Make sure you have AWS credentials configured for Bedrock.\n")
    
    # Run all tests
    asyncio.run(main())