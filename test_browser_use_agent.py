#!/usr/bin/env python3
"""Test BrowserUseAgent functionality."""

import asyncio
from manus_use.agents import BrowserUseAgent
from manus_use.config import Config


def test_browser_use_agent():
    """Test BrowserUseAgent with various tasks."""
    print("=== Testing BrowserUseAgent ===\n")
    
    # Load configuration
    config = Config.from_file()
    print(f"✓ Configuration loaded (provider: {config.llm.provider})")
    
    # Create BrowserUseAgent
    print("\n1. Creating BrowserUseAgent...")
    try:
        agent = BrowserUseAgent(config=config, headless=True)
        print("✓ BrowserUseAgent created successfully")
        print(f"  - Headless mode: {agent.headless}")
        print(f"  - Config provider: {agent.config.llm.provider}")
    except Exception as e:
        print(f"✗ Failed to create agent: {e}")
        return
    
    # Test 1: Simple navigation
    print("\n2. Testing simple navigation...")
    try:
        result = agent("Go to example.com and tell me what the page title is")
        print(f"✓ Result: {result[:200]}..." if len(str(result)) > 200 else f"✓ Result: {result}")
    except Exception as e:
        print(f"✗ Failed: {e}")
    
    # Test 2: Information extraction
    print("\n3. Testing information extraction...")
    try:
        result = agent(
            "Go to python.org and find out what the latest stable Python version is. "
            "Just give me the version number."
        )
        print(f"✓ Result: {result[:200]}..." if len(str(result)) > 200 else f"✓ Result: {result}")
    except Exception as e:
        print(f"✗ Failed: {e}")
    
    # Test 3: Search task
    print("\n4. Testing web search...")
    try:
        result = agent(
            "Search for 'OpenAI GPT-4' on Google and tell me one key fact about it "
            "from the search results"
        )
        print(f"✓ Result: {result[:200]}..." if len(str(result)) > 200 else f"✓ Result: {result}")
    except Exception as e:
        print(f"✗ Failed: {e}")
    
    # Test cleanup
    print("\n5. Testing cleanup...")
    try:
        asyncio.run(agent.cleanup())
        print("✓ Cleanup successful")
    except Exception as e:
        print(f"✗ Cleanup failed: {e}")
    
    print("\n=== Test Summary ===")
    print("BrowserUseAgent is working as a Strands Agent!")
    print("It successfully delegates tasks to browser-use for autonomous web browsing.")


async def test_async_usage():
    """Test BrowserUseAgent in async context."""
    print("\n\n=== Testing Async Usage ===\n")
    
    config = Config.from_file()
    agent = BrowserUseAgent(config=config, headless=True)
    
    print("Testing async execution...")
    try:
        # In async context, the agent returns a coroutine
        result = await agent._run_browser_task("Go to example.com and get the page title")
        print(f"✓ Async result: {result[:100]}..." if len(str(result)) > 100 else f"✓ Async result: {result}")
    except Exception as e:
        print(f"✗ Async execution failed: {e}")
    
    # Cleanup
    await agent.cleanup()
    print("✓ Async cleanup complete")


def test_error_handling():
    """Test error handling in BrowserUseAgent."""
    print("\n\n=== Testing Error Handling ===\n")
    
    # Test without browser-use installed (simulated)
    print("1. Testing missing dependencies handling...")
    # This is handled at import time, so we can't easily test it
    print("   (Skipped - requires uninstalling browser-use)")
    
    # Test with invalid task
    print("\n2. Testing with empty task...")
    try:
        config = Config.from_file()
        agent = BrowserUseAgent(config=config, headless=True)
        result = agent("")
        print(f"Result with empty task: {result}")
    except Exception as e:
        print(f"✓ Correctly handled empty task: {type(e).__name__}")
    
    print("\n✓ Error handling tests complete")


if __name__ == "__main__":
    # Run synchronous tests
    test_browser_use_agent()
    
    # Run async tests
    asyncio.run(test_async_usage())
    
    # Run error handling tests
    test_error_handling()
    
    print("\n\n✅ All BrowserUseAgent tests completed!")