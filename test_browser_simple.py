#!/usr/bin/env python3
"""Simple test for browser agent functionality."""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from src.manus_use.agents.browser import BrowserAgent
from src.manus_use.config import Config
from src.manus_use.tools.browser_tools import (
    browser_navigate,
    browser_get_state,
    browser_extract,
    browser_close,
)


async def test_browser_tools():
    """Test individual browser tools."""
    print("=== Testing Browser Tools ===\n")
    
    # Test 1: Navigate
    print("1. Testing browser_navigate...")
    try:
        nav_result = await browser_navigate(url="https://example.com")
        print(f"✓ Navigation successful: {nav_result}")
    except Exception as e:
        print(f"✗ Navigation failed: {e}")
    
    # Test 2: Get state
    print("\n2. Testing browser_get_state...")
    try:
        state_result = await browser_get_state()
        print(f"✓ State retrieved: {state_result[:200]}...")
    except Exception as e:
        print(f"✗ Get state failed: {e}")
    
    # Test 3: Extract content
    print("\n3. Testing browser_extract...")
    try:
        extract_result = await browser_extract(goal="Extract the main heading")
        print(f"✓ Content extracted: {extract_result}")
    except Exception as e:
        print(f"✗ Extract failed: {e}")
    
    # Test 4: Close browser
    print("\n4. Testing browser_close...")
    try:
        close_result = await browser_close()
        print(f"✓ Browser closed: {close_result}")
    except Exception as e:
        print(f"✗ Close failed: {e}")


async def test_browser_agent_simple():
    """Test BrowserAgent without AWS credentials."""
    print("\n\n=== Testing BrowserAgent ===\n")
    
    # Create a mock config
    config = Config()
    config.tools.browser_headless = False
    
    print("Creating BrowserAgent...")
    try:
        browser_agent = BrowserAgent(
            config=config,
            headless=False
        )
        print("✓ BrowserAgent created successfully")
        
        # Check available tools
        print(f"\nAvailable tools: {[tool.name for tool in browser_agent.tools]}")
        
    except Exception as e:
        print(f"✗ Failed to create BrowserAgent: {e}")
        import traceback
        traceback.print_exc()


async def main():
    """Run all tests."""
    print("Browser Agent Test Suite")
    print("=" * 50)
    
    # Test individual tools
    await test_browser_tools()
    
    # Test agent creation
    await test_browser_agent_simple()
    
    print("\n" + "=" * 50)
    print("✓ Test completed!")


if __name__ == "__main__":
    asyncio.run(main())