#!/usr/bin/env python3
"""Test BrowserAgent implementation."""

import asyncio
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.manus_use.agents.browser import BrowserAgent
from src.manus_use.config import Config


async def test_browser_agent():
    """Test the BrowserAgent with various web automation tasks."""
    
    # Initialize configuration
    config = Config.from_file()
    
    # Create BrowserAgent
    print("Creating BrowserAgent...")
    browser_agent = BrowserAgent(
        config=config,
        headless=True  # Run in headless mode for testing
    )
    
    # Test 1: Web search
    print("\n1. Testing web search...")
    search_result = await browser_agent.run(
        "Search for 'OpenAI GPT-4' and tell me what you find"
    )
    print(f"Search Result: {search_result}")
    
    # Test 2: Navigate and extract content
    print("\n2. Testing navigation and extraction...")
    extract_result = await browser_agent.run(
        "Navigate to https://example.com and extract the main heading and first paragraph"
    )
    print(f"Extract Result: {extract_result}")
    
    # Test 3: Take screenshot
    print("\n3. Testing screenshot...")
    screenshot_result = await browser_agent.run(
        "Take a screenshot of the current page and save it as 'example_screenshot.jpg'"
    )
    print(f"Screenshot Result: {screenshot_result}")
    
    # Test 4: Complex navigation
    print("\n4. Testing complex navigation...")
    complex_result = await browser_agent.run(
        "Go to https://httpbin.org/forms/post, fill in the custname field with 'Test User', "
        "custtel with '555-1234', and extract the form data"
    )
    print(f"Complex Result: {complex_result}")
    
    # Test 5: JavaScript execution
    print("\n5. Testing JavaScript execution...")
    js_result = await browser_agent.run(
        "Execute JavaScript to get the current page title and URL"
    )
    print(f"JavaScript Result: {js_result}")
    
    # Test 6: Clean up
    print("\n6. Closing browser session...")
    cleanup_result = await browser_agent.run(
        "Close the browser session"
    )
    print(f"Cleanup Result: {cleanup_result}")
    
    print("\n✅ BrowserAgent test completed!")


if __name__ == "__main__":
    asyncio.run(test_browser_agent())