#!/usr/bin/env python3
"""Test BrowserAgent with browser-use and AWS Bedrock."""

import asyncio
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.manus_use.agents.browser import BrowserAgent
from src.manus_use.config import Config


async def test_browser_agent_bedrock():
    """Test the BrowserAgent with browser-use and AWS Bedrock."""
    
    # Initialize configuration
    config = Config.from_file()
    
    # Ensure we're using AWS Bedrock in config
    print(f"Using model: {config.model.model_id}")
    print(f"AWS Region: {config.model.aws_region}")
    
    # Create BrowserAgent with headless=False to see the browser
    print("\nCreating BrowserAgent with browser-use...")
    browser_agent = BrowserAgent(
        config=config,
        headless=False  # Set to False to see browser actions
    )
    
    # Test 1: Navigate and get state
    print("\n1. Testing navigation and state retrieval...")
    nav_result = await browser_agent.run(
        "Navigate to https://example.com and tell me what elements are on the page"
    )
    print(f"Navigation Result: {nav_result}")
    
    # Test 2: Search and extract
    print("\n2. Testing web search and extraction...")
    search_result = await browser_agent.run(
        "Search for 'OpenAI GPT-4' and extract the key information from the first result"
    )
    print(f"Search Result: {search_result}")
    
    # Test 3: Form interaction
    print("\n3. Testing form interaction...")
    form_result = await browser_agent.run(
        "Go to https://httpbin.org/forms/post, fill in the customer name with 'Test User' and phone with '555-1234', then tell me what you see"
    )
    print(f"Form Result: {form_result}")
    
    # Test 4: Screenshot
    print("\n4. Testing screenshot capture...")
    screenshot_result = await browser_agent.run(
        "Take a screenshot of the current page and save it as 'bedrock_test_screenshot.jpg'"
    )
    print(f"Screenshot Result: {screenshot_result}")
    
    # Test 5: Close browser
    print("\n5. Closing browser...")
    close_result = await browser_agent.run(
        "Close the browser session"
    )
    print(f"Close Result: {close_result}")
    
    print("\n✅ Browser-use with AWS Bedrock test completed!")


if __name__ == "__main__":
    # Ensure AWS credentials are set
    if not os.environ.get("AWS_ACCESS_KEY_ID"):
        print("⚠️  AWS credentials not found in environment.")
        print("Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
        sys.exit(1)
    
    asyncio.run(test_browser_agent_bedrock())