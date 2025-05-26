#!/usr/bin/env python3
"""Test browser-use with AWS Bedrock (requires AWS credentials)."""

import asyncio
import os
from pathlib import Path

# Check AWS credentials first
if not os.environ.get("AWS_ACCESS_KEY_ID"):
    print("⚠️  AWS credentials not found!")
    print("Please set the following environment variables:")
    print("  export AWS_ACCESS_KEY_ID='your-access-key'")
    print("  export AWS_SECRET_ACCESS_KEY='your-secret-key'")
    print("  export AWS_DEFAULT_REGION='us-east-1'")
    exit(1)

# Direct browser-use test with AWS Bedrock
from browser_use import Agent
from browser_use.browser.browser import Browser, BrowserConfig
from browser_use.controller.service import Controller
from langchain_aws import ChatBedrock


async def test_browser_search():
    """Test browser agent with a simple search task."""
    
    # Initialize AWS Bedrock LLM
    print("Initializing AWS Bedrock LLM...")
    llm = ChatBedrock(
        model_id='us.anthropic.claude-3-5-sonnet-20241022-v2:0',  # Using Sonnet 3.5
        model_kwargs={
            'temperature': 0.0,
            'max_tokens': 4096,
        },
        region_name=os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
    )
    print(f"✓ Using model in region: {os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')}")
    
    # Create browser
    print("\nCreating browser...")
    browser = Browser(
        config=BrowserConfig(
            headless=False  # Show browser window
        )
    )
    print("✓ Browser created")
    
    # Define a simple task
    task = "Go to https://example.com and tell me what the main heading says"
    
    print(f"\nTask: {task}")
    print("\nRunning browser agent...\n")
    
    # Create and run agent
    agent = Agent(
        task=task,
        llm=llm,
        controller=Controller(),
        browser=browser,
        validate_output=False,
    )
    
    try:
        # Run with limited steps
        result = await agent.run(max_steps=5)
        print(f"\n✓ Task completed!")
        print(f"Result: {result}")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Always close browser
        print("\nClosing browser...")
        await browser.close()
        print("✓ Browser closed")


async def test_browser_interaction():
    """Test more complex browser interaction."""
    
    # Initialize LLM
    llm = ChatBedrock(
        model_id='us.anthropic.claude-3-5-sonnet-20241022-v2:0',
        model_kwargs={
            'temperature': 0.0,
            'max_tokens': 4096,
        },
        region_name=os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
    )
    
    # Create browser
    browser = Browser(
        config=BrowserConfig(
            headless=False
        )
    )
    
    # More complex task
    task = """
    1. Go to https://httpbin.org/forms/post
    2. Fill in the customer name field with "Test User"
    3. Fill in the telephone field with "555-1234"
    4. Tell me what you see on the page
    """
    
    print(f"\nComplex Task: {task}")
    print("\nRunning browser agent...\n")
    
    agent = Agent(
        task=task,
        llm=llm,
        controller=Controller(),
        browser=browser,
        validate_output=False,
    )
    
    try:
        result = await agent.run(max_steps=10)
        print(f"\n✓ Task completed!")
        print(f"Result: {result}")
    except Exception as e:
        print(f"\n✗ Error: {e}")
    finally:
        await browser.close()


async def main():
    """Run browser tests."""
    print("=== Browser-Use Test with AWS Bedrock ===")
    print(f"AWS Region: {os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')}")
    print("=" * 50)
    
    # Test 1: Simple navigation
    print("\nTest 1: Simple Navigation")
    print("-" * 30)
    await test_browser_search()
    
    # Test 2: Form interaction
    print("\n\nTest 2: Form Interaction")
    print("-" * 30)
    await test_browser_interaction()
    
    print("\n" + "=" * 50)
    print("✓ All tests completed!")


if __name__ == "__main__":
    asyncio.run(main())