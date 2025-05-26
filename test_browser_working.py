#!/usr/bin/env python3
"""Working browser-use demo with AWS Bedrock."""

import asyncio
from langchain_aws import ChatBedrock
from browser_use import Agent, BrowserSession
from browser_use.browser.browser import Browser, BrowserConfig
from browser_use.controller.service import Controller


async def main():
    """Run browser-use with AWS Bedrock."""
    
    print("=== Browser-Use Demo with AWS Bedrock ===\n")
    
    # Initialize AWS Bedrock LLM
    print("Initializing AWS Bedrock LLM...")
    llm = ChatBedrock(
        model_id='us.anthropic.claude-3-5-sonnet-20241022-v2:0',
        model_kwargs={
            'temperature': 0.0,
            'max_tokens': 4096,
        },
        region_name='us-east-1'
    )
    print("✓ LLM initialized\n")
    
    # Create browser with config
    print("Creating browser...")
    browser_config = BrowserConfig(headless=False)  # Show browser window
    browser = Browser(config=browser_config)
    print("✓ Browser created\n")
    
    # Create browser session
    print("Creating browser session...")
    browser_session = BrowserSession(
        browser=browser,
        profile=browser_config
    )
    print("✓ Browser session created\n")
    
    # Define task
    task = """Navigate to https://www.anthropic.com and tell me about their latest AI model announcements."""
    
    print(f"Task: {task}\n")
    print("Starting browser agent...\n")
    
    # Create agent with browser session
    agent = Agent(
        task=task,
        llm=llm,
        controller=Controller(),
        browser_session=browser_session,  # Use browser_session instead of browser
        validate_output=False,
        enable_memory=False  # Disable memory to avoid warning
    )
    
    # Run the agent
    try:
        result = await agent.run(max_steps=10)
        print(f"\n✓ Task completed!")
        print(f"Result: {result}")
    except Exception as e:
        print(f"\n✗ Error during execution: {e}")
        import traceback
        traceback.print_exc()
    
    # Close browser
    print("\nClosing browser...")
    await browser.close()
    print("✓ Browser closed")
    
    print("\n✅ Demo completed!")


if __name__ == "__main__":
    asyncio.run(main())