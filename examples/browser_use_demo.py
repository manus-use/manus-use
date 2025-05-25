#!/usr/bin/env python3
"""Direct browser-use demo with AWS Bedrock (similar to demo_browser.py)."""

import asyncio
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from browser_use import Agent
from browser_use.browser.browser import Browser, BrowserConfig
from browser_use.controller.service import Controller
from langchain_aws import ChatBedrock


async def main():
    """Run browser-use directly with AWS Bedrock."""
    
    # Initialize AWS Bedrock LLM
    llm = ChatBedrock(
        model_id='us.anthropic.claude-3-7-sonnet-20250219-v1:0',
        model_kwargs={
            'temperature': 0.0,
            'max_tokens': 4096,
        },
        region_name='us-east-1'
    )
    
    # Define the task
    task = """Navigate to https://www.anthropic.com and tell me about their latest AI model announcements."""
    
    print(f"Task: {task}")
    print("\nStarting browser-use with AWS Bedrock...\n")
    
    # Create browser
    browser = Browser(
        config=BrowserConfig(
            headless=False  # Show browser window
        )
    )
    
    # Create agent
    agent = Agent(
        task=task,
        llm=llm,
        controller=Controller(),
        browser=browser,
        validate_output=False,
    )
    
    # Run the agent
    await agent.run(max_steps=10)
    
    # Close browser
    await browser.close()
    
    print("\n✅ Demo completed!")


if __name__ == "__main__":
    # Check AWS credentials
    if not os.environ.get("AWS_ACCESS_KEY_ID"):
        print("⚠️  AWS credentials not found in environment.")
        print("Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
        sys.exit(1)
    
    asyncio.run(main())