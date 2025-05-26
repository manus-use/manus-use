#!/usr/bin/env python3
"""Test browser-use directly to understand the API."""

import asyncio
from langchain_aws import ChatBedrock
from browser_use import Agent


async def test_browser_use_direct():
    """Test browser-use directly without our wrapper."""
    print("Testing browser-use directly...\n")
    
    # Create LLM
    llm = ChatBedrock(
        model_id="us.anthropic.claude-3-5-sonnet-20241022-v2:0",
        model_kwargs={
            "temperature": 0.0,
            "max_tokens": 4096
        },
        region_name="us-east-1"
    )
    
    # Create agent with task
    agent = Agent(
        task="Go to example.com and tell me what the page says",
        llm=llm,
        headless=True
    )
    
    # Run the agent
    try:
        result = await agent.run()
        print(f"Success! Result: {result}")
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(test_browser_use_direct())