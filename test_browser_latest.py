#!/usr/bin/env python3
"""Test browser-use with the latest API."""

import asyncio
from browser_use import Agent
from langchain_aws import ChatBedrock


async def main():
    print("=== Browser-Use Test with AWS Bedrock ===\n")
    
    # Initialize AWS Bedrock LLM
    print("Initializing AWS Bedrock LLM...")
    llm = ChatBedrock(
        model_id='us.anthropic.claude-3-7-sonnet-20250219-v1:0',  # Using the model from config
        model_kwargs={
            'temperature': 0.0,
            'max_tokens': 4096,
        },
        region_name='us-east-1'
    )
    print("✓ LLM initialized\n")
    
    # Simple task
    task = "Go to https://example.com and tell me what the main heading says"
    
    print(f"Task: {task}\n")
    print("Starting browser agent...\n")
    
    # Create agent - let browser-use handle browser creation
    agent = Agent(
        task=task,
        llm=llm,
        enable_memory=False,  # Disable memory to avoid warnings
    )
    
    # Run the agent
    try:
        result = await agent.run(max_steps=5)
        print(f"\n✓ Task completed!")
        print(f"Result: {result}")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n✅ Test completed!")


if __name__ == "__main__":
    asyncio.run(main())