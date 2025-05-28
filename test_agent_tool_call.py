#!/usr/bin/env python3
"""Test if Strands agent calls tools properly"""

import asyncio
import os
import sys

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from strands import Agent as StrandsAgent
from manus_use.multi_agents.planning_agent import create_task_plan_tool
from manus_use.config import Config

async def main():
    """Test agent tool calling"""
    config = Config.from_file()
    
    # Create agent with the tool
    agent = StrandsAgent(
        tools=[create_task_plan_tool],
        model=config.get_model()
    )
    
    # Test direct prompt
    prompt = "Use the create_task_plan_tool to create a plan for: List 3 common web vulnerabilities"
    
    print(f"Prompt: {prompt}\n")
    
    result = agent(prompt)
    if asyncio.iscoroutine(result):
        result = await result
    
    print(f"Result type: {type(result)}")
    print(f"Result attributes: {dir(result)}")
    
    if hasattr(result, 'state'):
        print(f"\nState: {result.state}")
        if 'tool_calls' in result.state:
            print(f"Tool calls: {result.state['tool_calls']}")
    
    if hasattr(result, 'message'):
        print(f"\nMessage: {result.message}")

if __name__ == "__main__":
    asyncio.run(main())