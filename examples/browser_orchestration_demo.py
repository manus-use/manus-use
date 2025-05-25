#!/usr/bin/env python3
"""Demonstrate BrowserAgent working with PlanningAgent orchestrator."""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.manus_use.multi_agents.task_planner import PlanningAgent
from src.manus_use.config import Config


async def browser_orchestration_demo():
    """Demonstrate browser automation through orchestrator."""
    
    # Initialize configuration
    config = Config.from_file()
    
    # Create PlanningAgent (orchestrator)
    print("Creating Planning/Orchestrator Agent...")
    orchestrator = PlanningAgent(config=config)
    
    # Complex task requiring browser automation
    task = """
    I need to research the latest developments in AI and create a summary report:
    1. Search for recent news about GPT-4 and Claude 3
    2. Visit the official OpenAI and Anthropic websites
    3. Extract key information about their latest models
    4. Take screenshots of important pages
    5. Create a markdown report summarizing the findings
    """
    
    print(f"\nTask: {task}")
    print("\nOrchestrator is planning and delegating to specialized agents...\n")
    
    # Run the task
    result = await orchestrator.run(task)
    
    print("\n✅ Task completed!")
    print(f"\nResult: {result}")


if __name__ == "__main__":
    asyncio.run(browser_orchestration_demo())