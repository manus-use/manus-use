#!/usr/bin/env python3
"""Debug script to test orchestrator and see response structure."""

import asyncio
import logging
from src.manus_use.multi_agents.orchestrator import Orchestrator
from src.manus_use.config import load_config

# Configure logging to see detailed output
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

async def main():
    # Load configuration
    config = load_config()
    
    # Create orchestrator
    orchestrator = Orchestrator(config)
    
    # Simple test task to debug response format
    task = "List 3 steps to search for security vulnerabilities"
    
    print(f"\n{'='*60}")
    print(f"Testing orchestrator with task: {task}")
    print(f"{'='*60}\n")
    
    try:
        # Execute task
        result = await orchestrator.execute(task)
        print(f"\nOrchestrator result: {result}")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())