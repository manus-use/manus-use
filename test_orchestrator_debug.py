#!/usr/bin/env python3
"""Debug test for orchestrator to understand response structure"""

import asyncio
import logging
import os
import sys

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from manus_use.multi_agents.orchestrator import Orchestrator

# Configure logging to see debug info
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

async def main():
    """Test orchestrator with a simple task"""
    orchestrator = Orchestrator()
    
    # Simple test task
    task = "List 3 common web vulnerabilities"
    
    print(f"\n🔍 Testing orchestrator with task: {task}\n")
    
    try:
        result = await orchestrator.run_async(task)
        print(f"\n✅ Result: {result}")
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())