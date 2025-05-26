#!/usr/bin/env python3
"""Simple test to debug BrowserUseAgent."""

import asyncio
import traceback
from manus_use.agents import BrowserUseAgent
from manus_use.config import Config


async def test_simple():
    """Simple test with full error output."""
    print("=== Simple BrowserUseAgent Test ===\n")
    
    config = Config.from_file()
    agent = BrowserUseAgent(config=config, headless=True)
    
    try:
        print("Attempting to run a simple task...")
        result = agent("Go to example.com")
        print(f"Result type: {type(result)}")
        
        if asyncio.iscoroutine(result):
            print("Result is a coroutine, awaiting...")
            result = await result
            
        print(f"Final result: {result}")
        
    except Exception as e:
        print(f"\nError: {type(e).__name__}: {e}")
        print("\nFull traceback:")
        traceback.print_exc()
    
    finally:
        await agent.cleanup()


if __name__ == "__main__":
    asyncio.run(test_simple())