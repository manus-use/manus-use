#!/usr/bin/env python3
"""Simple test for BrowserUseAgent to verify basic functionality."""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.agents.browser_use_agent import BrowserUseAgent
from manus_use.config import Config


async def test_simple():
    """Test basic BrowserUseAgent functionality."""
    print("Testing BrowserUseAgent...")
    
    # Create config
    config = Config()
    config.llm.provider = "bedrock"
    config.llm.model = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
    
    # Create agent
    agent = BrowserUseAgent(config=config)
    
    # Test 1: Simple calculation (no browser needed)
    print("\n1. Testing simple calculation...")
    try:
        result = await agent("What is 2+2?")
        print(f"✅ Result: {result}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Test 2: Basic web navigation
    print("\n2. Testing web navigation...")
    try:
        result = await agent("Go to https://example.com and tell me the page title")
        print(f"✅ Result: {result[:100]}..." if len(str(result)) > 100 else f"✅ Result: {result}")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Test 3: Streaming
    print("\n3. Testing streaming...")
    try:
        events = []
        async for event in agent.stream_async("What is the capital of France?"):
            events.append(event)
            if event.get("type") == "token":
                print(event.get("data", ""), end="", flush=True)
        print(f"\n✅ Received {len(events)} streaming events")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    print("\nTest completed!")


if __name__ == "__main__":
    asyncio.run(test_simple())