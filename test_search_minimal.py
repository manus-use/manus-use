#!/usr/bin/env python3
"""Minimal test of web search tool."""

from pathlib import Path
from manus_use import ManusAgent
from manus_use.config import Config
from manus_use.tools import web_search

print("Testing web search with ManusUse...")

# Create a simple search function that doesn't use the agent
print("\n1. Testing search tool directly:")
try:
    results = web_search("Python programming", max_results=2)
    print(f"✓ Found {len(results)} results")
    for r in results:
        print(f"  - {r.get('title', 'No title')}")
except Exception as e:
    print(f"✗ Direct search failed: {e}")

# Now test with agent
print("\n2. Testing search with agent:")
try:
    config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
    agent = ManusAgent(
        tools=[web_search],
        config=config,
        enable_sandbox=False
    )
    
    response = agent("Search for 'Python programming' and list the first 2 results")
    print(f"✓ Agent response: {response.content if hasattr(response, 'content') else str(response)[:200]}...")
except Exception as e:
    print(f"✗ Agent search failed: {e}")
    import traceback
    traceback.print_exc()