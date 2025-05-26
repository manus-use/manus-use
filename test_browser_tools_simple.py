"""Simple test for browser_tools.py."""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.tools.browser_tools import browser_do, browser_cleanup


async def test_simple():
    """Test a simple browser task."""
    print("Testing browser_tools.py with a simple task...")
    
    # Test browser_do
    result = await browser_do(
        task="Go to https://example.com and tell me what the main heading says",
        headless=True
    )
    
    print(f"\nResult: {result}")
    print(f"Success: {result.get('success')}")
    
    if result.get('success'):
        print(f"Browser result: {result.get('result')}")
    else:
        print(f"Error: {result.get('error')}")
    
    # Cleanup
    cleanup_result = await browser_cleanup()
    print(f"\nCleanup: {cleanup_result}")


if __name__ == "__main__":
    asyncio.run(test_simple())