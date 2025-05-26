#!/usr/bin/env python3
"""Test the manus-use BrowserAgent wrapper."""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from src.manus_use.agents.browser import BrowserAgent
from src.manus_use.config import Config


def main():
    """Test BrowserAgent with AWS Bedrock."""
    print("=== Testing manus-use BrowserAgent ===\n")
    
    # Load config with Bedrock settings
    config_path = Path(__file__).parent / "config" / "config.bedrock.toml"
    config = Config.from_file(config_path)
    
    print(f"Using model: {config.llm.model}")
    print(f"Provider: {config.llm.provider}")
    print(f"Browser headless: {config.tools.browser_headless}\n")
    
    # Create BrowserAgent
    print("Creating BrowserAgent...")
    try:
        browser_agent = BrowserAgent(
            config=config,
            headless=config.tools.browser_headless
        )
        print("✓ BrowserAgent created successfully\n")
        
        # Test simple navigation
        print("Testing navigation...")
        result = browser_agent(
            "Go to https://example.com and tell me what the page title is"
        )
        
        print(f"\n✓ Navigation test completed!")
        print(f"Result: {result}")
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n✅ Test completed!")


if __name__ == "__main__":
    main()