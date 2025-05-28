#!/usr/bin/env python3
"""Simple test to check for vulnerabilities using browser_use_agent with visible browser."""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.agents.browser_use_agent import BrowserUseAgent
from manus_use.config import Config


async def check_vulnerabilities():
    """Use browser to check for recent vulnerabilities."""
    print("🔍 Checking for Recent Security Vulnerabilities")
    print("=" * 60)
    
    # Load config from config.toml with headless=False
    config = Config.from_file(Path("config.toml"))
    config.browser_use.headless = False  # Ensure browser is visible
    
    print(f"Using configuration from config.toml:")
    print(f"  Provider: {config.browser_use.provider}")
    print(f"  Model: {config.browser_use.model}")
    print(f"  Headless: {config.browser_use.headless}")
    print(f"  Browser will be VISIBLE\n")
    
    try:
        # Create browser agent
        agent = BrowserUseAgent(config=config)
        
        # Simpler task - just check one security site
        print("📋 Task: Checking latest vulnerabilities on SecurityWeek...")
        task = """
        Go to SecurityWeek.com and find the 2 most recent vulnerability articles.
        For each article, extract:
        1. Title
        2. Date published
        3. Brief summary (1-2 sentences)
        4. Affected systems or vendors mentioned
        
        Focus on the most recent articles about vulnerabilities or security flaws.
        """
        
        print("🌐 Opening visible browser...\n")
        result = await agent(task)
        
        print("✅ Results:")
        print("-" * 60)
        print(result)
        print("-" * 60)
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n✅ Test completed!")
    print("The browser was running in visible mode (headless=False)")


async def main():
    """Run the vulnerability check."""
    await check_vulnerabilities()


if __name__ == "__main__":
    asyncio.run(main())