#!/usr/bin/env python3
"""Simple test for browser agent with vulnerability assessment."""

import asyncio
import logging
from src.manus_use.agents import BrowserUseAgent
from src.manus_use.config import Config

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

async def main():
    """Run browser agent to assess vulnerabilities."""
    
    # Load configuration
    config = Config.from_file()
    
    # Create browser agent with headless=False
    browser_agent = BrowserUseAgent(
        config=config,
        headless=False,  # Show browser window
        enable_memory=True
    )
    
    # The request to assess vulnerabilities
    request = "Search for and assess the latest 2 critical vulnerabilities from May 2025. If May 2025 hasn't occurred yet, find the 2 most recent critical vulnerabilities. For each vulnerability, provide: CVE ID, affected systems, severity score, and brief description."
    
    print(f"\n{'='*60}")
    print(f"Running BrowserUseAgent with request:")
    print(f"'{request}'")
    print(f"Browser mode: headless=False")
    print(f"{'='*60}\n")
    
    try:
        # Run the browser agent
        print("Starting browser agent...")
        result = await browser_agent(request)
        
        # Display results
        print(f"\n{'='*60}")
        print("RESULTS:")
        print(f"{'='*60}")
        print(result)
        print(f"{'='*60}\n")
        
    except Exception as e:
        print(f"\nError running browser agent: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        if hasattr(browser_agent, 'cleanup'):
            await browser_agent.cleanup()

if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())