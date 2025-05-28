#!/usr/bin/env python3
"""Test multi-agent orchestrator with vulnerability assessment request."""

import asyncio
import logging
from src.manus_use.multi_agents import Orchestrator
from src.manus_use.config import Config

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

async def main():
    """Run the multi-agent orchestrator with vulnerability assessment request."""
    
    # Load configuration
    config = Config.from_file()
    
    # Override browser settings to use headless=False
    config.browser_use.headless = False
    
    # Create orchestrator
    orchestrator = Orchestrator(config=config)
    
    # The request to assess vulnerabilities
    request = "assess the latest 2 vulnerabilities in May 2025"
    
    print(f"\n{'='*60}")
    print(f"Running multi-agent orchestrator with request:")
    print(f"'{request}'")
    print(f"Browser mode: headless={config.browser_use.headless}")
    print(f"{'='*60}\n")
    
    try:
        # Run the orchestrator
        result = await orchestrator.run_async(request)
        
        # Display results
        print(f"\n{'='*60}")
        print("RESULTS:")
        print(f"{'='*60}")
        print(f"Success: {result.success}")
        
        if result.success:
            print(f"\nOutput:")
            print(result.output)
        else:
            print(f"\nError:")
            print(result.error)
            
        print(f"{'='*60}\n")
        
    except Exception as e:
        print(f"\nError running orchestrator: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())