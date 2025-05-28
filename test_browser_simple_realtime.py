#!/usr/bin/env python3
"""
Simple test for BrowserUseAgent real-time data access.
Tests a single task to verify the orchestrator properly routes to BrowserUseAgent.
"""

import asyncio
import logging
from pathlib import Path
from manus_use.multi_agents.orchestrator import Orchestrator
from manus_use.config import Config

# Configure logging for detailed output
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def test_browser_agent_routing():
    """Test that orchestrator correctly routes browser tasks to BrowserUseAgent"""
    logger.info("Starting BrowserUseAgent routing test...")
    
    try:
        # Load configuration
        config = Config.from_file(Path("config.toml"))
        
        logger.info("Configuration loaded successfully")
        
        # Create orchestrator
        orchestrator = Orchestrator(config)
        logger.info("Orchestrator created")
        
        # Simple browser task that requires real-time data
        task = """
        Go to https://www.google.com and search for "current time in New York".
        Tell me what time it shows.
        """
        
        logger.info(f"Submitting task: {task}")
        
        # Run the task
        result = await orchestrator.run_async(task)
        
        logger.info(f"Task completed successfully!")
        logger.info(f"Result: {result}")
        
        return result
        
    except Exception as e:
        logger.error(f"Test failed with error: {e}", exc_info=True)
        raise

async def test_weather_search():
    """Test real-time weather data retrieval"""
    logger.info("Starting weather search test...")
    
    try:
        config = Config.from_file(Path("config.toml"))
        orchestrator = Orchestrator(config)
        
        # Weather search task
        task = """
        Search for "weather in San Francisco" and tell me:
        1. Current temperature
        2. Weather conditions (sunny, cloudy, etc.)
        3. Today's high and low temperatures
        """
        
        logger.info(f"Submitting weather task: {task}")
        result = await orchestrator.run_async(task)
        
        logger.info(f"Weather search completed!")
        logger.info(f"Result: {result}")
        
        return result
        
    except Exception as e:
        logger.error(f"Weather test failed: {e}", exc_info=True)
        raise

async def test_stock_price():
    """Test real-time stock price retrieval"""
    logger.info("Starting stock price test...")
    
    try:
        config = Config.from_file(Path("config.toml"))
        orchestrator = Orchestrator(config)
        
        # Stock price task
        task = """
        Look up the current stock price for Apple (AAPL).
        Tell me:
        1. Current price
        2. Change today ($ and %)
        3. Market cap if available
        """
        
        logger.info(f"Submitting stock task: {task}")
        result = await orchestrator.run_async(task)
        
        logger.info(f"Stock price search completed!")
        logger.info(f"Result: {result}")
        
        return result
        
    except Exception as e:
        logger.error(f"Stock test failed: {e}", exc_info=True)
        raise

async def main():
    """Run the tests"""
    logger.info("="*60)
    logger.info("BROWSERUSEAGENT REAL-TIME DATA TEST")
    logger.info("="*60)
    
    # Test 1: Basic browser routing
    logger.info("\nTest 1: Browser Agent Routing")
    logger.info("-"*30)
    await test_browser_agent_routing()
    
    # Small delay between tests
    await asyncio.sleep(3)
    
    # Test 2: Weather search
    logger.info("\nTest 2: Weather Search")
    logger.info("-"*30)
    await test_weather_search()
    
    # Small delay between tests
    await asyncio.sleep(3)
    
    # Test 3: Stock price
    logger.info("\nTest 3: Stock Price Lookup")
    logger.info("-"*30)
    await test_stock_price()
    
    logger.info("\n" + "="*60)
    logger.info("ALL TESTS COMPLETED")
    logger.info("="*60)

if __name__ == "__main__":
    asyncio.run(main())