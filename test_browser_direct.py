#!/usr/bin/env python3
"""
Direct test of BrowserUseAgent without orchestrator.
Tests real-time data access capabilities.
"""

import asyncio
import logging
from pathlib import Path
from manus_use.agents.browser_use_agent import BrowserUseAgent
from manus_use.config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def test_browser_agent_direct():
    """Test BrowserUseAgent directly for real-time data"""
    logger.info("Testing BrowserUseAgent directly...")
    
    try:
        # Load configuration
        config = Config.from_file(Path("config.toml"))
        logger.info("Configuration loaded")
        
        # Create BrowserUseAgent directly
        browser_agent = BrowserUseAgent(config)
        logger.info("BrowserUseAgent created")
        
        # Simple test task
        task = "Go to https://www.google.com and tell me what the Google Doodle is today (if any)."
        
        logger.info(f"Running task: {task}")
        
        # Run the task
        result = await browser_agent.run_async(task)
        
        logger.info(f"Task completed!")
        logger.info(f"Result: {result}")
        
        return result
        
    except Exception as e:
        logger.error(f"Test failed: {e}", exc_info=True)
        raise

async def test_stock_price_direct():
    """Test getting real-time stock price"""
    logger.info("Testing stock price retrieval...")
    
    try:
        config = Config.from_file(Path("config.toml"))
        browser_agent = BrowserUseAgent(config)
        
        # Stock price task
        task = """
        Search for "AAPL stock price" on Google and tell me:
        1. The current stock price
        2. The percentage change today
        """
        
        logger.info(f"Running stock task: {task}")
        result = await browser_agent.run_async(task)
        
        logger.info(f"Stock task completed!")
        logger.info(f"Result: {result}")
        
        return result
        
    except Exception as e:
        logger.error(f"Stock test failed: {e}", exc_info=True)
        raise

async def test_weather_direct():
    """Test getting real-time weather"""
    logger.info("Testing weather retrieval...")
    
    try:
        config = Config.from_file(Path("config.toml"))
        browser_agent = BrowserUseAgent(config)
        
        # Weather task
        task = "Search for 'weather in New York' and tell me the current temperature."
        
        logger.info(f"Running weather task: {task}")
        result = await browser_agent.run_async(task)
        
        logger.info(f"Weather task completed!")
        logger.info(f"Result: {result}")
        
        return result
        
    except Exception as e:
        logger.error(f"Weather test failed: {e}", exc_info=True)
        raise

async def main():
    """Run all direct tests"""
    logger.info("="*60)
    logger.info("DIRECT BROWSERUSEAGENT TEST")
    logger.info("="*60)
    
    # Test 1: Basic browser functionality
    logger.info("\nTest 1: Google Homepage")
    logger.info("-"*30)
    try:
        await test_browser_agent_direct()
        logger.info("✓ Test 1 PASSED")
    except Exception as e:
        logger.error(f"✗ Test 1 FAILED: {e}")
    
    await asyncio.sleep(2)
    
    # Test 2: Stock price
    logger.info("\nTest 2: Stock Price")
    logger.info("-"*30)
    try:
        await test_stock_price_direct()
        logger.info("✓ Test 2 PASSED")
    except Exception as e:
        logger.error(f"✗ Test 2 FAILED: {e}")
    
    await asyncio.sleep(2)
    
    # Test 3: Weather
    logger.info("\nTest 3: Weather")
    logger.info("-"*30)
    try:
        await test_weather_direct()
        logger.info("✓ Test 3 PASSED")
    except Exception as e:
        logger.error(f"✗ Test 3 FAILED: {e}")
    
    logger.info("\n" + "="*60)
    logger.info("ALL TESTS COMPLETED")
    logger.info("="*60)

if __name__ == "__main__":
    asyncio.run(main())