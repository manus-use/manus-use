#!/usr/bin/env python3
"""
Test script for BrowserUseAgent to access real-time data through orchestrator.
This tests complex tasks requiring web browsing capabilities.
"""

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from manus_use.multi_agents.orchestrator import Orchestrator
from manus_use.config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def test_realtime_stock_data():
    """Test fetching real-time stock market data"""
    logger.info("Testing real-time stock market data retrieval...")
    
    config = Config.from_file(Path("config.toml"))
    orchestrator = Orchestrator(config)
    
    # Complex task requiring real-time web data
    task = """
    Please get me the current stock price and today's performance for:
    1. Apple (AAPL)
    2. Microsoft (MSFT)
    3. Google (GOOGL)
    
    Also provide the current market indices:
    - S&P 500
    - Dow Jones
    - NASDAQ
    
    Include the timestamp of when this data was retrieved.
    """
    
    result = await orchestrator.run(task)
    logger.info(f"Stock market data result:\n{result}")
    return result

async def test_realtime_weather_data():
    """Test fetching real-time weather data"""
    logger.info("Testing real-time weather data retrieval...")
    
    config = Config.from_file(Path("config.toml"))
    orchestrator = Orchestrator(config)
    
    # Task requiring current weather information
    task = """
    Get the current weather conditions and 3-day forecast for:
    1. New York City
    2. San Francisco
    3. London
    
    Include:
    - Current temperature
    - Weather conditions
    - Humidity
    - Wind speed
    - Forecast summary for next 3 days
    """
    
    result = await orchestrator.run_async(task)
    logger.info(f"Weather data result:\n{result}")
    return result

async def test_realtime_news_data():
    """Test fetching real-time news data"""
    logger.info("Testing real-time news data retrieval...")
    
    config = Config.from_file(Path("config.toml"))
    orchestrator = Orchestrator(config)
    
    # Task requiring current news
    task = """
    Find the top 5 latest technology news headlines from today.
    Include:
    - Headline
    - Brief summary
    - Source
    - Publication time
    
    Focus on AI, cybersecurity, or major tech company news.
    """
    
    result = await orchestrator.run_async(task)
    logger.info(f"News data result:\n{result}")
    return result

async def test_complex_research_task():
    """Test a complex research task requiring multiple web searches"""
    logger.info("Testing complex research task...")
    
    config = Config.from_file(Path("config.toml"))
    orchestrator = Orchestrator(config)
    
    # Complex multi-step research task
    task = """
    Research the current state of quantum computing in 2025:
    
    1. Find the latest breakthroughs in quantum computing from the past month
    2. Identify the top 3 companies leading in quantum computing
    3. Get their current stock prices if publicly traded
    4. Find any recent announcements or press releases
    5. Summarize the current challenges and future outlook
    
    Provide sources for all information.
    """
    
    result = await orchestrator.run_async(task)
    logger.info(f"Research task result:\n{result}")
    return result

async def test_realtime_crypto_data():
    """Test fetching real-time cryptocurrency data"""
    logger.info("Testing real-time cryptocurrency data retrieval...")
    
    config = Config.from_file(Path("config.toml"))
    orchestrator = Orchestrator(config)
    
    # Task requiring current crypto prices
    task = """
    Get the current prices and 24-hour changes for:
    1. Bitcoin (BTC)
    2. Ethereum (ETH)
    3. Solana (SOL)
    
    Also provide:
    - Total crypto market cap
    - Bitcoin dominance percentage
    - Top 3 trending cryptocurrencies today
    
    Include data source and timestamp.
    """
    
    result = await orchestrator.run_async(task)
    logger.info(f"Crypto data result:\n{result}")
    return result

async def main():
    """Run all tests"""
    logger.info(f"Starting BrowserUseAgent real-time data tests at {datetime.now()}")
    
    try:
        # Run tests sequentially to avoid overwhelming the browser
        results = {}
        
        # Test 1: Stock market data
        results['stocks'] = test_realtime_stock_data()
        await asyncio.sleep(2)  # Brief pause between tests
        
        # Test 2: Weather data
        results['weather'] = await test_realtime_weather_data()
        await asyncio.sleep(2)
        
        # Test 3: News data
        results['news'] = await test_realtime_news_data()
        await asyncio.sleep(2)
        
        # Test 4: Complex research
        results['research'] = await test_complex_research_task()
        await asyncio.sleep(2)
        
        # Test 5: Cryptocurrency data
        results['crypto'] = await test_realtime_crypto_data()
        
        # Summary
        logger.info("\n" + "="*60)
        logger.info("TEST SUMMARY")
        logger.info("="*60)
        for test_name, result in results.items():
            status = "✓ PASSED" if result else "✗ FAILED"
            logger.info(f"{test_name.upper()}: {status}")
        logger.info("="*60 + "\n")
        
    except Exception as e:
        logger.error(f"Test failed with error: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    asyncio.run(main())