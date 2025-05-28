#!/usr/bin/env python3
"""
Test browser-use library directly to verify it's working.
"""

import asyncio
from browser_use import Agent
from browser_use.browser.browser import Browser, BrowserConfig
from browser_use.browser.context import BrowserContext
from langchain_anthropic import ChatAnthropic
import os

async def test_browser_use_basic():
    """Test basic browser-use functionality"""
    print("Testing browser-use library...")
    
    # Create LLM
    llm = ChatAnthropic(
        model_name="claude-3-5-sonnet-20241022",
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
        temperature=0
    )
    
    # Create browser
    browser = Browser(config=BrowserConfig(headless=True))
    async with browser.session() as session:
        # Create agent
        agent = Agent(
            task="Go to https://www.example.com and tell me the main heading",
            llm=llm,
            browser_context=session
        )
        
        # Run agent
        result = await agent.run()
        print(f"Result: {result}")
        
    return result

async def test_browser_use_search():
    """Test search functionality"""
    print("\nTesting search functionality...")
    
    llm = ChatAnthropic(
        model_name="claude-3-5-sonnet-20241022",
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
        temperature=0
    )
    
    browser = Browser(config=BrowserConfig(headless=True))
    async with browser.session() as session:
        agent = Agent(
            task="Search for 'OpenAI' on Google and tell me the first result",
            llm=llm,
            browser_context=session
        )
        
        result = await agent.run()
        print(f"Search result: {result}")
        
    return result

async def test_browser_use_realtime():
    """Test real-time data retrieval"""
    print("\nTesting real-time data...")
    
    llm = ChatAnthropic(
        model_name="claude-3-5-sonnet-20241022",
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
        temperature=0
    )
    
    browser = Browser(config=BrowserConfig(headless=True))
    async with browser.session() as session:
        agent = Agent(
            task="Go to https://time.is and tell me what time it shows",
            llm=llm,
            browser_context=session
        )
        
        result = await agent.run()
        print(f"Time result: {result}")
        
    return result

async def main():
    """Run all tests"""
    print("="*60)
    print("BROWSER-USE LIBRARY TEST")
    print("="*60)
    
    # Check API key
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY not set")
        return
    
    try:
        # Test 1: Basic functionality
        print("\nTest 1: Basic Browser-Use")
        print("-"*30)
        await test_browser_use_basic()
        print("✓ Test 1 completed")
        
        await asyncio.sleep(2)
        
        # Test 2: Search
        print("\nTest 2: Search Functionality")
        print("-"*30)
        await test_browser_use_search()
        print("✓ Test 2 completed")
        
        await asyncio.sleep(2)
        
        # Test 3: Real-time data
        print("\nTest 3: Real-time Data")
        print("-"*30)
        await test_browser_use_realtime()
        print("✓ Test 3 completed")
        
    except Exception as e:
        print(f"Test failed: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "="*60)
    print("ALL TESTS COMPLETED")
    print("="*60)

if __name__ == "__main__":
    asyncio.run(main())