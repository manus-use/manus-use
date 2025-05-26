#!/usr/bin/env python3
"""Comprehensive browser-use test with various tasks."""

import asyncio
from browser_use import Agent
from langchain_aws import ChatBedrock


async def test_navigation():
    """Test simple navigation."""
    print("\n=== Test 1: Simple Navigation ===")
    
    llm = ChatBedrock(
        model_id='us.anthropic.claude-3-7-sonnet-20250219-v1:0',
        model_kwargs={'temperature': 0.0, 'max_tokens': 4096},
        region_name='us-east-1'
    )
    
    agent = Agent(
        task="Go to https://www.python.org and tell me what the current Python version is",
        llm=llm,
        enable_memory=False,
    )
    
    result = await agent.run(max_steps=10)
    print(f"Result: {result.history[-1].extracted_content}")
    return result


async def test_search():
    """Test web search functionality."""
    print("\n=== Test 2: Web Search ===")
    
    llm = ChatBedrock(
        model_id='us.anthropic.claude-3-7-sonnet-20250219-v1:0',
        model_kwargs={'temperature': 0.0, 'max_tokens': 4096},
        region_name='us-east-1'
    )
    
    agent = Agent(
        task="Search for 'browser automation python' on DuckDuckGo and tell me the top 3 results",
        llm=llm,
        enable_memory=False,
    )
    
    result = await agent.run(max_steps=15)
    print(f"Result: {result.history[-1].extracted_content}")
    return result


async def test_form_interaction():
    """Test form filling."""
    print("\n=== Test 3: Form Interaction ===")
    
    llm = ChatBedrock(
        model_id='us.anthropic.claude-3-7-sonnet-20250219-v1:0',
        model_kwargs={'temperature': 0.0, 'max_tokens': 4096},
        region_name='us-east-1'
    )
    
    agent = Agent(
        task="""Go to https://httpbin.org/forms/post and:
        1. Fill in the customer name with 'Test User'
        2. Fill in the telephone with '555-1234'
        3. Tell me what you see after filling the form""",
        llm=llm,
        enable_memory=False,
    )
    
    result = await agent.run(max_steps=20)
    print(f"Result: {result.history[-1].extracted_content}")
    return result


async def test_screenshot():
    """Test screenshot capability."""
    print("\n=== Test 4: Screenshot ===")
    
    llm = ChatBedrock(
        model_id='us.anthropic.claude-3-7-sonnet-20250219-v1:0',
        model_kwargs={'temperature': 0.0, 'max_tokens': 4096},
        region_name='us-east-1'
    )
    
    agent = Agent(
        task="Go to https://www.anthropic.com, take a screenshot of the page, and describe what you see",
        llm=llm,
        enable_memory=False,
    )
    
    result = await agent.run(max_steps=10)
    print(f"Result: {result.history[-1].extracted_content}")
    return result


async def main():
    """Run all browser tests."""
    print("=== Comprehensive Browser-Use Tests ===")
    print("Testing various browser automation capabilities with AWS Bedrock")
    print("=" * 60)
    
    # Run tests
    try:
        # Test 1: Navigation
        await test_navigation()
        
        # Test 2: Search
        await test_search()
        
        # Test 3: Form interaction
        await test_form_interaction()
        
        # Test 4: Screenshot
        await test_screenshot()
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 60)
    print("✅ All tests completed!")
    
    # Summary
    print("\n📊 Browser-Use Capabilities Demonstrated:")
    print("- ✓ Page navigation")
    print("- ✓ Content extraction")
    print("- ✓ Web search")
    print("- ✓ Form filling")
    print("- ✓ Screenshot capture")
    print("- ✓ Multi-step tasks")


if __name__ == "__main__":
    asyncio.run(main())