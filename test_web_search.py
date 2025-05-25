#!/usr/bin/env python3
"""Test web search functionality for ManusUse."""

import asyncio
from pathlib import Path


async def test_web_search_tool():
    """Test the web search tool directly."""
    print("=== Testing Web Search Tool ===\n")
    
    # Test 1: Direct tool usage
    print("1. Testing web search tool directly...")
    try:
        from manus_use.tools.web_search import web_search_sync
        
        results = web_search_sync("Python programming", max_results=3)
        print(f"✓ Found {len(results)} results")
        
        for i, result in enumerate(results, 1):
            print(f"\nResult {i}:")
            print(f"  Title: {result.get('title', 'No title')}")
            print(f"  URL: {result.get('url', 'No URL')}")
            print(f"  Snippet: {result.get('snippet', 'No snippet')[:100]}...")
            
    except Exception as e:
        print(f"✗ Direct web search failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 2: Web search with agent
    print("\n\n2. Testing web search with agent...")
    try:
        from manus_use import ManusAgent
        from manus_use.config import Config
        from manus_use.tools import web_search
        
        config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
        
        agent = ManusAgent(
            tools=[web_search],
            config=config,
            enable_sandbox=False
        )
        
        # Test various search queries
        queries = [
            "What is AWS Bedrock?",
            "Latest news about Claude AI 2024",
            "Python asyncio tutorial"
        ]
        
        for query in queries:
            print(f"\nSearching for: '{query}'")
            response = agent(f"Search for '{query}' and summarize what you find in 2-3 sentences.")
            
            content = response.content if hasattr(response, 'content') else str(response)
            print(f"✓ Agent response: {content[:300]}...")
            
    except Exception as e:
        print(f"✗ Agent web search failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 3: Complex search task
    print("\n\n3. Testing complex search task...")
    try:
        from manus_use.tools import web_search, file_write
        
        agent = ManusAgent(
            tools=[web_search, file_write],
            config=config,
            enable_sandbox=False
        )
        
        # Complex task combining search and file operations
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            task = f"""
            Search for information about 'machine learning frameworks comparison 2024'.
            Create a summary of the top 3 frameworks mentioned and save it to {tmpdir}/ml_frameworks.txt
            """
            
            print(f"Task: {task.strip()}")
            response = agent(task)
            
            print(f"\n✓ Complex task completed")
            
            # Check if file was created
            summary_file = Path(tmpdir) / "ml_frameworks.txt"
            if summary_file.exists():
                print(f"✓ Summary file created")
                print(f"✓ File content preview: {summary_file.read_text()[:200]}...")
            else:
                print("✗ Summary file was not created")
                
    except Exception as e:
        print(f"✗ Complex search task failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n\n✅ All web search tests completed successfully!")
    return True


async def test_search_engine_config():
    """Test search engine configuration."""
    print("\n=== Testing Search Engine Configuration ===\n")
    
    try:
        from manus_use.config import Config
        from manus_use.tools.web_search import get_search_engine, DuckDuckGoSearch
        
        # Test default configuration
        config = Config()
        print(f"✓ Default search engine: {config.tools.search_engine}")
        print(f"✓ Max search results: {config.tools.max_search_results}")
        
        # Test search engine instance
        engine = get_search_engine(config)
        print(f"✓ Search engine type: {type(engine).__name__}")
        
        # Verify it's DuckDuckGo by default
        assert isinstance(engine, DuckDuckGoSearch), "Default should be DuckDuckGo"
        print("✓ Default search engine is DuckDuckGo")
        
    except Exception as e:
        print(f"✗ Configuration test failed: {e}")
        return False
    
    return True


async def main():
    """Run all web search tests."""
    print("ManusUse Web Search Test Suite")
    print("=" * 50)
    
    tests = [
        test_web_search_tool,
        test_search_engine_config,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if await test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} crashed: {e}")
            failed += 1
    
    print("\n" + "=" * 50)
    print(f"Tests passed: {passed}")
    print(f"Tests failed: {failed}")
    
    if failed == 0:
        print("\n✅ All web search tests passed!")
    else:
        print(f"\n❌ {failed} tests failed")


if __name__ == "__main__":
    asyncio.run(main())