#!/usr/bin/env python3
"""Direct test of DuckDuckGo search."""

try:
    print("Testing DuckDuckGo search directly...")
    from duckduckgo_search import DDGS
    
    with DDGS() as ddgs:
        results = list(ddgs.text("Python programming", max_results=3))
        
    print(f"\nFound {len(results)} results:")
    for i, result in enumerate(results, 1):
        print(f"\nResult {i}:")
        print(f"  Title: {result.get('title', 'No title')}")
        print(f"  Link: {result.get('link', 'No link')}")
        print(f"  Body: {result.get('body', 'No body')[:100]}...")
        
except Exception as e:
    print(f"\nError: {e}")
    print(f"Error type: {type(e).__name__}")
    
    # Try with different parameters
    print("\nTrying with different approach...")
    try:
        from duckduckgo_search import DDGS
        
        ddgs = DDGS()
        results = list(ddgs.text("test", max_results=1))
        print(f"Alternative approach worked: {len(results)} results")
    except Exception as e2:
        print(f"Alternative approach also failed: {e2}")