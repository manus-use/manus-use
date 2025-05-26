"""Test browser_tools.py functionality."""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.tools.browser_tools import (
    browser_do,
    browser_navigate,
    browser_search_google,
    browser_extract_content,
    browser_get_page_info,
    browser_scroll_down,
    browser_click_element,
    browser_input_text,
    browser_cleanup
)


async def test_browser_tools():
    """Test various browser tools."""
    print("Testing browser_tools.py...")
    print("=" * 60)
    
    # Test 1: Basic navigation with browser_do
    print("\n=== Test 1: browser_do navigation ===")
    result = await browser_do(
        task="Go to https://example.com and tell me what the main heading says"
    )
    print(f"Result: {result}")
    print(f"Success: {result.get('success')}")
    
    # Test 2: Direct navigation
    print("\n=== Test 2: browser_navigate ===")
    result = await browser_navigate(url="https://www.python.org")
    print(f"Result: {result}")
    print(f"Success: {result.get('success')}")
    
    # Test 3: Get page info
    print("\n=== Test 3: browser_get_page_info ===")
    result = await browser_get_page_info()
    print(f"Result: {result}")
    print(f"Success: {result.get('success')}")
    
    # Test 4: Extract content
    print("\n=== Test 4: browser_extract_content ===")
    result = await browser_extract_content(
        goal="the latest Python version mentioned on the page"
    )
    print(f"Result: {result}")
    print(f"Success: {result.get('success')}")
    
    # Test 5: Search Google
    print("\n=== Test 5: browser_search_google ===")
    result = await browser_search_google(query="Strands SDK Python")
    print(f"Result: {result}")
    print(f"Success: {result.get('success')}")
    
    # Test 6: Complex task with browser_do
    print("\n=== Test 6: Complex browser_do task ===")
    result = await browser_do(
        task="Go to https://github.com and search for 'strands sdk', then tell me how many stars the first result has"
    )
    print(f"Result: {result}")
    print(f"Success: {result.get('success')}")
    
    # Cleanup
    print("\n=== Cleanup ===")
    result = await browser_cleanup()
    print(f"Cleanup result: {result}")
    
    print("\n" + "=" * 60)
    print("All tests completed!")


async def test_individual_tools():
    """Test individual browser tool functions."""
    print("\n\nTesting individual browser tools...")
    print("=" * 60)
    
    # Test navigation and interaction
    print("\n=== Test: Navigation and interaction ===")
    
    # Navigate to a form page
    await browser_navigate("https://www.w3schools.com/html/html_forms.asp")
    
    # Scroll down to see more content
    await browser_scroll_down(pixels=500)
    
    # Try to interact with elements (this will use browser_do internally)
    result = await browser_click_element("Try it Yourself button")
    print(f"Click result: {result}")
    
    # Cleanup
    await browser_cleanup()
    
    print("\nIndividual tools test completed!")


async def test_error_handling():
    """Test error handling in browser tools."""
    print("\n\nTesting error handling...")
    print("=" * 60)
    
    # Test with invalid URL
    print("\n=== Test: Invalid URL ===")
    result = await browser_navigate("not-a-valid-url")
    print(f"Result: {result}")
    print(f"Success: {result.get('success')}")
    print(f"Error: {result.get('error')}")
    
    # Test with impossible task
    print("\n=== Test: Impossible task ===")
    result = await browser_do(
        task="Click on a button that definitely does not exist: XYZ123ABC"
    )
    print(f"Result: {result}")
    print(f"Success: {result.get('success')}")
    
    # Cleanup
    await browser_cleanup()
    
    print("\nError handling test completed!")


async def main():
    """Run all tests."""
    try:
        # Run basic tests
        await test_browser_tools()
        
        # Run individual tool tests
        await test_individual_tools()
        
        # Run error handling tests
        await test_error_handling()
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Ensure cleanup
        await browser_cleanup()


if __name__ == "__main__":
    print("Starting browser_tools.py tests...")
    print("Note: This will open browser windows and perform actual web browsing.")
    print("Make sure you have AWS credentials configured for Bedrock.\n")
    
    asyncio.run(main())