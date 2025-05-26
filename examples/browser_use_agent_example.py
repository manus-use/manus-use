"""Example of using BrowserUseAgent - browser-use as a Strands Agent."""

from manus_use.agents import BrowserUseAgent
from manus_use.config import Config


def example_browser_use_agent():
    """Example of using browser-use directly as a Strands Agent."""
    print("=== BrowserUseAgent Example ===\n")
    
    # Load configuration
    config = Config.from_file()
    
    # Create BrowserUseAgent - it's a full Strands Agent
    browser_agent = BrowserUseAgent(config=config, headless=True)
    print("✓ BrowserUseAgent created\n")
    
    # Example 1: Simple navigation and extraction
    print("Example 1: Get Python version from python.org")
    result = browser_agent("Go to python.org and tell me what the latest Python version is")
    print(f"Result: {result}\n")
    
    # Example 2: Search and summarize
    print("Example 2: Search for information")
    result = browser_agent(
        "Search for 'Strands SDK Python' on Google and summarize what you find "
        "about this framework from the first few results"
    )
    print(f"Result: {result[:300]}...\n" if len(result) > 300 else f"Result: {result}\n")
    
    # Example 3: Complex multi-step task
    print("Example 3: Multi-step GitHub task")
    result = browser_agent(
        "Go to GitHub, search for 'anthropics/anthropic-sdk-python', "
        "navigate to the repository, and tell me: "
        "1) How many stars it has, "
        "2) When it was last updated, "
        "3) What the main programming language is"
    )
    print(f"Result: {result}\n")
    
    # Cleanup
    import asyncio
    asyncio.run(browser_agent.cleanup())
    print("✓ Browser cleaned up")


def compare_approaches():
    """Compare the three different approaches to browser automation."""
    print("\n=== Comparison of Browser Automation Approaches ===\n")
    
    print("1. Original BrowserAgent with micro-tools:")
    print("   - Uses individual tools: browser_navigate, browser_click, etc.")
    print("   - Agent orchestrates each micro-action")
    print("   - Limited by what the agent can coordinate")
    print("   - Example: agent.tool.browser_navigate(url='...')")
    
    print("\n2. BrowserAgent with browser_do tool:")
    print("   - Uses single browser_do tool with natural language")
    print("   - Tool internally uses browser-use agent")
    print("   - More flexible but still goes through tool system")
    print("   - Example: agent.tool.browser_do(task='Go to ...')")
    
    print("\n3. BrowserUseAgent (browser-use as Strands Agent):")
    print("   - browser-use IS the agent, not just a tool")
    print("   - Direct delegation, no tool overhead")
    print("   - Maximum flexibility and capability")
    print("   - Example: agent('Go to ...')")
    
    print("\nRecommendation: Use BrowserUseAgent for maximum capability!")


if __name__ == "__main__":
    # Run the example
    example_browser_use_agent()
    
    # Show comparison
    compare_approaches()