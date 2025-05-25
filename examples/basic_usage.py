"""Basic usage examples for ManusUse."""

from manus_use import ManusAgent, BrowserAgent, DataAnalysisAgent
from manus_use.tools import file_read, file_write, code_execute


def example_manus_agent():
    """Example using the Manus agent."""
    print("=== Manus Agent Example ===")
    
    # Create agent with specific tools
    agent = ManusAgent(tools=[file_read, file_write, code_execute])
    
    # Use the agent
    response = agent(
        "Create a Python script that generates the Fibonacci sequence "
        "up to n=10 and save it to fibonacci.py"
    )
    print(response)


def example_browser_agent():
    """Example using the Browser agent."""
    print("\n=== Browser Agent Example ===")
    
    # Create browser agent
    agent = BrowserAgent()
    
    # Search and extract information
    response = agent(
        "Search for information about the latest Python version "
        "and summarize the key new features"
    )
    print(response)


def example_data_analysis():
    """Example using the Data Analysis agent."""
    print("\n=== Data Analysis Agent Example ===")
    
    # Create data analysis agent
    agent = DataAnalysisAgent()
    
    # Analyze data
    response = agent(
        "Create sample sales data for the last 12 months and "
        "generate a trend analysis with visualization"
    )
    print(response)


def example_custom_config():
    """Example with custom configuration."""
    print("\n=== Custom Configuration Example ===")
    
    from manus_use.config import Config, LLMConfig
    
    # Create custom config
    config = Config(
        llm=LLMConfig(
            provider="openai",
            model="gpt-4",
            temperature=0.7,
            max_tokens=2000
        )
    )
    
    # Create agent with custom config
    agent = ManusAgent(config=config)
    
    response = agent("Write a haiku about AI agents")
    print(response)


if __name__ == "__main__":
    # Run examples
    try:
        example_manus_agent()
    except Exception as e:
        print(f"Manus agent example failed: {e}")
        
    try:
        example_browser_agent()
    except Exception as e:
        print(f"Browser agent example failed: {e}")
        
    try:
        example_data_analysis()
    except Exception as e:
        print(f"Data analysis example failed: {e}")
        
    try:
        example_custom_config()
    except Exception as e:
        print(f"Custom config example failed: {e}")