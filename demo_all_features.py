#!/usr/bin/env python3
"""Demo showcasing all ManusUse features with AWS Bedrock."""

from pathlib import Path
import tempfile

from manus_use import ManusAgent
from manus_use.config import Config
from manus_use.tools import file_write, file_read, code_execute, web_search


def main():
    """Run comprehensive demo of ManusUse features."""
    print("=== ManusUse Complete Feature Demo ===")
    print("Using AWS Bedrock with Claude Opus 4\n")
    
    # Load configuration
    config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
    
    # Create agent with all tools
    agent = ManusAgent(
        tools=[file_write, file_read, code_execute, web_search],
        config=config,
        enable_sandbox=False
    )
    
    print("✓ Agent initialized with all tools\n")
    
    # Demo 1: Web Search
    print("=" * 60)
    print("Demo 1: Web Search Capability")
    print("-" * 60)
    
    response = agent("Search for 'Python data visualization libraries' and summarize the top 3")
    print("Response:", response.content if hasattr(response, 'content') else str(response))
    
    # Demo 2: File Operations + Code Generation
    print("\n" + "=" * 60)
    print("Demo 2: File Operations + Code Generation")
    print("-" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        task = f"""
        1. Create a Python script at {tmpdir}/data_analysis.py that:
           - Generates sample data (10 random numbers between 1-100)
           - Calculates mean, median, and standard deviation
           - Prints the results
        2. Execute the script and show the output
        """
        
        response = agent(task)
        print("Response:", response.content if hasattr(response, 'content') else str(response))
    
    # Demo 3: Research + Report Generation
    print("\n" + "=" * 60)
    print("Demo 3: Research + Report Generation")
    print("-" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        task = f"""
        1. Search for information about "machine learning model deployment best practices"
        2. Create a markdown report at {tmpdir}/ml_deployment_guide.md with:
           - Introduction
           - Top 3 best practices based on your search
           - Conclusion
        3. Read the file and show me the content
        """
        
        response = agent(task)
        print("Response:", response.content if hasattr(response, 'content') else str(response)[:500] + "...")
    
    # Demo 4: Quick Tasks
    print("\n" + "=" * 60)
    print("Demo 4: Quick Tasks")
    print("-" * 60)
    
    tasks = [
        "Calculate the factorial of 7",
        "What's the current status of Python 4.0?",
        "Generate a haiku about AI agents"
    ]
    
    for task in tasks:
        print(f"\nTask: {task}")
        response = agent(task)
        print(f"Response: {response.content if hasattr(response, 'content') else str(response)}")
    
    print("\n" + "=" * 60)
    print("✅ Demo completed successfully!")
    print("\nManusUse demonstrates:")
    print("- Web search integration")
    print("- File operations (read/write)")
    print("- Code execution")
    print("- Complex task handling")
    print("- Integration with AWS Bedrock Claude Opus 4")


if __name__ == "__main__":
    main()