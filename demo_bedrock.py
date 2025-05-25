#!/usr/bin/env python3
"""Demo script showcasing ManusUse capabilities with AWS Bedrock."""

from pathlib import Path
import tempfile

from manus_use import ManusAgent
from manus_use.config import Config
from manus_use.tools import file_write, file_read, code_execute


def main():
    """Run demo showcasing ManusUse capabilities."""
    print("=== ManusUse Demo with AWS Bedrock (Claude Opus) ===\n")
    
    # Load configuration
    config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
    
    # Create agent with multiple tools
    agent = ManusAgent(
        tools=[file_write, file_read, code_execute],
        config=config,
        enable_sandbox=False
    )
    
    print("Agent initialized with file operations and code execution tools.\n")
    
    # Demo 1: Create and analyze data
    print("Demo 1: Data Creation and Analysis")
    print("-" * 40)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Complex task
        task = f"""
        Please complete the following tasks:
        1. Create a CSV file at {tmpdir}/sales_data.csv with sample sales data for 5 products over 3 months
        2. Write a Python script at {tmpdir}/analyze_sales.py that reads the CSV and calculates total sales per product
        3. Execute the script and show me the results
        """
        
        print("Task:", task.strip())
        print("\nAgent working...\n")
        
        response = agent(task)
        
        print("Agent Response:")
        print("-" * 40)
        print(response.content if hasattr(response, 'content') else str(response))
    
    print("\n" + "=" * 60 + "\n")
    
    # Demo 2: Code generation
    print("Demo 2: Code Generation")
    print("-" * 40)
    
    task = """
    Create a Python function that implements the QuickSort algorithm.
    Include proper documentation and then test it with a sample list [64, 34, 25, 12, 22, 11, 90].
    """
    
    print("Task:", task.strip())
    print("\nAgent working...\n")
    
    response = agent(task)
    
    print("Agent Response:")
    print("-" * 40)
    print(response.content if hasattr(response, 'content') else str(response))
    
    print("\n✅ Demo completed successfully!")


if __name__ == "__main__":
    main()