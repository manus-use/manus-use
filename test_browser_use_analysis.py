#!/usr/bin/env python3
"""Multi-agent test to analyze browser-use documentation."""

import asyncio
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.manus_use.multi_agents import FlowOrchestrator
from src.manus_use.config import Config


async def analyze_browser_use_docs():
    """Use multi-agent system to analyze browser-use documentation."""
    
    print("=== Browser-Use Documentation Analysis ===\n")
    
    # Load configuration
    config_path = Path(__file__).parent / "config" / "config.bedrock.toml"
    if not config_path.exists():
        print(f"Error: Configuration file not found at {config_path}")
        print("Please ensure config/config.bedrock.toml exists")
        return
    
    config = Config.from_file(config_path)
    
    # Create orchestrator
    orchestrator = FlowOrchestrator(config=config)
    
    # Complex request that will use multiple agents
    request = """
    Analyze the browser-use documentation at https://deepwiki.com/browser-use/browser-use and create a comprehensive report:
    
    1. Use the browser agent to navigate to the page and extract all key information including:
       - What is browser-use and its main purpose
       - Key features and capabilities
       - Installation instructions
       - Basic usage examples
       - Advanced features
       - Architecture overview
       - Best practices
       - Common use cases
       - Any code examples provided
    
    2. After extraction, analyze the information and create a well-structured markdown report that includes:
       - Executive summary
       - Feature comparison with similar tools
       - Step-by-step setup guide
       - Code examples with explanations
       - Architecture diagram (if available)
       - Best practices section
       - Pros and cons analysis
       - Recommendations for different use cases
    
    3. Save the final report to 'browser_use_analysis.md' with proper markdown formatting.
    
    Be thorough and extract ALL relevant information from the documentation.
    """
    
    try:
        print("Starting multi-agent analysis...")
        print("This may take several minutes...\n")
        
        # Run the orchestrator
        result = await orchestrator.run_async(request)
        
        print("\n=== Analysis Complete ===")
        print(f"Result: {result}")
        
        # Check if the file was created
        output_file = Path("browser_use_analysis.md")
        if output_file.exists():
            print(f"\n✓ Report saved to: {output_file}")
            print(f"  File size: {output_file.stat().st_size} bytes")
            
            # Display first few lines
            with open(output_file, 'r') as f:
                lines = f.readlines()[:10]
                print("\nFirst 10 lines of the report:")
                print("-" * 50)
                for line in lines:
                    print(line.rstrip())
                if len(lines) == 10:
                    print("...")
        else:
            print("\n✗ Output file not created")
            
    except Exception as e:
        print(f"\n✗ Error during analysis: {e}")
        import traceback
        traceback.print_exc()


async def test_planning_only():
    """Test just the planning phase to see how tasks are decomposed."""
    
    print("\n=== Testing Planning Phase ===\n")
    
    config_path = Path(__file__).parent / "config" / "config.bedrock.toml"
    config = Config.from_file(config_path)
    
    orchestrator = FlowOrchestrator(config=config)
    planner = orchestrator.agents.get("planner")
    
    if planner:
        # Create a plan for the browser-use analysis
        request = """
        Analyze https://deepwiki.com/browser-use/browser-use documentation 
        and create a comprehensive markdown report with all features, 
        setup instructions, and best practices.
        """
        
        print("Creating task plan...")
        plan = planner.create_plan(request)
        
        print(f"\nGenerated {len(plan)} tasks:\n")
        for i, task in enumerate(plan, 1):
            print(f"{i}. Task ID: {task.task_id}")
            print(f"   Agent: {task.agent_type}")
            print(f"   Description: {task.description}")
            print(f"   Dependencies: {task.dependencies}")
            print(f"   Priority: {task.priority}")
            print()


def main():
    """Run the browser-use analysis."""
    
    print("Browser-Use Multi-Agent Analysis Test")
    print("=" * 50)
    
    # Create event loop and run
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        # First test planning
        loop.run_until_complete(test_planning_only())
        
        # Then run full analysis
        print("\n" + "=" * 50)
        user_input = input("\nProceed with full analysis? (y/n): ")
        
        if user_input.lower() == 'y':
            loop.run_until_complete(analyze_browser_use_docs())
        else:
            print("Analysis cancelled.")
            
    finally:
        loop.close()


if __name__ == "__main__":
    main()