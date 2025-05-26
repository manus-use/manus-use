#!/usr/bin/env python3
"""Demonstrate intelligent task routing with the PlanningAgent as orchestrator."""

import asyncio
from pathlib import Path
import json

from manus_use import FlowOrchestrator, ManusAgent, BrowserAgent, DataAnalysisAgent
from manus_use.config import Config
from manus_use.multi_agents.task_planning_agent import PlanningAgent
from manus_use.tools import file_write, file_read, web_search, code_execute


def demo_intelligent_routing():
    """Demonstrate how PlanningAgent routes tasks to specialized agents."""
    print("=== Intelligent Multi-Agent Orchestration Demo ===\n")
    
    # Load configuration
    config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
    
    # Create the orchestrator
    orchestrator = FlowOrchestrator(config=config)
    
    # Replace default planner with enhanced version
    enhanced_planner = PlanningAgent(config=config)
    orchestrator.agents["planner"] = enhanced_planner
    
    # Create specialized agents with appropriate tools
    print("Setting up specialized agents...")
    
    # 1. Manus Agent - General purpose with file and code execution
    manus_agent = ManusAgent(
        tools=[file_write, file_read, code_execute],
        config=config,
        enable_sandbox=False
    )
    orchestrator.add_agent("manus", manus_agent)
    print("✓ Manus Agent: File operations, code execution, general tasks")
    
    # 2. Browser Agent - Web research specialist
    browser_agent = BrowserAgent(
        tools=[web_search],  # In real implementation would have more browser tools
        config=config
    )
    orchestrator.add_agent("browser", browser_agent)
    print("✓ Browser Agent: Web research and information retrieval")
    
    # 3. Data Analysis Agent - Statistical analysis and visualization
    data_agent = DataAnalysisAgent(
        tools=[code_execute, file_write],  # Can execute data analysis code
        config=config
    )
    orchestrator.add_agent("data_analysis", data_agent)
    print("✓ Data Analysis Agent: Statistical analysis and visualization\n")
    
    # Test Case 1: Simple query analysis
    print("=" * 60)
    print("Test 1: Query Analysis")
    print("-" * 60)
    
    query = "What are the current trends in AI and machine learning?"
    print(f"Query: {query}")
    
    analysis = enhanced_planner.analyze_query_complexity(query)
    print(f"\nAnalysis: {analysis['analysis'][:300]}...")
    
    # Test Case 2: Complex multi-agent task
    print("\n" + "=" * 60)
    print("Test 2: Complex Multi-Agent Task")
    print("-" * 60)
    
    complex_query = """
    Research the top 3 Python web frameworks (Django, Flask, FastAPI), 
    analyze their GitHub stars trend over the past year, 
    and create a comparison report with visualizations.
    """
    
    print(f"Complex Query: {complex_query.strip()}")
    print("\nGenerating execution plan...")
    
    # Get the plan from the orchestrator
    plan = enhanced_planner.create_plan(complex_query)
    
    print(f"\n✓ Generated plan with {len(plan)} tasks:\n")
    for i, task in enumerate(plan, 1):
        print(f"{i}. Task ID: {task.task_id}")
        print(f"   Agent: {task.agent_type}")
        print(f"   Description: {task.description}")
        print(f"   Dependencies: {task.dependencies}")
        print(f"   Priority: {task.priority}")
        print(f"   Complexity: {task.estimated_complexity}")
        print()
    
    # Test Case 3: Execute a simpler multi-agent workflow
    print("=" * 60)
    print("Test 3: Executing Multi-Agent Workflow")
    print("-" * 60)
    
    simple_query = "Search for Python async programming best practices and create a summary file"
    
    print(f"Query: {simple_query}")
    print("\nExecuting with orchestrator...\n")
    
    try:
        # Run the orchestrator
        result = orchestrator.run(simple_query)
        
        print("✓ Execution completed!")
        print(f"Result: {result.content if hasattr(result, 'content') else str(result)[:500]}...")
        
    except Exception as e:
        print(f"✗ Execution failed: {e}")
        import traceback
        traceback.print_exc()


def demo_parallel_execution():
    """Demonstrate parallel execution of independent tasks."""
    print("\n\n=== Parallel Task Execution Demo ===\n")
    
    config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
    orchestrator = FlowOrchestrator(config=config)
    
    # Use enhanced planner
    orchestrator.agents["planner"] = PlanningAgent(config=config)
    
    # Create a query that benefits from parallel execution
    parallel_query = """
    Perform the following independent tasks:
    1. Calculate the first 20 Fibonacci numbers
    2. Search for information about quantum computing
    3. Generate a random dataset of 100 numbers and calculate statistics
    """
    
    print(f"Query: {parallel_query.strip()}")
    print("\nThis query has independent tasks that can run in parallel.")
    print("The orchestrator should recognize this and plan accordingly.\n")
    
    # Get the plan
    planner = orchestrator.agents["planner"]
    plan = planner.create_plan(parallel_query)
    
    print(f"✓ Generated plan with {len(plan)} tasks")
    
    # Check for parallel execution opportunities
    root_tasks = [t for t in plan if not t.dependencies]
    print(f"✓ Found {len(root_tasks)} tasks that can run in parallel")
    
    # Show task dependencies
    print("\nTask Dependencies Graph:")
    for task in plan:
        if task.dependencies:
            print(f"  {task.task_id} depends on: {', '.join(task.dependencies)}")
        else:
            print(f"  {task.task_id} (no dependencies - can run immediately)")


def main():
    """Run all orchestration demos."""
    print("ManusUse Intelligent Orchestration Demo")
    print("Showcasing the PlanningAgent as an intelligent task router")
    print("=" * 70)
    
    demo_intelligent_routing()
    demo_parallel_execution()
    
    print("\n" + "=" * 70)
    print("✅ Demo completed!")
    print("\nKey Orchestration Features Demonstrated:")
    print("- Intelligent query analysis and decomposition")
    print("- Routing tasks to specialized agents based on expertise")
    print("- Managing task dependencies")
    print("- Identifying opportunities for parallel execution")
    print("- Coordinating multiple agents for complex queries")


if __name__ == "__main__":
    main()