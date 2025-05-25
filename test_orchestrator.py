#!/usr/bin/env python3
"""Test the FlowOrchestrator multi-agent system."""

from pathlib import Path
import tempfile

from manus_use import ManusAgent, BrowserAgent, DataAnalysisAgent
from manus_use.config import Config
from manus_use.multi_agents import FlowOrchestrator, TaskPlan


def test_simple_orchestrator():
    """Test basic orchestrator functionality."""
    print("=== Testing FlowOrchestrator ===\n")
    
    # Load configuration
    config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
    
    # Create orchestrator
    print("1. Creating FlowOrchestrator...")
    orchestrator = FlowOrchestrator(config=config)
    print("✓ Orchestrator created with default planning agent\n")
    
    # Add specialized agents
    print("2. Adding specialized agents...")
    orchestrator.add_agent("researcher", BrowserAgent(config=config))
    orchestrator.add_agent("analyst", DataAnalysisAgent(config=config))
    orchestrator.add_agent("writer", ManusAgent(config=config))
    print("✓ Added researcher, analyst, and writer agents\n")
    
    # Test 1: Simple orchestrated task
    print("3. Testing simple orchestrated task...")
    try:
        result = orchestrator.run(
            "Research Python web frameworks and create a brief summary"
        )
        print(f"✓ Result: {result.content if hasattr(result, 'content') else str(result)[:200]}...\n")
    except Exception as e:
        print(f"✗ Simple task failed: {e}\n")
    
    # Test 2: Manual task plan
    print("4. Testing manual task plan...")
    try:
        # Create a manual plan
        plan = [
            TaskPlan(
                task_id="task1",
                description="Generate a list of 5 random numbers between 1 and 100",
                agent_type="manus",
                dependencies=[],
                inputs={},
                expected_output="List of 5 random numbers"
            ),
            TaskPlan(
                task_id="task2",
                description="Calculate the mean and standard deviation of these numbers",
                agent_type="data_analysis",
                dependencies=["task1"],
                inputs={},
                expected_output="Statistical analysis"
            ),
            TaskPlan(
                task_id="task3",
                description="Write a brief report about the analysis",
                agent_type="writer",
                dependencies=["task1", "task2"],
                inputs={},
                expected_output="Analysis report"
            )
        ]
        
        # Execute the plan
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            results = loop.run_until_complete(orchestrator.execute_plan(plan))
            
            print("✓ Manual plan executed successfully")
            print(f"  Task 1 result: {str(results.get('task1', 'No result'))[:100]}...")
            print(f"  Task 2 result: {str(results.get('task2', 'No result'))[:100]}...")
            print(f"  Task 3 result: {str(results.get('task3', 'No result'))[:100]}...\n")
        finally:
            loop.close()
            
    except Exception as e:
        print(f"✗ Manual plan failed: {e}\n")
        import traceback
        traceback.print_exc()


def test_complex_orchestration():
    """Test complex multi-agent orchestration."""
    print("\n=== Testing Complex Orchestration ===\n")
    
    config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
    orchestrator = FlowOrchestrator(config=config)
    
    # Add agents with specific tools
    from manus_use.tools import web_search, file_write, file_read, code_execute
    
    # Research agent with web search
    research_agent = ManusAgent(
        tools=[web_search],
        config=config,
        enable_sandbox=False
    )
    orchestrator.add_agent("researcher", research_agent)
    
    # Writer agent with file operations
    writer_agent = ManusAgent(
        tools=[file_write, file_read],
        config=config,
        enable_sandbox=False
    )
    orchestrator.add_agent("writer", writer_agent)
    
    # Complex task
    print("Testing complex multi-agent task...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a complex plan
        plan = [
            TaskPlan(
                task_id="research",
                description="Search for information about 'Python async programming best practices'",
                agent_type="researcher",
                dependencies=[],
                inputs={},
                expected_output="Search results about Python async programming"
            ),
            TaskPlan(
                task_id="write_report",
                description=f"Based on the research results, create a markdown report at {tmpdir}/async_guide.md",
                agent_type="writer",
                dependencies=["research"],
                inputs={},
                expected_output="Markdown report file"
            ),
            TaskPlan(
                task_id="read_report",
                description=f"Read the report from {tmpdir}/async_guide.md and provide a summary",
                agent_type="writer",
                dependencies=["write_report"],
                inputs={},
                expected_output="Summary of the report"
            )
        ]
        
        try:
            import asyncio
            loop = asyncio.new_event_loop()
            try:
                results = loop.run_until_complete(orchestrator.execute_plan(plan))
                
                print("✓ Complex orchestration completed")
                
                # Check if file was created
                report_path = Path(tmpdir) / "async_guide.md"
                if report_path.exists():
                    print(f"✓ Report file created: {report_path}")
                    print(f"✓ File size: {len(report_path.read_text())} characters")
                else:
                    print("✗ Report file was not created")
                    
                # Show final summary
                final_result = results.get("read_report", "No summary")
                print(f"\nFinal Summary:\n{final_result.content if hasattr(final_result, 'content') else str(final_result)[:300]}...")
                
            finally:
                loop.close()
                
        except Exception as e:
            print(f"✗ Complex orchestration failed: {e}")
            import traceback
            traceback.print_exc()


def main():
    """Run all orchestrator tests."""
    print("manus-use FlowOrchestrator Test Suite")
    print("=" * 50)
    
    test_simple_orchestrator()
    test_complex_orchestration()
    
    print("\n" + "=" * 50)
    print("✅ Orchestrator tests completed!")
    print("\nThe FlowOrchestrator enables:")
    print("- Multi-agent coordination")
    print("- Task dependencies and sequencing")
    print("- Parallel execution when possible")
    print("- Result sharing between agents")
    print("- Complex workflow automation")


if __name__ == "__main__":
    main()