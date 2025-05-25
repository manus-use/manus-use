#!/usr/bin/env python3
"""Simple demo of the FlowOrchestrator."""

from pathlib import Path
import asyncio

from manus_use import ManusAgent
from manus_use.multi_agents import FlowOrchestrator, TaskPlan
from manus_use.config import Config
from manus_use.tools import file_write, file_read


def demo_simple_orchestration():
    """Demonstrate simple orchestration with manual task plan."""
    print("=== FlowOrchestrator Demo ===\n")
    
    # Load configuration
    config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
    
    # Create orchestrator
    orchestrator = FlowOrchestrator(config=config)
    print("✓ FlowOrchestrator created\n")
    
    # Create agents
    calc_agent = ManusAgent(tools=[], config=config, enable_sandbox=False)
    file_agent = ManusAgent(tools=[file_write, file_read], config=config, enable_sandbox=False)
    
    # Add agents to orchestrator
    orchestrator.add_agent("calculator", calc_agent)
    orchestrator.add_agent("file_handler", file_agent)
    print("✓ Added calculator and file_handler agents\n")
    
    # Create a simple task plan
    print("Creating task plan...")
    plan = [
        TaskPlan(
            task_id="calc_task",
            description="Calculate the sum of 15 + 27 and the product of 8 * 9",
            agent_type="calculator",
            dependencies=[],
            inputs={},
            expected_output="Calculation results"
        ),
        TaskPlan(
            task_id="save_task",
            description="Save the calculation results to /tmp/calc_results.txt",
            agent_type="file_handler",
            dependencies=["calc_task"],
            inputs={},
            expected_output="File saved confirmation"
        ),
        TaskPlan(
            task_id="verify_task",
            description="Read the file /tmp/calc_results.txt and confirm the contents",
            agent_type="file_handler",
            dependencies=["save_task"],
            inputs={},
            expected_output="File contents"
        )
    ]
    
    print("✓ Task plan created with 3 tasks\n")
    
    # Execute the plan
    print("Executing plan...")
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        results = loop.run_until_complete(orchestrator.execute_plan(plan))
        
        print("\n✓ Plan execution completed!\n")
        print("Results:")
        print("-" * 50)
        
        for task_id, result in results.items():
            print(f"\n{task_id}:")
            content = result.content if hasattr(result, 'content') else str(result)
            print(f"  {content[:200]}...")
            
    except Exception as e:
        print(f"✗ Execution failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        loop.close()


def demo_orchestrator_run():
    """Demonstrate using the orchestrator.run() method."""
    print("\n\n=== FlowOrchestrator.run() Demo ===\n")
    
    config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
    orchestrator = FlowOrchestrator(config=config)
    
    # Note: The default PlanningAgent needs to be improved to actually create plans
    # For now, it returns a simple placeholder plan
    
    try:
        print("Running orchestrator with a complex request...")
        result = orchestrator.run(
            "Calculate the fibonacci sequence up to n=10 and save it to a file"
        )
        
        print("\nResult:")
        content = result.content if hasattr(result, 'content') else str(result)
        print(content)
        
    except Exception as e:
        print(f"✗ Run failed: {e}")
        import traceback
        traceback.print_exc()


def main():
    """Run orchestrator demos."""
    print("manus-use FlowOrchestrator Demo")
    print("=" * 60)
    print("The FlowOrchestrator coordinates multiple agents to complete complex tasks.\n")
    
    demo_simple_orchestration()
    demo_orchestrator_run()
    
    print("\n" + "=" * 60)
    print("✅ Demo completed!")
    print("\nKey Features:")
    print("- Coordinate multiple specialized agents")
    print("- Handle task dependencies")
    print("- Share results between tasks")
    print("- Execute tasks in proper order")
    print("- Support both manual plans and automatic planning")


if __name__ == "__main__":
    main()