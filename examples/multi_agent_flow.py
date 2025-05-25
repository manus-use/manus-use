"""Multi-agent flow example."""

from manus_use import ManusAgent, BrowserAgent, DataAnalysisAgent
from manus_use.multi_agents import FlowOrchestrator


def example_multi_agent_flow():
    """Example of multi-agent workflow."""
    print("=== Multi-Agent Flow Example ===")
    
    # Create flow orchestrator
    flow = FlowOrchestrator()
    
    # Add specialized agents
    flow.add_agent("researcher", BrowserAgent())
    flow.add_agent("analyst", DataAnalysisAgent())
    flow.add_agent("writer", ManusAgent())
    
    # Execute complex task
    result = flow.run(
        "Research the top 5 programming languages in 2024, "
        "analyze their popularity trends, and create a comprehensive "
        "report with visualizations"
    )
    
    print(result)


def example_custom_flow():
    """Example of custom flow with dependencies."""
    print("\n=== Custom Flow Example ===")
    
    from manus_use.multi_agents import TaskPlan
    
    # Create orchestrator
    flow = FlowOrchestrator()
    
    # Define custom task plan
    plan = [
        TaskPlan(
            task_id="gather_data",
            description="Search for AI market size data for the last 5 years",
            agent_type="browser",
            dependencies=[],
            inputs={},
            expected_output="Market size data in structured format"
        ),
        TaskPlan(
            task_id="analyze_trends",
            description="Analyze the market growth trends and create projections",
            agent_type="data_analysis",
            dependencies=["gather_data"],
            inputs={},
            expected_output="Trend analysis with growth projections"
        ),
        TaskPlan(
            task_id="create_report",
            description="Create a comprehensive market analysis report",
            agent_type="manus",
            dependencies=["gather_data", "analyze_trends"],
            inputs={},
            expected_output="Complete market analysis report"
        )
    ]
    
    # Execute the custom plan
    import asyncio
    loop = asyncio.new_event_loop()
    try:
        results = loop.run_until_complete(flow.execute_plan(plan))
        print("Final report:", results.get("create_report", "No report generated"))
    finally:
        loop.close()


if __name__ == "__main__":
    try:
        example_multi_agent_flow()
    except Exception as e:
        print(f"Multi-agent flow example failed: {e}")
        
    try:
        example_custom_flow()
    except Exception as e:
        print(f"Custom flow example failed: {e}")