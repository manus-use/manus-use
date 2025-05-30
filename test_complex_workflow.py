#!/usr/bin/env python3
"""
Complex workflow example using manus_workflow with different agent types
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.tools.workflow import manus_workflow, WORKFLOW_DIR

def create_complex_analysis_workflow():
    """
    Create a complex workflow that:
    1. Uses browser agent to research a topic
    2. Uses manus agent to process and save the research
    3. Uses data_analysis agent to analyze the data
    4. Uses mcp agent for additional processing
    """
    print("\n=== Creating Complex Multi-Agent Workflow ===")
    
    # Ensure workflow directory exists
    os.makedirs(WORKFLOW_DIR, exist_ok=True)
    
    # Define a complex workflow with multiple agent types
    tool_use = {
        "toolUseId": "complex-analysis-workflow",
        "input": {
            "action": "create",
            "workflow_id": "market-research-analysis",
            "tasks": [
                {
                    "task_id": "research-market-trends",
                    "description": "Research current AI and machine learning market trends. Visit websites like TechCrunch, Gartner, or similar tech news sites to gather information about the latest AI developments, market size, and key players.",
                    "agent_type": "browser",
                    "priority": 5,
                    "timeout": 300
                },
                {
                    "task_id": "extract-key-data",
                    "description": """Extract and structure the key information from the research:
                    1. Create a structured summary of the findings
                    2. Identify top 5 AI trends
                    3. List major companies mentioned
                    4. Note any statistics or market data
                    5. Save the structured data to a file called 'ai_market_research.json'
                    """,
                    "agent_type": "manus",
                    "dependencies": ["research-market-trends"],
                    "priority": 4
                },
                {
                    "task_id": "analyze-trends",
                    "description": """Analyze the extracted data:
                    1. Load the data from 'ai_market_research.json'
                    2. Create visualizations showing:
                       - Trend popularity (bar chart)
                       - Company mentions frequency
                       - Market growth projections if available
                    3. Generate statistical summary
                    4. Create a data analysis report
                    """,
                    "agent_type": "data_analysis",
                    "dependencies": ["extract-key-data"],
                    "priority": 3
                },
                {
                    "task_id": "generate-insights",
                    "description": """Generate business insights from the analysis:
                    1. Identify top 3 opportunities in the AI market
                    2. Recommend strategic focus areas
                    3. Highlight potential risks or challenges
                    4. Create an executive summary
                    """,
                    "agent_type": "manus",
                    "dependencies": ["analyze-trends"],
                    "priority": 2
                },
                {
                    "task_id": "create-final-report",
                    "description": """Create a comprehensive final report:
                    1. Combine all previous findings
                    2. Structure the report with:
                       - Executive Summary
                       - Market Overview
                       - Key Trends Analysis
                       - Opportunities and Recommendations
                       - Visualizations and Data
                    3. Save as 'AI_Market_Research_Report.md'
                    """,
                    "agent_type": "manus",
                    "dependencies": ["generate-insights"],
                    "priority": 1
                }
            ]
        }
    }
    
    # Create the workflow
    result = manus_workflow(
        tool=tool_use,
        system_prompt="You are a comprehensive research and analysis assistant capable of web browsing, data analysis, and report generation.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"\nWorkflow creation result: {result}")
    return result

def create_development_workflow():
    """
    Create a software development workflow
    """
    print("\n=== Creating Software Development Workflow ===")
    
    tool_use = {
        "toolUseId": "dev-workflow",
        "input": {
            "action": "create",
            "workflow_id": "python-app-development",
            "tasks": [
                {
                    "task_id": "design-architecture",
                    "description": """Design a Python web scraping application:
                    1. Create application architecture diagram
                    2. Define main components:
                       - Web scraper module
                       - Data processor module
                       - Storage module
                       - API module
                    3. List required libraries (BeautifulSoup, requests, etc)
                    4. Save design to 'app_architecture.md'
                    """,
                    "agent_type": "manus",
                    "priority": 5
                },
                {
                    "task_id": "implement-scraper",
                    "description": """Implement the web scraper module:
                    1. Create scraper.py with:
                       - Base scraper class
                       - Methods for different websites
                       - Error handling
                       - Rate limiting
                    2. Add unit tests in test_scraper.py
                    3. Create requirements.txt
                    """,
                    "agent_type": "manus",
                    "dependencies": ["design-architecture"],
                    "priority": 4
                },
                {
                    "task_id": "test-scraper",
                    "description": """Test the scraper implementation:
                    1. Run the scraper on a test website
                    2. Verify data extraction works correctly
                    3. Check error handling
                    4. Document any issues found
                    """,
                    "agent_type": "browser",
                    "dependencies": ["implement-scraper"],
                    "priority": 3
                },
                {
                    "task_id": "analyze-performance",
                    "description": """Analyze scraper performance:
                    1. Measure scraping speed
                    2. Check memory usage
                    3. Create performance metrics visualization
                    4. Identify optimization opportunities
                    """,
                    "agent_type": "data_analysis",
                    "dependencies": ["test-scraper"],
                    "priority": 2
                },
                {
                    "task_id": "create-documentation",
                    "description": """Create comprehensive documentation:
                    1. API documentation
                    2. User guide
                    3. Installation instructions
                    4. Example usage
                    5. Save as README.md
                    """,
                    "agent_type": "manus",
                    "dependencies": ["analyze-performance"],
                    "priority": 1
                }
            ]
        }
    }
    
    result = manus_workflow(
        tool=tool_use,
        system_prompt="You are a software development assistant skilled in Python programming, testing, and documentation.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"\nDevelopment workflow result: {result}")
    return result

def create_data_pipeline_workflow():
    """
    Create a data processing pipeline workflow
    """
    print("\n=== Creating Data Pipeline Workflow ===")
    
    tool_use = {
        "toolUseId": "data-pipeline",
        "input": {
            "action": "create",
            "workflow_id": "sales-data-pipeline",
            "tasks": [
                {
                    "task_id": "generate-sample-data",
                    "description": """Generate sample sales data:
                    1. Create 1000 sales records with:
                       - Product names
                       - Quantities
                       - Prices
                       - Dates
                       - Regions
                    2. Add some data quality issues (missing values, outliers)
                    3. Save as 'raw_sales_data.csv'
                    """,
                    "agent_type": "manus",
                    "priority": 5
                },
                {
                    "task_id": "clean-data",
                    "description": """Clean and preprocess the data:
                    1. Load raw_sales_data.csv
                    2. Handle missing values
                    3. Remove outliers
                    4. Standardize formats
                    5. Create data quality report
                    6. Save cleaned data as 'cleaned_sales_data.csv'
                    """,
                    "agent_type": "data_analysis",
                    "dependencies": ["generate-sample-data"],
                    "priority": 4
                },
                {
                    "task_id": "analyze-sales",
                    "description": """Perform sales analysis:
                    1. Calculate total sales by region
                    2. Identify top selling products
                    3. Analyze seasonal trends
                    4. Create visualizations:
                       - Sales by region (bar chart)
                       - Product performance (pie chart)
                       - Time series analysis
                    5. Generate insights report
                    """,
                    "agent_type": "data_analysis",
                    "dependencies": ["clean-data"],
                    "priority": 3
                },
                {
                    "task_id": "create-dashboard",
                    "description": """Create an executive dashboard:
                    1. Design dashboard layout
                    2. Include key metrics:
                       - Total revenue
                       - Growth rate
                       - Top products
                       - Regional performance
                    3. Add visualizations from analysis
                    4. Create HTML dashboard file
                    """,
                    "agent_type": "manus",
                    "dependencies": ["analyze-sales"],
                    "priority": 2
                },
                {
                    "task_id": "generate-recommendations",
                    "description": """Generate business recommendations:
                    1. Based on the analysis, recommend:
                       - Inventory optimization strategies
                       - Regional focus areas
                       - Product line adjustments
                    2. Create action plan
                    3. Estimate potential impact
                    4. Save as 'business_recommendations.md'
                    """,
                    "agent_type": "manus",
                    "dependencies": ["analyze-sales"],
                    "priority": 1
                }
            ]
        }
    }
    
    result = manus_workflow(
        tool=tool_use,
        system_prompt="You are a data analysis expert skilled in data processing, visualization, and business intelligence.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"\nData pipeline workflow result: {result}")
    return result

def start_workflow(workflow_id):
    """Start a workflow execution"""
    print(f"\n=== Starting Workflow: {workflow_id} ===")
    
    tool_use = {
        "toolUseId": f"start-{workflow_id}",
        "input": {
            "action": "start",
            "workflow_id": workflow_id
        }
    }
    
    try:
        result = manus_workflow(
            tool=tool_use,
            system_prompt="You are a workflow execution coordinator.",
            inference_config={},
            messages=[],
            tool_config={}
        )
        print(f"Start result: {result}")
        return result
    except Exception as e:
        print(f"Error starting workflow: {e}")
        return None

def check_workflow_status(workflow_id):
    """Check workflow status"""
    print(f"\n=== Checking Status: {workflow_id} ===")
    
    tool_use = {
        "toolUseId": f"status-{workflow_id}",
        "input": {
            "action": "status",
            "workflow_id": workflow_id
        }
    }
    
    result = manus_workflow(
        tool=tool_use,
        system_prompt="You are a workflow assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"Status result: {result}")
    return result

def list_all_workflows():
    """List all workflows"""
    print("\n=== Listing All Workflows ===")
    
    tool_use = {
        "toolUseId": "list-workflows",
        "input": {
            "action": "list"
        }
    }
    
    result = manus_workflow(
        tool=tool_use,
        system_prompt="You are a workflow assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"List result: {result}")
    return result

def main():
    """Run complex workflow examples"""
    print("=== Complex Multi-Agent Workflow Examples ===")
    print(f"Workflow directory: {WORKFLOW_DIR}")
    
    # Check if config exists
    config_path = Path(__file__).parent / "config.toml"
    if not config_path.exists():
        print(f"\n⚠️  Warning: Config file not found at {config_path}")
        print("Please ensure config.toml is properly configured")
        return
    
    # Create workflows
    workflows = []
    
    # 1. Market Research Workflow
    result1 = create_complex_analysis_workflow()
    if result1["status"] == "success":
        workflows.append("market-research-analysis")
    
    # 2. Development Workflow
    result2 = create_development_workflow()
    if result2["status"] == "success":
        workflows.append("python-app-development")
    
    # 3. Data Pipeline Workflow
    result3 = create_data_pipeline_workflow()
    if result3["status"] == "success":
        workflows.append("sales-data-pipeline")
    
    # List all workflows
    list_all_workflows()
    
    # Check status of each workflow
    for workflow_id in workflows:
        check_workflow_status(workflow_id)
    
    # Option to start workflows (uncomment to execute)
    print("\n=== Ready to Execute Workflows ===")
    print("To execute workflows, uncomment the following lines:")
    print("# for workflow_id in workflows:")
    print("#     start_workflow(workflow_id)")
    
    # Uncomment these lines to actually start the workflows
    # for workflow_id in workflows:
    #     start_workflow(workflow_id)
    #     time.sleep(2)  # Brief pause between starts
    
    print("\n=== Summary ===")
    print(f"Created {len(workflows)} complex workflows:")
    for i, wf in enumerate(workflows, 1):
        print(f"{i}. {wf}")
    print("\nThese workflows demonstrate:")
    print("- Multi-agent coordination (browser, manus, data_analysis, mcp)")
    print("- Complex task dependencies")
    print("- Real-world use cases")
    print("- Data processing pipelines")
    print("- Web research and analysis")

if __name__ == "__main__":
    main()