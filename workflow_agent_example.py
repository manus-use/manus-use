#!/usr/bin/env python3
"""
Strands Agent that uses the workflow tool to handle complex tasks
with headless=False for browser operations
"""

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Import Strands SDK
from strands import Agent
from strands.tools import tool

# Import our workflow tool
from manus_use.tools.workflow import manus_workflow, WORKFLOW_DIR

# Create custom tools for the workflow agent
@tool
def create_workflow(workflow_id: str, tasks: list, description: str = ""):
    """Create a new workflow with specified tasks"""
    tool_use = {
        "toolUseId": f"create-{workflow_id}",
        "input": {
            "action": "create",
            "workflow_id": workflow_id,
            "tasks": tasks
        }
    }
    
    result = manus_workflow(
        tool=tool_use,
        system_prompt="You are a workflow creation assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    return result

@tool
def start_workflow(workflow_id: str):
    """Start execution of a workflow"""
    tool_use = {
        "toolUseId": f"start-{workflow_id}",
        "input": {
            "action": "start",
            "workflow_id": workflow_id
        }
    }
    
    result = manus_workflow(
        tool=tool_use,
        system_prompt="You are a workflow execution coordinator.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    return result

@tool
def check_workflow_status(workflow_id: str):
    """Check the status of a workflow"""
    tool_use = {
        "toolUseId": f"status-{workflow_id}",
        "input": {
            "action": "status",
            "workflow_id": workflow_id
        }
    }
    
    result = manus_workflow(
        tool=tool_use,
        system_prompt="You are a workflow monitor.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    return result

@tool
def list_workflows():
    """List all workflows"""
    tool_use = {
        "toolUseId": "list-all",
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
    
    return result

@tool
def delete_workflow(workflow_id: str):
    """Delete a workflow"""
    tool_use = {
        "toolUseId": f"delete-{workflow_id}",
        "input": {
            "action": "delete",
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
    
    return result

class WorkflowAgent:
    """Agent that manages complex workflows using multiple agent types"""
    
    def __init__(self, model_name: str = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"):
        """Initialize the workflow agent"""
        # Create system prompt
        self.system_prompt = """You are a Workflow Management Agent that coordinates complex multi-step tasks using different specialized agents:

1. **manus**: General computation, file operations, and Python code execution
2. **browser**: Web browsing and scraping (with headless=False for visibility)
3. **data_analysis**: Data processing, analysis, and visualization
4. **mcp**: Model Context Protocol tools

Your capabilities:
- Create workflows with multiple tasks and dependencies
- Assign appropriate agent types to each task
- Monitor workflow execution and status
- Handle complex real-world scenarios

When creating workflows:
- Break down complex tasks into logical steps
- Assign the most appropriate agent type to each task
- Define dependencies between tasks
- Use browser agent for any web-related tasks (it runs with headless=False)
- Use data_analysis agent for data processing and visualization
- Use manus agent for general file operations and code execution

Always ensure workflows are well-structured and tasks are properly sequenced."""
        
        # Initialize the agent with tools
        self.agent = Agent(
            model=model_name,
            system_prompt=self.system_prompt,
            tools=[create_workflow, start_workflow, check_workflow_status, 
                   list_workflows, delete_workflow]
        )
    
    async def handle_request(self, request: str) -> str:
        """Handle a user request by creating and executing appropriate workflows"""
        #response = await self.agent.run(request)

        response = await self.agent(request)
        return response
    
    def handle_request_sync(self, request: str) -> str:
        """Synchronous version of handle_request"""
        return asyncio.run(self.handle_request(request))

# Example usage
def main():
    """Example of using the WorkflowAgent"""
    print("=== Workflow Agent Example ===")
    print(f"Workflow directory: {WORKFLOW_DIR}")
    
    # Ensure workflow directory exists
    os.makedirs(WORKFLOW_DIR, exist_ok=True)
    
    # Create the agent
    agent = WorkflowAgent()
    
    # Example 1: Research and Analysis Task
    print("\n--- Example 1: Web Research and Analysis ---")
    research_request = """
    Create and execute a workflow to research the latest trends in artificial intelligence.
    The workflow should:
    1. Use the browser (with headless=False so we can see it) to visit AI news websites
    2. Extract key information about current AI trends
    3. Analyze the data and create visualizations
    4. Generate a comprehensive report
    
    Make sure to use the appropriate agent types for each task.
    """
    
    response1 = agent.handle_request_sync(research_request)
    print(f"Response: {response1}")
    
    # Example 2: Data Processing Pipeline
    print("\n--- Example 2: Data Processing Pipeline ---")
    data_request = """
    Create a workflow for processing sales data:
    1. Generate sample sales data (1000 records)
    2. Clean and preprocess the data
    3. Perform statistical analysis and create visualizations
    4. Generate insights and recommendations
    
    Use the appropriate agent types for each step.
    """
    
    response2 = agent.handle_request_sync(data_request)
    print(f"Response: {response2}")
    
    # Example 3: Web Scraping and Analysis
    print("\n--- Example 3: Web Scraping Project ---")
    scraping_request = """
    Create a workflow to scrape product information from an e-commerce site:
    1. Use browser agent (headless=False) to navigate to a shopping website
    2. Extract product names, prices, and ratings
    3. Process and analyze the scraped data
    4. Create a report with price comparisons and recommendations
    
    Make sure the browser is visible during scraping.
    """
    
    response3 = agent.handle_request_sync(scraping_request)
    print(f"Response: {response3}")
    
    # Example 4: Check workflow status
    print("\n--- Example 4: Workflow Management ---")
    management_request = """
    List all current workflows and their status.
    """
    
    response4 = agent.handle_request_sync(management_request)
    print(f"Response: {response4}")

if __name__ == "__main__":
    # Check if we're running with a configured model
    try:
        from manus_use.config import Config
        config = Config.from_file()
        if config.llm.provider == "bedrock":
            print("Using AWS Bedrock configuration")
            # For Bedrock, we need to use the appropriate model name
            agent = WorkflowAgent(model_name="us.anthropic.claude-3-7-sonnet-20250219-v1:0")
        else:
            print("Using default model configuration")
            agent = WorkflowAgent()
    except Exception as e:
        print(f"Configuration error: {e}")
        print("Using default agent configuration")
    
    main()