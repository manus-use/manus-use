#!/usr/bin/env python3
"""
Enhanced Workflow Agent with better tool calling support
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, Any, List

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from strands import Agent
from strands.tools import tool
from manus_use.tools.workflow import manus_workflow, WORKFLOW_DIR

# Create wrapper functions that are easier for the agent to use
@tool
def create_workflow(workflow_id: str, tasks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Create a new workflow with the specified tasks.
    
    Args:
        workflow_id: Unique identifier for the workflow
        tasks: List of task dictionaries, each containing:
            - task_id: Unique identifier for the task
            - description: What the task should do
            - agent_type: One of "manus", "browser", "data_analysis", or "mcp"
            - dependencies: List of task_ids this task depends on (optional)
            - priority: Priority level 1-5 (optional)
    
    Returns:
        Result of workflow creation
    """
    # Create a ToolUse-like object
    tool_use = {
        "toolUseId": f"create-{workflow_id}",
        "input": {
            "action": "create",
            "workflow_id": workflow_id,
            "tasks": tasks
        }
    }
    return manus_workflow(tool_use)

@tool
def list_workflows() -> Dict[str, Any]:
    """
    List all workflows in the system.
    
    Returns:
        List of all workflows and their current status
    """
    tool_use = {
        "toolUseId": "list-workflows",
        "input": {"action": "list"}
    }
    return manus_workflow(tool_use)

@tool
def start_workflow(workflow_id: str) -> Dict[str, Any]:
    """
    Start execution of a workflow.
    
    Args:
        workflow_id: The ID of the workflow to start
        
    Returns:
        Result of starting the workflow
    """
    tool_use = {
        "toolUseId": f"start-{workflow_id}",
        "input": {
            "action": "start",
            "workflow_id": workflow_id
        }
    }
    return manus_workflow(tool_use)

@tool
def check_workflow_status(workflow_id: str) -> Dict[str, Any]:
    """
    Check the status of a workflow.
    
    Args:
        workflow_id: The ID of the workflow to check
        
    Returns:
        Current status of the workflow
    """
    tool_use = {
        "toolUseId": f"status-{workflow_id}",
        "input": {
            "action": "status",
            "workflow_id": workflow_id
        }
    }
    return manus_workflow(tool_use)

@tool
def delete_workflow(workflow_id: str) -> Dict[str, Any]:
    """
    Delete a workflow.
    
    Args:
        workflow_id: The ID of the workflow to delete
        
    Returns:
        Result of deleting the workflow
    """
    tool_use = {
        "toolUseId": f"delete-{workflow_id}",
        "input": {
            "action": "delete",
            "workflow_id": workflow_id
        }
    }
    return manus_workflow(tool_use)

class EnhancedWorkflowAgent:
    """Enhanced agent with simplified workflow tools"""
    
    def __init__(self, model_name: str = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"):
        """Initialize the enhanced workflow agent"""
        self.system_prompt = """You are a Workflow Management Agent that coordinates complex multi-step tasks.

You have access to these workflow tools:
1. create_workflow(workflow_id, tasks) - Create a new workflow
2. list_workflows() - List all workflows
3. start_workflow(workflow_id) - Start a workflow
4. check_workflow_status(workflow_id) - Check workflow status
5. delete_workflow(workflow_id) - Delete a workflow

Available agent types for tasks:
- manus: General computation, file operations, and Python code execution
- browser: Web browsing and scraping (runs with visible browser)
- data_analysis: Data processing, analysis, and visualization
- mcp: Model Context Protocol tools

When creating workflows, each task should have:
- task_id: A unique identifier
- description: What the task should do
- agent_type: The type of agent to use
- dependencies: List of task_ids this depends on (optional)
- priority: 1-5 priority level (optional)

Example task format:
{
    "task_id": "analyze_data",
    "description": "Analyze the collected data",
    "agent_type": "data_analysis",
    "dependencies": ["collect_data"],
    "priority": 2
}"""
        
        # Initialize with the wrapper tools
        self.agent = Agent(
            model=model_name,
            system_prompt=self.system_prompt,
            tools=[create_workflow, list_workflows, start_workflow, 
                   check_workflow_status, delete_workflow]
        )
    
    def handle_request(self, request: str) -> str:
        """Handle a user request"""
        response = self.agent(request)
        return response

def main():
    """Test the enhanced workflow agent"""
    print("=== Enhanced Workflow Agent ===")
    print(f"Workflow directory: {WORKFLOW_DIR}")
    
    # Ensure workflow directory exists
    os.makedirs(WORKFLOW_DIR, exist_ok=True)
    
    # Create the agent
    agent = EnhancedWorkflowAgent()
    

    # Example 1: Research and Analysis Task
    print("\n--- Example 1: Web Research and Analysis ---")
    research_request = """research the latest trends in artificial intelligence.
    """
    
    response1 = agent.handle_request(research_request)
    print(f"Response: {response1}")

    # Test 1: List workflows
    print("\n--- Test 1: List Workflows ---")
    response = agent.handle_request("List all workflows")
    print(f"Response: {response}")
    
    # Test 2: Create a simple workflow
    print("\n--- Test 2: Create Simple Workflow ---")
    response = agent.handle_request("""
    Create a workflow called 'hello-world-workflow' with two tasks:
    1. First task (id: 'write_file') using manus agent: Write 'Hello World!' to hello.txt
    2. Second task (id: 'read_file') using manus agent: Read hello.txt and display contents
    The second task depends on the first task.
    """)
    print(f"Response: {response}")
    
    # Test 3: Start the workflow
    print("\n--- Test 3: Start Workflow ---")
    response = agent.handle_request("Start the workflow 'hello-world-workflow'")
    print(f"Response: {response}")
    
    # Test 4: Check status
    print("\n--- Test 4: Check Status ---")
    response = agent.handle_request("Check the status of workflow 'hello-world-workflow'")
    print(f"Response: {response}")

if __name__ == "__main__":
    # Check configuration
    try:
        from manus_use.config import Config
        config = Config.from_file()
        if config.llm.provider == "bedrock":
            print("Using AWS Bedrock configuration")
    except Exception as e:
        print(f"Configuration note: {e}")
    
    main()