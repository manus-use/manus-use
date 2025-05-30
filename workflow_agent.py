#!/usr/bin/env python3
"""
Strands Agent that uses the workflow tool to handle complex tasks
with headless=False for browser operations
"""

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
- Call manus_workflow to manage workflows with multiple tasks and dependencies
- Assign appropriate agent types to each task
- Monitor workflow execution and status
- Handle complex real-world scenarios

CRITICAL: When calling the manus_workflow tool, you need to understand its calling convention:
- The tool expects parameters to be passed as a JSON object
- The JSON object should contain an "action" field and other fields based on the action

TOOL CALLING EXAMPLES:

1. To list all workflows:
   Use manus_workflow with parameters: {"action": "list"}

2. To create a workflow:
   Use manus_workflow with parameters: {
       "action": "create",
       "workflow_id": "my-workflow",
       "tasks": [
           {
               "task_id": "task1",
               "description": "First task description",
               "agent_type": "manus",
               "priority": 1,
               "dependencies": []
           },
           {
               "task_id": "task2",
               "description": "Second task description",
               "agent_type": "browser",
               "priority": 1,
               "dependencies": ["task1"]
           }
       ]
   }

3. To start a workflow:
   Use manus_workflow with parameters: {"action": "start", "workflow_id": "my-workflow"}

4. To check workflow status:
   Use manus_workflow with parameters: {"action": "status", "workflow_id": "my-workflow"}

5. To delete a workflow:
   Use manus_workflow with parameters: {"action": "delete", "workflow_id": "my-workflow"}

REMEMBER:
- Always use proper JSON syntax (double quotes for strings, proper nesting)
- The entire parameter must be a single JSON object
- agent_type must be one of: "manus", "browser", "data_analysis", or "mcp"
- task_id values must be unique within a workflow
- dependencies is an array of task_id strings that must exist in the workflow

When creating workflows:
- Break down complex tasks into logical steps
- Assign the most appropriate agent type to each task
- Define dependencies between tasks
- Use browser agent for any web-related tasks (it runs with headless=False)
- Use data_analysis agent for data processing and visualization
- Use manus agent for general file operations and code execution

Always ensure workflows are well-structured and tasks are properly sequenced.
"""
        
        # Initialize the agent with tools
        self.agent = Agent(
            model=model_name,
            system_prompt=self.system_prompt,
            tools=[manus_workflow]
        )
    
    def handle_request(self, request: str) -> str:
        """Handle a user request by creating and executing appropriate workflows"""
        response = self.agent(request)
        return response
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
    Assesss the 2 most recent vulnerabilities
    Make sure to use the appropriate agent types for each task as specified.
    """
    response1 = agent.handle_request(research_request)
    print(f"Response: {response1}")
    

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