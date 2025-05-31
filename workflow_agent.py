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

# Import our workflow tool
import manus_use.tools.workflow_tool as workflow_tool

# Create custom tools for the workflow agent

class WorkflowAgent:
    """Agent that manages complex workflows using multiple agent types"""
    
    def __init__(self, model_name: str = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"):
        """Initialize the workflow agent"""
        # Create system prompt
        self.system_prompt = """You are a Workflow Management Agent that coordinates complex multi-step tasks using different specialized agents:

Available agent types for tasks:
- manus: General computation, http request for web_search, file operations, and Python code execution
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
}

Always ensure workflows are well-structured and tasks are properly sequenced.
"""
        
        # Initialize the agent with tools
        self.agent = Agent(
            model=model_name,
            system_prompt=self.system_prompt,
            tools=[workflow_tool]
        )
    
    def handle_request(self, request: str) -> str:
        """Handle a user request by creating and executing appropriate workflows"""
        response = self.agent(request)
        return response
    
# Example usage
def main():
    """Example of using the WorkflowAgent"""
    print("=== Workflow Agent Example ===")
    #print(f"Workflow directory: {WORKFLOW_DIR}")
    
    # Ensure workflow directory exists
    #os.makedirs(WORKFLOW_DIR, exist_ok=True)
    
    # Create the agent
    agent = WorkflowAgent()
    # Example 1: Research and Analysis Task
    print("\n--- Example 1: Web Research and Analysis ---")
    research_request = """
    Assesss the 2 most recent vulnerabilities, and find the valid poc links and save them into marddown file.
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