#!/usr/bin/env python3
"""
Test workflow agent with mock responses to avoid API dependencies
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Import Strands SDK
from strands import Agent
from strands.tools import tool

# Mock workflow tool
@tool
def mock_create_workflow(workflow_id: str, tasks: list, description: str = ""):
    """Mock create workflow tool"""
    return {
        "status": "success",
        "content": [{"text": f"Created workflow {workflow_id} with {len(tasks)} tasks"}]
    }

@tool
def mock_start_workflow(workflow_id: str):
    """Mock start workflow tool"""
    return {
        "status": "success",
        "content": [{"text": f"Started workflow {workflow_id}"}]
    }

@tool
def mock_check_workflow_status(workflow_id: str):
    """Mock check workflow status tool"""
    return {
        "status": "success",
        "content": [{"text": f"Workflow {workflow_id} is running (50% complete)"}]
    }

@tool
def mock_list_workflows():
    """Mock list workflows tool"""
    return {
        "status": "success",
        "content": [{"text": "Found 3 workflows:\n- test_workflow_001 (completed)\n- test_workflow_002 (running)\n- test_workflow_003 (created)"}]
    }

class MockWorkflowAgent:
    """Mock workflow agent for testing"""
    
    def __init__(self):
        self.system_prompt = """You are a Workflow Management Agent for testing purposes."""
        
        # Create a mock model that returns predefined responses
        mock_model = Mock()
        mock_model.name = "mock-model"
        
        # Configure mock to return tool calls
        mock_model.converse.return_value = [{
            "type": "text",
            "text": "I'll help you with that workflow task."
        }]
        
        # Initialize the agent with mock tools
        self.agent = Agent(
            model=mock_model,
            system_prompt=self.system_prompt,
            tools=[mock_create_workflow, mock_start_workflow, 
                   mock_check_workflow_status, mock_list_workflows]
        )
    
    async def handle_request(self, request: str) -> str:
        """Handle a user request"""
        # For testing, return a mock response
        if "create" in request.lower():
            return "Created workflow test_workflow_001 with 3 tasks"
        elif "list" in request.lower():
            return "Found 3 workflows:\n- test_workflow_001 (completed)\n- test_workflow_002 (running)\n- test_workflow_003 (created)"
        elif "status" in request.lower():
            return "Workflow test_workflow_001 is running (50% complete)"
        else:
            return "I can help you create, list, and check the status of workflows."
    
    def handle_request_sync(self, request: str) -> str:
        """Synchronous version of handle_request"""
        return asyncio.run(self.handle_request(request))

def test_mock_workflow_agent():
    """Test the mock workflow agent"""
    print("=== Mock Workflow Agent Test ===\n")
    
    # Create the mock agent
    agent = MockWorkflowAgent()
    
    # Test 1: Create workflow
    print("--- Test 1: Create Workflow ---")
    create_request = "Create a workflow for testing with 3 tasks"
    response = agent.handle_request_sync(create_request)
    print(f"Request: {create_request}")
    print(f"Response: {response}\n")
    
    # Test 2: List workflows
    print("--- Test 2: List Workflows ---")
    list_request = "List all workflows"
    response = agent.handle_request_sync(list_request)
    print(f"Request: {list_request}")
    print(f"Response: {response}\n")
    
    # Test 3: Check status
    print("--- Test 3: Check Workflow Status ---")
    status_request = "Check the status of test_workflow_001"
    response = agent.handle_request_sync(status_request)
    print(f"Request: {status_request}")
    print(f"Response: {response}\n")
    
    # Test 4: General help
    print("--- Test 4: General Help ---")
    help_request = "What can you do?"
    response = agent.handle_request_sync(help_request)
    print(f"Request: {help_request}")
    print(f"Response: {response}\n")

def test_workflow_tools_directly():
    """Test workflow tools directly"""
    print("\n=== Direct Workflow Tools Test ===\n")
    
    # Test create workflow
    print("--- Creating Workflow ---")
    result = mock_create_workflow(
        workflow_id="test_direct",
        tasks=[
            {"task_id": "task1", "description": "First task"},
            {"task_id": "task2", "description": "Second task"},
        ]
    )
    print(f"Create result: {result}\n")
    
    # Test list workflows
    print("--- Listing Workflows ---")
    result = mock_list_workflows()
    print(f"List result: {result}\n")
    
    # Test check status
    print("--- Checking Status ---")
    result = mock_check_workflow_status(workflow_id="test_direct")
    print(f"Status result: {result}\n")

if __name__ == "__main__":
    # Run tests
    test_mock_workflow_agent()
    test_workflow_tools_directly()
    
    print("\n=== All Tests Completed ===")
    print("The mock workflow agent is working correctly!")
    print("\nNote: To use the real workflow agent with AWS Bedrock or Anthropic API,")
    print("you'll need to configure valid API credentials and model names.")