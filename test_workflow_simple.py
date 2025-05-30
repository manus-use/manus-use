#!/usr/bin/env python3
"""
Simple test of the workflow functionality without Strands Agent
"""

import os
import sys
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Import our workflow tool directly
from manus_use.tools.workflow import manus_workflow, WORKFLOW_DIR

def test_workflow_directly():
    """Test the workflow tool directly without Strands Agent"""
    print(f"=== Direct Workflow Test ===")
    print(f"Workflow directory: {WORKFLOW_DIR}")
    
    # Ensure workflow directory exists
    os.makedirs(WORKFLOW_DIR, exist_ok=True)
    
    # Test 1: Create a simple workflow
    print("\n--- Test 1: Create Workflow ---")
    create_tool_use = {
        "toolUseId": "create-test-workflow",
        "input": {
            "action": "create",
            "workflow_id": "test_workflow_001",
            "tasks": [
                {
                    "task_id": "task1",
                    "type": "computation",
                    "description": "Calculate factorial of 5",
                    "agent_type": "manus",
                    "priority": 1
                },
                {
                    "task_id": "task2",
                    "type": "file_operation",
                    "description": "Write result to file",
                    "agent_type": "manus",
                    "dependencies": ["task1"],
                    "priority": 2
                }
            ]
        }
    }
    
    try:
        result = manus_workflow(
            tool=create_tool_use,
            system_prompt="You are a workflow creation assistant.",
            inference_config={},
            messages=[],
            tool_config={}
        )
        print(f"Create result: {result}")
    except Exception as e:
        print(f"Create error: {e}")
    
    # Test 2: List workflows
    print("\n--- Test 2: List Workflows ---")
    list_tool_use = {
        "toolUseId": "list-all",
        "input": {"action": "list"}
    }
    
    try:
        result = manus_workflow(
            tool=list_tool_use,
            system_prompt="You are a workflow assistant.",
            inference_config={},
            messages=[],
            tool_config={}
        )
        print(f"List result: {result}")
    except Exception as e:
        print(f"List error: {e}")
    
    # Test 3: Check workflow status
    print("\n--- Test 3: Check Workflow Status ---")
    status_tool_use = {
        "toolUseId": "status-test",
        "input": {
            "action": "status",
            "workflow_id": "test_workflow_001"
        }
    }
    
    try:
        result = manus_workflow(
            tool=status_tool_use,
            system_prompt="You are a workflow monitor.",
            inference_config={},
            messages=[],
            tool_config={}
        )
        print(f"Status result: {result}")
    except Exception as e:
        print(f"Status error: {e}")

if __name__ == "__main__":
    test_workflow_directly()