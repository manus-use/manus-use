#!/usr/bin/env python3
"""Test script for manus_use workflow module with ManusWorkflowManager"""

import json
import os
import sys
from pathlib import Path

# Add the manus-use src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.tools.workflow import manus_workflow, ManusWorkflowManager, WORKFLOW_DIR

def test_workflow_creation():
    """Test creating a workflow with different agent types"""
    print("\n=== Testing Workflow Creation with Agent Types ===")
    
    # Ensure workflow directory exists
    os.makedirs(WORKFLOW_DIR, exist_ok=True)
    
    # Create a test workflow with different agent types
    tool_use = {
        "toolUseId": "test-tool-use-1",
        "input": {
            "action": "create",
            "workflow_id": "test-manus-workflow",
            "tasks": [
                {
                    "task_id": "manus-task",
                    "description": "List files in the current directory",
                    "agent_type": "manus",
                    "priority": 5
                },
                {
                    "task_id": "browser-task", 
                    "description": "Search for Python workflow examples",
                    "agent_type": "browser",
                    "priority": 3
                },
                {
                    "task_id": "data-task",
                    "description": "Analyze the results from previous tasks",
                    "agent_type": "data_analysis",
                    "dependencies": ["manus-task", "browser-task"],
                    "priority": 1
                }
            ]
        }
    }
    
    # Create the workflow
    result = manus_workflow(
        tool=tool_use,
        system_prompt="You are a helpful assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"Create result: {result}")
    return result["status"] == "success"

def test_workflow_list():
    """Test listing workflows"""
    print("\n=== Testing Workflow List ===")
    
    tool_use = {
        "toolUseId": "test-tool-use-2",
        "input": {
            "action": "list"
        }
    }
    
    result = manus_workflow(
        tool=tool_use,
        system_prompt="You are a helpful assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"List result: {result}")
    return result["status"] == "success"

def test_workflow_status():
    """Test getting workflow status"""
    print("\n=== Testing Workflow Status ===")
    
    tool_use = {
        "toolUseId": "test-tool-use-3",
        "input": {
            "action": "status",
            "workflow_id": "test-manus-workflow"
        }
    }
    
    result = manus_workflow(
        tool=tool_use,
        system_prompt="You are a helpful assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"Status result: {result}")
    return result["status"] == "success"

def test_invalid_action():
    """Test invalid action handling"""
    print("\n=== Testing Invalid Action ===")
    
    tool_use = {
        "toolUseId": "test-tool-use-4",
        "input": {
            "action": "invalid_action"
        }
    }
    
    result = manus_workflow(
        tool=tool_use,
        system_prompt="You are a helpful assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"Invalid action result: {result}")
    return result["status"] == "error" and "Unknown action" in result["content"][0]["text"]

def test_mcp_agent_workflow():
    """Test workflow with MCP agent type"""
    print("\n=== Testing MCP Agent Workflow ===")
    
    tool_use = {
        "toolUseId": "test-tool-use-5",
        "input": {
            "action": "create",
            "workflow_id": "test-mcp-workflow",
            "tasks": [
                {
                    "task_id": "mcp-task-1",
                    "description": "Use MCP tools to perform a task",
                    "agent_type": "mcp",
                    "priority": 5
                }
            ]
        }
    }
    
    result = manus_workflow(
        tool=tool_use,
        system_prompt="You are a helpful assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"MCP workflow result: {result}")
    
    # Clean up
    if result["status"] == "success":
        delete_tool_use = {
            "toolUseId": "test-tool-use-6",
            "input": {
                "action": "delete",
                "workflow_id": "test-mcp-workflow"
            }
        }
        manus_workflow(
            tool=delete_tool_use,
            system_prompt="You are a helpful assistant.",
            inference_config={},
            messages=[],
            tool_config={}
        )
    
    return result["status"] == "success"

def test_workflow_manager_directly():
    """Test ManusWorkflowManager directly"""
    print("\n=== Testing ManusWorkflowManager Directly ===")
    
    try:
        # Create a tool context
        tool_context = {
            "system_prompt": "You are a helpful assistant.",
            "inference_config": {},
            "messages": [],
            "tool_config": {}
        }
        
        # Create manager instance
        manager = ManusWorkflowManager(tool_context)
        
        # Test agent registry
        print(f"Available agent types: {list(manager.agent_registry.keys())}")
        
        # Test getting agents for different task types
        test_tasks = [
            {"task_id": "t1", "agent_type": "manus"},
            {"task_id": "t2", "agent_type": "browser"},
            {"task_id": "t3", "agent_type": "data_analysis"},
            {"task_id": "t4", "agent_type": "mcp"},
            {"task_id": "t5", "agent_type": "unknown"}  # Should fallback to manus
        ]
        
        for task in test_tasks:
            try:
                agent = manager.get_agent_for_task(task)
                print(f"✓ Got agent for {task['agent_type']}: {type(agent).__name__}")
            except Exception as e:
                print(f"✗ Failed to get agent for {task['agent_type']}: {e}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error testing ManusWorkflowManager: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_workflow_persistence():
    """Test workflow file persistence"""
    print("\n=== Testing Workflow Persistence ===")
    
    # Create a workflow
    workflow_id = "test-persistence-manus"
    tool_use = {
        "toolUseId": "test-tool-use-7",
        "input": {
            "action": "create",
            "workflow_id": workflow_id,
            "tasks": [
                {
                    "task_id": "persist-task-1",
                    "description": "Test persistence task",
                    "agent_type": "manus"
                }
            ]
        }
    }
    
    result = manus_workflow(
        tool=tool_use,
        system_prompt="You are a helpful assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    # Check if file was created
    workflow_file = WORKFLOW_DIR / f"{workflow_id}.json"
    if workflow_file.exists():
        print(f"✓ Workflow file created: {workflow_file}")
        
        # Read and verify content
        with open(workflow_file, "r") as f:
            data = json.load(f)
            print(f"✓ Workflow data contains {len(data['tasks'])} tasks")
            print(f"✓ First task agent_type: {data['tasks'][0].get('agent_type', 'default')}")
        
        # Clean up
        os.remove(workflow_file)
        print(f"✓ Cleanup: Removed {workflow_file}")
        return True
    else:
        print(f"✗ Workflow file not created")
        return False

def test_workflow_delete():
    """Test deleting a workflow"""
    print("\n=== Testing Workflow Delete ===")
    
    tool_use = {
        "toolUseId": "test-tool-use-8",
        "input": {
            "action": "delete",
            "workflow_id": "test-manus-workflow"
        }
    }
    
    result = manus_workflow(
        tool=tool_use,
        system_prompt="You are a helpful assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"Delete result: {result}")
    return result["status"] == "success" or "not found" in str(result.get("content", []))

def main():
    """Run all tests"""
    print("Testing manus_use workflow module with ManusWorkflowManager")
    print(f"Workflow directory: {WORKFLOW_DIR}")
    
    # Check if config exists
    config_path = Path(__file__).parent / "config.toml"
    if not config_path.exists():
        print(f"\n⚠️  Warning: Config file not found at {config_path}")
        print("Some tests may fail without proper configuration")
    
    tests = [
        test_workflow_creation,
        test_workflow_list,
        test_workflow_status,
        test_invalid_action,
        test_mcp_agent_workflow,
        test_workflow_manager_directly,
        test_workflow_persistence,
        test_workflow_delete
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
                print(f"✓ {test.__name__} passed")
            else:
                failed += 1
                print(f"✗ {test.__name__} failed")
        except Exception as e:
            failed += 1
            print(f"✗ {test.__name__} failed with error: {e}")
            import traceback
            traceback.print_exc()
    
    print(f"\n=== Test Summary ===")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Total: {len(tests)}")
    
    # Cleanup
    try:
        # Remove any test workflows
        for file in WORKFLOW_DIR.glob("test-*.json"):
            os.remove(file)
            print(f"Cleaned up: {file}")
    except Exception as e:
        print(f"Cleanup error: {e}")

if __name__ == "__main__":
    main()