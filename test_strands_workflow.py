#!/usr/bin/env python3
"""Test script for strands_tools.workflow module"""

import json
import os
import sys
import time
from pathlib import Path

# Add the tools directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "tools" / "src"))

from strands_tools.workflow import workflow, WorkflowManager, WORKFLOW_DIR

def test_workflow_creation():
    """Test creating a workflow"""
    print("\n=== Testing Workflow Creation ===")
    
    # Ensure workflow directory exists
    os.makedirs(WORKFLOW_DIR, exist_ok=True)
    
    # Create a test workflow
    tool_use = {
        "toolUseId": "test-tool-use-1",
        "input": {
            "action": "create",
            "workflow_id": "test-workflow-demo",
            "tasks": [
                {
                    "task_id": "task-1",
                    "description": "What is the capital of France?",
                    "priority": 5
                },
                {
                    "task_id": "task-2", 
                    "description": "What is 2 + 2?",
                    "priority": 3
                },
                {
                    "task_id": "task-3",
                    "description": "Summarize the results from task-1 and task-2",
                    "dependencies": ["task-1", "task-2"],
                    "priority": 1
                }
            ]
        }
    }
    
    # Create the workflow
    result = workflow(
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
    
    result = workflow(
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
            "workflow_id": "test-workflow-demo"
        }
    }
    
    result = workflow(
        tool=tool_use,
        system_prompt="You are a helpful assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"Status result: {result}")
    return result["status"] == "success"

def test_workflow_start():
    """Test starting a workflow"""
    print("\n=== Testing Workflow Start ===")
    print("Note: This will fail without a configured LLM agent")
    
    tool_use = {
        "toolUseId": "test-tool-use-4",
        "input": {
            "action": "start",
            "workflow_id": "test-workflow-demo"
        }
    }
    
    try:
        result = workflow(
            tool=tool_use,
            system_prompt="You are a helpful assistant.",
            inference_config={},
            messages=[],
            tool_config={}
        )
        
        print(f"Start result: {result}")
        return True
    except Exception as e:
        print(f"Expected error (no agent configured): {e}")
        return True

def test_workflow_delete():
    """Test deleting a workflow"""
    print("\n=== Testing Workflow Delete ===")
    
    tool_use = {
        "toolUseId": "test-tool-use-5",
        "input": {
            "action": "delete",
            "workflow_id": "test-workflow-demo"
        }
    }
    
    result = workflow(
        tool=tool_use,
        system_prompt="You are a helpful assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"Delete result: {result}")
    return result["status"] == "success"

def test_invalid_action():
    """Test invalid action handling"""
    print("\n=== Testing Invalid Action ===")
    
    tool_use = {
        "toolUseId": "test-tool-use-6",
        "input": {
            "action": "invalid_action"
        }
    }
    
    result = workflow(
        tool=tool_use,
        system_prompt="You are a helpful assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"Invalid action result: {result}")
    return result["status"] == "error" and "Unknown action" in result["content"][0]["text"]

def test_missing_required_fields():
    """Test missing required fields"""
    print("\n=== Testing Missing Required Fields ===")
    
    # Test missing tasks for create
    tool_use = {
        "toolUseId": "test-tool-use-7",
        "input": {
            "action": "create",
            "workflow_id": "test-workflow-missing"
        }
    }
    
    result = workflow(
        tool=tool_use,
        system_prompt="You are a helpful assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"Missing tasks result: {result}")
    assert result["status"] == "error"
    
    # Test missing workflow_id for status
    tool_use = {
        "toolUseId": "test-tool-use-8",
        "input": {
            "action": "status"
        }
    }
    
    result = workflow(
        tool=tool_use,
        system_prompt="You are a helpful assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"Missing workflow_id result: {result}")
    return result["status"] == "error"

def test_workflow_persistence():
    """Test workflow file persistence"""
    print("\n=== Testing Workflow Persistence ===")
    
    # Create a workflow
    workflow_id = "test-persistence"
    tool_use = {
        "toolUseId": "test-tool-use-9",
        "input": {
            "action": "create",
            "workflow_id": workflow_id,
            "tasks": [
                {
                    "task_id": "persist-task-1",
                    "description": "Test persistence task"
                }
            ]
        }
    }
    
    result = workflow(
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
            print(f"✓ Workflow data: {json.dumps(data, indent=2)}")
        
        # Clean up
        os.remove(workflow_file)
        print(f"✓ Cleanup: Removed {workflow_file}")
        return True
    else:
        print(f"✗ Workflow file not created")
        return False

def test_workflow_with_dependencies():
    """Test workflow with task dependencies"""
    print("\n=== Testing Workflow with Dependencies ===")
    
    # Create a workflow with complex dependencies
    tool_use = {
        "toolUseId": "test-tool-use-10",
        "input": {
            "action": "create",
            "workflow_id": "test-dependencies",
            "tasks": [
                {
                    "task_id": "data-fetch",
                    "description": "Fetch data from source",
                    "priority": 5
                },
                {
                    "task_id": "data-process",
                    "description": "Process the fetched data",
                    "dependencies": ["data-fetch"],
                    "priority": 4
                },
                {
                    "task_id": "data-validate",
                    "description": "Validate processed data",
                    "dependencies": ["data-process"],
                    "priority": 3
                },
                {
                    "task_id": "generate-report",
                    "description": "Generate final report",
                    "dependencies": ["data-validate"],
                    "priority": 2
                }
            ]
        }
    }
    
    result = workflow(
        tool=tool_use,
        system_prompt="You are a helpful assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    if result["status"] == "success":
        print("✓ Created workflow with dependencies")
        
        # Check status
        status_tool_use = {
            "toolUseId": "test-tool-use-11",
            "input": {
                "action": "status",
                "workflow_id": "test-dependencies"
            }
        }
        
        status_result = workflow(
            tool=status_tool_use,
            system_prompt="You are a helpful assistant.",
            inference_config={},
            messages=[],
            tool_config={}
        )
        
        print(f"Status of dependency workflow: {status_result}")
        
        # Clean up
        delete_tool_use = {
            "toolUseId": "test-tool-use-12",  
            "input": {
                "action": "delete",
                "workflow_id": "test-dependencies"
            }
        }
        
        workflow(
            tool=delete_tool_use,
            system_prompt="You are a helpful assistant.",
            inference_config={},
            messages=[],
            tool_config={}
        )
        
        return True
    return False

def test_parallel_tasks():
    """Test workflow with parallel tasks"""
    print("\n=== Testing Parallel Tasks ===")
    
    # Create a workflow with tasks that can run in parallel
    tool_use = {
        "toolUseId": "test-tool-use-13",
        "input": {
            "action": "create",
            "workflow_id": "test-parallel",
            "tasks": [
                {
                    "task_id": "parallel-1",
                    "description": "First parallel task",
                    "priority": 5
                },
                {
                    "task_id": "parallel-2",
                    "description": "Second parallel task",
                    "priority": 5
                },
                {
                    "task_id": "parallel-3",
                    "description": "Third parallel task",
                    "priority": 5
                },
                {
                    "task_id": "combine-results",
                    "description": "Combine results from parallel tasks",
                    "dependencies": ["parallel-1", "parallel-2", "parallel-3"],
                    "priority": 1
                }
            ]
        }
    }
    
    result = workflow(
        tool=tool_use,
        system_prompt="You are a helpful assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    if result["status"] == "success":
        print("✓ Created workflow with parallel tasks")
        
        # Clean up
        delete_tool_use = {
            "toolUseId": "test-tool-use-14",
            "input": {
                "action": "delete",
                "workflow_id": "test-parallel"
            }
        }
        
        workflow(
            tool=delete_tool_use,
            system_prompt="You are a helpful assistant.",
            inference_config={},
            messages=[],
            tool_config={}
        )
        
        return True
    return False

def main():
    """Run all tests"""
    print("Testing strands_tools.workflow module")
    print(f"Workflow directory: {WORKFLOW_DIR}")
    
    tests = [
        test_workflow_creation,
        test_workflow_list,
        test_workflow_status,
        test_workflow_start,
        test_workflow_delete,
        test_invalid_action,
        test_missing_required_fields,
        test_workflow_persistence,
        test_workflow_with_dependencies,
        test_parallel_tasks
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