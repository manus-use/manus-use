#!/usr/bin/env python3
"""
Test workflow creation and execution without using Strands agents
"""

import json
from pathlib import Path

# Create workflows directory
WORKFLOW_DIR = Path(__file__).parent / "workflows"
WORKFLOW_DIR.mkdir(exist_ok=True)

def create_test_workflow():
    """Create a test workflow manually"""
    
    # Define a simple workflow
    workflow = {
        "workflow_id": "test_direct_001",
        "created_at": "2025-05-29T10:00:00Z",
        "status": "created",
        "tasks": [
            {
                "task_id": "task1",
                "type": "computation",
                "description": "Print hello world",
                "agent_type": "manus",
                "priority": 1
            },
            {
                "task_id": "task2",
                "type": "data_analysis",
                "description": "Generate a simple chart",
                "agent_type": "data_analysis",
                "priority": 2,
                "dependencies": []
            },
            {
                "task_id": "task3",
                "type": "file_operation",
                "description": "Save results to file",
                "agent_type": "manus",
                "priority": 3,
                "dependencies": ["task1", "task2"]
            }
        ],
        "current_task_index": 0,
        "task_results": {
            "task1": {"status": "pending", "result": None, "priority": 1},
            "task2": {"status": "pending", "result": None, "priority": 2},
            "task3": {"status": "pending", "result": None, "priority": 3}
        },
        "parallel_execution": True
    }
    
    # Save workflow to file
    workflow_file = WORKFLOW_DIR / f"{workflow['workflow_id']}.json"
    with open(workflow_file, "w") as f:
        json.dump(workflow, f, indent=2)
    
    print(f"Created workflow file: {workflow_file}")
    print(f"Workflow content:\n{json.dumps(workflow, indent=2)}")
    
    # List all workflows
    print("\n=== All Workflows ===")
    for wf_file in WORKFLOW_DIR.glob("*.json"):
        print(f"- {wf_file.name}")
        
    return workflow

def check_workflow_structure():
    """Check the structure of existing workflows"""
    print("\n=== Checking Existing Workflows ===")
    
    for wf_file in WORKFLOW_DIR.glob("*.json"):
        try:
            with open(wf_file, "r") as f:
                wf_data = json.load(f)
                print(f"\nWorkflow: {wf_file.stem}")
                print(f"  Status: {wf_data.get('status', 'unknown')}")
                print(f"  Tasks: {len(wf_data.get('tasks', []))}")
                
                # Show task details
                for task in wf_data.get('tasks', []):
                    print(f"    - {task.get('task_id', 'unknown')}: {task.get('description', 'no description')}")
                    print(f"      Type: {task.get('type', 'unknown')}, Agent: {task.get('agent_type', 'unknown')}")
                    
        except Exception as e:
            print(f"Error reading {wf_file}: {e}")

if __name__ == "__main__":
    # Check existing workflows first
    check_workflow_structure()
    
    # Create a new test workflow
    print("\n=== Creating New Test Workflow ===")
    create_test_workflow()