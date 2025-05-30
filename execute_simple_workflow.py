#!/usr/bin/env python3
"""
Simple workflow execution example
"""

import os
import sys
import time
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.tools.workflow import manus_workflow, WORKFLOW_DIR

def create_simple_workflow():
    """Create a simple workflow that can be executed quickly"""
    print("\n=== Creating Simple Workflow ===")
    
    tool_use = {
        "toolUseId": "create-simple",
        "input": {
            "action": "create",
            "workflow_id": "quick-analysis",
            "tasks": [
                {
                    "task_id": "generate-data",
                    "description": """Generate a simple dataset:
Create a Python list of 10 random numbers between 1 and 100.
Store it in a variable called 'numbers'.
Print the numbers.""",
                    "agent_type": "manus",
                    "priority": 5
                },
                {
                    "task_id": "analyze-data",
                    "description": """Analyze the numbers:
Calculate the mean, median, min, and max of the numbers.
Create a simple text-based visualization showing the distribution.
Print the results.""",
                    "agent_type": "data_analysis",
                    "dependencies": ["generate-data"],
                    "priority": 3
                },
                {
                    "task_id": "create-summary",
                    "description": """Create a summary report:
Summarize the findings from the analysis.
Include the key statistics and any patterns observed.
Save the summary to a file called 'analysis_summary.txt'.""",
                    "agent_type": "manus",
                    "dependencies": ["analyze-data"],
                    "priority": 1
                }
            ]
        }
    }
    
    result = manus_workflow(
        tool=tool_use,
        system_prompt="You are a helpful data analysis assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"Create result: {result}")
    return result

def start_workflow(workflow_id):
    """Start workflow execution"""
    print(f"\n=== Starting Workflow: {workflow_id} ===")
    
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
    
    print(f"Start result: {result}")
    return result

def monitor_workflow(workflow_id, max_checks=10, interval=5):
    """Monitor workflow execution"""
    print(f"\n=== Monitoring Workflow: {workflow_id} ===")
    
    for i in range(max_checks):
        tool_use = {
            "toolUseId": f"status-{workflow_id}-{i}",
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
        
        if result["status"] == "success":
            content = result["content"][0]["text"]
            if "Overall Status: completed" in content:
                print(f"\n✓ Workflow completed!")
                print(content)
                return True
            elif "Overall Status: running" in content:
                # Extract progress
                try:
                    progress_line = [line for line in content.split('\n') if 'Progress:' in line][0]
                    print(f"Check {i+1}: {progress_line}")
                except:
                    print(f"Check {i+1}: Workflow is running...")
            elif "Overall Status: error" in content:
                print(f"\n✗ Workflow failed!")
                print(content)
                return False
        
        if i < max_checks - 1:
            time.sleep(interval)
    
    print(f"\n⚠️  Workflow did not complete within {max_checks * interval} seconds")
    return False

def main():
    """Main execution"""
    print("=== Simple Workflow Execution Example ===")
    print(f"Workflow directory: {WORKFLOW_DIR}")
    
    # Ensure workflow directory exists
    os.makedirs(WORKFLOW_DIR, exist_ok=True)
    
    # Check config
    config_path = Path(__file__).parent / "config.toml"
    if not config_path.exists():
        print(f"\n⚠️  Warning: Config file not found at {config_path}")
        print("Workflow execution requires proper configuration")
        return
    
    # Create workflow
    create_result = create_simple_workflow()
    if create_result["status"] != "success":
        print("Failed to create workflow")
        return
    
    workflow_id = "quick-analysis"
    
    # Start workflow
    print("\n" + "="*50)
    print("STARTING WORKFLOW EXECUTION")
    print("="*50)
    
    start_result = start_workflow(workflow_id)
    if start_result["status"] == "success":
        # Monitor execution
        monitor_workflow(workflow_id, max_checks=20, interval=3)
    else:
        print("Failed to start workflow")
    
    # Cleanup
    print("\n=== Cleaning Up ===")
    tool_use = {
        "toolUseId": "cleanup",
        "input": {
            "action": "delete",
            "workflow_id": workflow_id
        }
    }
    
    manus_workflow(
        tool=tool_use,
        system_prompt="",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print("Workflow deleted")

if __name__ == "__main__":
    main()