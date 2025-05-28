#!/usr/bin/env python3
"""Test workflow directly without agent orchestration"""

import asyncio
import os
import sys

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from manus_use.multi_agents.planning_agent import create_task_plan_tool
from strands_tools.workflow import workflow as workflow_tool

async def main():
    """Test workflow directly"""
    # Step 1: Create a task plan
    request = "List 3 common web vulnerabilities"
    print(f"Creating task plan for: {request}")
    
    task_list = create_task_plan_tool(request)
    print(f"\nTask list created with {len(task_list)} tasks")
    
    # Step 2: Create workflow
    workflow_id = "test_workflow_001"
    create_tool_use = {
        "toolUseId": f"create_{workflow_id}",
        "input": {
            "action": "create",
            "workflow_id": workflow_id,
            "tasks": task_list
        }
    }
    
    print(f"\nCreating workflow {workflow_id}...")
    create_result = workflow_tool(tool=create_tool_use)
    if asyncio.iscoroutine(create_result):
        create_result = await create_result
    
    print(f"Create result: {create_result}")
    
    if create_result.get("status") == "error":
        print(f"Error creating workflow: {create_result}")
        return
    
    # Step 3: Start workflow
    start_tool_use = {
        "toolUseId": f"start_{workflow_id}",
        "input": {
            "action": "start",
            "workflow_id": workflow_id
        }
    }
    
    print(f"\nStarting workflow {workflow_id}...")
    start_result = workflow_tool(tool=start_tool_use)
    if asyncio.iscoroutine(start_result):
        start_result = await start_result
    
    print(f"\nWorkflow result: {start_result}")

if __name__ == "__main__":
    asyncio.run(main())