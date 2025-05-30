#!/usr/bin/env python3
"""
Advanced example: Create a workflow system that can execute Python functions directly
by extending the workflow tool to support function execution.
"""

import asyncio
import json
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from datetime import datetime

# Add the tools directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "tools" / "src"))

from strands_tools.workflow import workflow, WorkflowManager, WORKFLOW_DIR

class PythonFunctionWorkflow:
    """Helper class to create workflows from Python functions"""
    
    def __init__(self):
        self.functions = {}
        self.workflows = {}
    
    def register_function(self, func: Callable, task_id: str = None, 
                         dependencies: List[str] = None, priority: int = 3):
        """Register a Python function as a workflow task"""
        if task_id is None:
            task_id = func.__name__
        
        self.functions[task_id] = {
            "function": func,
            "dependencies": dependencies or [],
            "priority": priority
        }
        
        return task_id
    
    def create_workflow_from_functions(self, workflow_id: str, 
                                     function_ids: List[str],
                                     system_prompt: str = None):
        """Create a workflow from registered functions"""
        tasks = []
        
        for func_id in function_ids:
            if func_id not in self.functions:
                raise ValueError(f"Function {func_id} not registered")
            
            func_info = self.functions[func_id]
            func = func_info["function"]
            
            # Create task description that includes the function code
            task_description = f"""Execute this Python function and return the result:

```python
{self._get_function_source(func)}

# Execute the function
result = {func.__name__}()
print(f"Function result: {{result}}")
return result
```"""
            
            task = {
                "task_id": func_id,
                "description": task_description,
                "dependencies": func_info["dependencies"],
                "priority": func_info["priority"]
            }
            
            tasks.append(task)
        
        # Create workflow
        tool_use = {
            "toolUseId": f"create-{workflow_id}",
            "input": {
                "action": "create",
                "workflow_id": workflow_id,
                "tasks": tasks
            }
        }
        
        result = workflow(
            tool=tool_use,
            system_prompt=system_prompt or "You are a Python function executor. Execute the provided Python functions and return their results.",
            inference_config={},
            messages=[],
            tool_config={}
        )
        
        if result["status"] == "success":
            self.workflows[workflow_id] = {
                "functions": function_ids,
                "created_at": datetime.now().isoformat()
            }
        
        return result
    
    def _get_function_source(self, func: Callable) -> str:
        """Get the source code of a function"""
        import inspect
        try:
            return inspect.getsource(func)
        except:
            # Fallback for lambda or built-in functions
            return f"# Function: {func.__name__}\n# [Source not available]"
    
    def execute_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Execute a workflow (requires configured LLM)"""
        tool_use = {
            "toolUseId": f"start-{workflow_id}",
            "input": {
                "action": "start",
                "workflow_id": workflow_id
            }
        }
        
        return workflow(
            tool=tool_use,
            system_prompt="You are a Python function executor.",
            inference_config={},
            messages=[],
            tool_config={}
        )
    
    def get_status(self, workflow_id: str) -> Dict[str, Any]:
        """Get workflow status"""
        tool_use = {
            "toolUseId": f"status-{workflow_id}",
            "input": {
                "action": "status",
                "workflow_id": workflow_id
            }
        }
        
        return workflow(
            tool=tool_use,
            system_prompt="You are a workflow assistant.",
            inference_config={},
            messages=[],
            tool_config={}
        )


# Example usage with actual Python functions
def example_with_real_functions():
    """Example using real Python functions in a workflow"""
    print("\n=== Example: Real Python Functions Workflow ===")
    
    # Create workflow manager
    wf = PythonFunctionWorkflow()
    
    # Define some Python functions
    def fetch_data():
        """Simulate fetching data from a source"""
        data = {
            "users": [
                {"id": 1, "name": "Alice", "score": 85},
                {"id": 2, "name": "Bob", "score": 92},
                {"id": 3, "name": "Charlie", "score": 78},
                {"id": 4, "name": "David", "score": 95},
                {"id": 5, "name": "Eve", "score": 88}
            ]
        }
        return data
    
    def process_data():
        """Process the fetched data"""
        # In a real workflow, this would use the data from fetch_data
        # For demo purposes, we'll recreate it
        data = {
            "users": [
                {"id": 1, "name": "Alice", "score": 85},
                {"id": 2, "name": "Bob", "score": 92},
                {"id": 3, "name": "Charlie", "score": 78},
                {"id": 4, "name": "David", "score": 95},
                {"id": 5, "name": "Eve", "score": 88}
            ]
        }
        
        # Calculate statistics
        scores = [user["score"] for user in data["users"]]
        avg_score = sum(scores) / len(scores)
        max_score = max(scores)
        min_score = min(scores)
        
        processed = {
            "total_users": len(data["users"]),
            "average_score": avg_score,
            "max_score": max_score,
            "min_score": min_score,
            "top_performer": next(u["name"] for u in data["users"] if u["score"] == max_score)
        }
        
        return processed
    
    def generate_report():
        """Generate a report from processed data"""
        # This would use results from process_data in a real workflow
        processed = {
            "total_users": 5,
            "average_score": 87.6,
            "max_score": 95,
            "min_score": 78,
            "top_performer": "David"
        }
        
        report = f"""
Performance Report
==================
Total Users: {processed['total_users']}
Average Score: {processed['average_score']:.1f}
Highest Score: {processed['max_score']}
Lowest Score: {processed['min_score']}
Top Performer: {processed['top_performer']}

Recommendation: Continue monitoring performance trends.
"""
        return report
    
    # Register functions
    wf.register_function(fetch_data, priority=5)
    wf.register_function(process_data, dependencies=["fetch_data"], priority=3)
    wf.register_function(generate_report, dependencies=["process_data"], priority=1)
    
    # Create workflow
    result = wf.create_workflow_from_functions(
        workflow_id="data-processing-workflow",
        function_ids=["fetch_data", "process_data", "generate_report"]
    )
    
    print(f"Workflow creation result: {result}")
    
    if result["status"] == "success":
        # Check status
        status = wf.get_status("data-processing-workflow")
        print(f"\nWorkflow status: {status}")
        
        # Clean up
        cleanup_tool_use = {
            "toolUseId": "cleanup-data-processing",
            "input": {
                "action": "delete",
                "workflow_id": "data-processing-workflow"
            }
        }
        workflow(cleanup_tool_use, system_prompt="", inference_config={}, messages=[], tool_config={})


def example_mathematical_pipeline():
    """Example: Mathematical computation pipeline"""
    print("\n=== Example: Mathematical Pipeline ===")
    
    wf = PythonFunctionWorkflow()
    
    # Mathematical functions
    def generate_numbers():
        """Generate a list of numbers"""
        import random
        numbers = [random.randint(1, 100) for _ in range(20)]
        return {"numbers": numbers}
    
    def calculate_statistics():
        """Calculate statistics from numbers"""
        # In real workflow, would use result from generate_numbers
        import statistics
        numbers = [23, 45, 67, 89, 12, 34, 56, 78, 90, 21, 43, 65, 87, 32, 54, 76, 98, 10, 32, 54]
        
        stats = {
            "mean": statistics.mean(numbers),
            "median": statistics.median(numbers),
            "mode": statistics.mode(numbers) if len(set(numbers)) < len(numbers) else "No mode",
            "std_dev": statistics.stdev(numbers),
            "variance": statistics.variance(numbers)
        }
        return stats
    
    def visualize_results():
        """Create a simple text visualization"""
        # Would use results from previous tasks
        stats = {
            "mean": 53.5,
            "median": 54.0,
            "mode": "32",
            "std_dev": 26.8,
            "variance": 718.4
        }
        
        visualization = f"""
Statistical Analysis Results
============================
Mean:     {stats['mean']:.2f}  |{'█' * int(stats['mean']/2)}
Median:   {stats['median']:.2f}  |{'█' * int(stats['median']/2)}
Std Dev:  {stats['std_dev']:.2f}  |{'█' * int(stats['std_dev']/2)}

Distribution: Normal (approximate)
"""
        return visualization
    
    # Register and create workflow
    wf.register_function(generate_numbers, priority=5)
    wf.register_function(calculate_statistics, dependencies=["generate_numbers"], priority=3)
    wf.register_function(visualize_results, dependencies=["calculate_statistics"], priority=1)
    
    result = wf.create_workflow_from_functions(
        workflow_id="math-pipeline",
        function_ids=["generate_numbers", "calculate_statistics", "visualize_results"]
    )
    
    print(f"Math pipeline result: {result}")
    
    # Cleanup
    if result["status"] == "success":
        cleanup_tool_use = {
            "toolUseId": "cleanup-math",
            "input": {"action": "delete", "workflow_id": "math-pipeline"}
        }
        workflow(cleanup_tool_use, system_prompt="", inference_config={}, messages=[], tool_config={})


def example_async_style_workflow():
    """Example: Simulating async-style workflow with parallel tasks"""
    print("\n=== Example: Parallel Task Workflow ===")
    
    wf = PythonFunctionWorkflow()
    
    # Define parallel tasks (no dependencies)
    def task_a():
        """Independent task A"""
        result = {"task": "A", "value": sum(range(100)), "timestamp": str(datetime.now())}
        return result
    
    def task_b():
        """Independent task B"""
        result = {"task": "B", "value": len("Hello World" * 100), "timestamp": str(datetime.now())}
        return result
    
    def task_c():
        """Independent task C"""
        result = {"task": "C", "value": 2 ** 10, "timestamp": str(datetime.now())}
        return result
    
    def combine_results():
        """Combine results from parallel tasks"""
        # In real workflow, would get results from tasks A, B, C
        combined = {
            "all_tasks": ["A", "B", "C"],
            "combined_value": 4950 + 1100 + 1024,  # Sum of all task values
            "completion_time": str(datetime.now()),
            "status": "All parallel tasks completed successfully"
        }
        return combined
    
    # Register all tasks
    wf.register_function(task_a, priority=5)
    wf.register_function(task_b, priority=5)
    wf.register_function(task_c, priority=5)
    wf.register_function(combine_results, 
                        dependencies=["task_a", "task_b", "task_c"], 
                        priority=1)
    
    # Create workflow
    result = wf.create_workflow_from_functions(
        workflow_id="parallel-tasks",
        function_ids=["task_a", "task_b", "task_c", "combine_results"]
    )
    
    print(f"Parallel workflow result: {result}")
    
    # Cleanup
    if result["status"] == "success":
        cleanup_tool_use = {
            "toolUseId": "cleanup-parallel",
            "input": {"action": "delete", "workflow_id": "parallel-tasks"}
        }
        workflow(cleanup_tool_use, system_prompt="", inference_config={}, messages=[], tool_config={})


def main():
    """Run all examples"""
    print("=== Python Function Workflow Executor ===")
    print(f"Workflow directory: {WORKFLOW_DIR}")
    
    # Ensure workflow directory exists
    os.makedirs(WORKFLOW_DIR, exist_ok=True)
    
    # Run examples
    example_with_real_functions()
    example_mathematical_pipeline()
    example_async_style_workflow()
    
    print("\n=== Summary ===")
    print("This example demonstrates:")
    print("1. Creating workflows from Python functions")
    print("2. Handling task dependencies")
    print("3. Parallel task execution")
    print("4. Data processing pipelines")
    print("\nNote: Actual execution requires a configured LLM agent.")
    print("The workflow system converts functions to prompts for the agent.")

if __name__ == "__main__":
    main()