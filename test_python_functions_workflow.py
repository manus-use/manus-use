#!/usr/bin/env python3
"""Example of using strands_tools.workflow to run Python functions as tasks"""

import json
import os
import sys
import time
from pathlib import Path

# Add the tools directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "tools" / "src"))

from strands_tools.workflow import workflow, WORKFLOW_DIR

def example_python_functions_workflow():
    """Create a workflow that executes Python functions as tasks"""
    print("\n=== Creating Workflow with Python Function Tasks ===")
    
    # Ensure workflow directory exists
    os.makedirs(WORKFLOW_DIR, exist_ok=True)
    
    # Define tasks that will execute Python functions
    tool_use = {
        "toolUseId": "python-functions-workflow",
        "input": {
            "action": "create",
            "workflow_id": "python-functions-demo",
            "tasks": [
                {
                    "task_id": "calculate-fibonacci",
                    "description": """Calculate the first 10 Fibonacci numbers using Python:
                    
def fibonacci(n):
    if n <= 0:
        return []
    elif n == 1:
        return [0]
    elif n == 2:
        return [0, 1]
    else:
        fib = [0, 1]
        for i in range(2, n):
            fib.append(fib[i-1] + fib[i-2])
        return fib

result = fibonacci(10)
print(f"First 10 Fibonacci numbers: {result}")
return result
""",
                    "priority": 5
                },
                {
                    "task_id": "process-data",
                    "description": """Process a list of numbers and calculate statistics:

import statistics

# Sample data
numbers = [23, 45, 67, 89, 12, 34, 56, 78, 90, 21]

# Calculate statistics
mean = statistics.mean(numbers)
median = statistics.median(numbers)
std_dev = statistics.stdev(numbers)

results = {
    "mean": mean,
    "median": median,
    "std_dev": std_dev,
    "min": min(numbers),
    "max": max(numbers),
    "count": len(numbers)
}

print(f"Statistics: {results}")
return results
""",
                    "priority": 4
                },
                {
                    "task_id": "string-manipulation",
                    "description": """Perform string manipulation operations:

def process_text(text):
    # Various string operations
    operations = {
        "original": text,
        "uppercase": text.upper(),
        "lowercase": text.lower(),
        "reversed": text[::-1],
        "word_count": len(text.split()),
        "char_count": len(text),
        "title_case": text.title(),
        "is_palindrome": text.lower() == text.lower()[::-1]
    }
    return operations

sample_text = "Hello World from Python Workflow"
result = process_text(sample_text)
print(f"String operations result: {result}")
return result
""",
                    "priority": 3
                },
                {
                    "task_id": "combine-results",
                    "description": """Combine and summarize results from previous tasks:

# This task depends on the previous tasks
# In a real workflow, you would access the results from dependencies
# For now, let's create a summary

summary = {
    "workflow_name": "Python Functions Demo",
    "tasks_completed": ["calculate-fibonacci", "process-data", "string-manipulation"],
    "summary": "Successfully executed Python functions for mathematical calculations, data processing, and string manipulation",
    "timestamp": str(datetime.now())
}

print(f"Workflow summary: {summary}")
return summary
""",
                    "dependencies": ["calculate-fibonacci", "process-data", "string-manipulation"],
                    "priority": 1
                }
            ]
        }
    }
    
    # Create the workflow
    result = workflow(
        tool=tool_use,
        system_prompt="You are a helpful Python programming assistant. Execute the Python code provided in each task.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"\nWorkflow creation result: {result}")
    return result

def example_data_processing_pipeline():
    """Create a data processing pipeline workflow"""
    print("\n=== Creating Data Processing Pipeline Workflow ===")
    
    tool_use = {
        "toolUseId": "data-pipeline-workflow",
        "input": {
            "action": "create",
            "workflow_id": "data-pipeline-demo",
            "tasks": [
                {
                    "task_id": "generate-data",
                    "description": """Generate sample data for processing:

import random
import json

# Generate sample sales data
sales_data = []
for i in range(100):
    sale = {
        "id": i + 1,
        "product": random.choice(["Widget A", "Widget B", "Widget C", "Widget D"]),
        "quantity": random.randint(1, 10),
        "price": round(random.uniform(10.0, 100.0), 2),
        "date": f"2024-01-{random.randint(1, 31):02d}"
    }
    sales_data.append(sale)

# Save to a variable for next steps
print(f"Generated {len(sales_data)} sales records")
print(f"Sample record: {sales_data[0]}")
return sales_data
""",
                    "priority": 5
                },
                {
                    "task_id": "filter-data",
                    "description": """Filter data based on criteria:

# Filter for high-value sales (quantity * price > 200)
# In a real workflow, this would use the data from generate-data task

filtered_sales = []
for sale in sales_data:  # This would come from previous task
    total_value = sale["quantity"] * sale["price"]
    if total_value > 200:
        sale["total_value"] = total_value
        filtered_sales.append(sale)

print(f"Filtered to {len(filtered_sales)} high-value sales")
return filtered_sales
""",
                    "dependencies": ["generate-data"],
                    "priority": 4
                },
                {
                    "task_id": "aggregate-data",
                    "description": """Aggregate data by product:

from collections import defaultdict

# Aggregate sales by product
# In a real workflow, this would use the filtered data

product_summary = defaultdict(lambda: {"count": 0, "total_quantity": 0, "total_revenue": 0})

for sale in filtered_sales:  # This would come from previous task
    product = sale["product"]
    product_summary[product]["count"] += 1
    product_summary[product]["total_quantity"] += sale["quantity"]
    product_summary[product]["total_revenue"] += sale["total_value"]

# Convert to regular dict for output
summary = dict(product_summary)
print(f"Product summary: {json.dumps(summary, indent=2)}")
return summary
""",
                    "dependencies": ["filter-data"],
                    "priority": 3
                },
                {
                    "task_id": "generate-report",
                    "description": """Generate final report:

# Generate a summary report
# In a real workflow, this would use all previous results

report = {
    "title": "Sales Analysis Report",
    "total_records_processed": 100,
    "high_value_sales": len(filtered_sales),
    "products_analyzed": len(product_summary),
    "top_product": max(product_summary.items(), key=lambda x: x[1]["total_revenue"])[0],
    "recommendations": [
        "Focus on high-value products",
        "Increase inventory for top sellers",
        "Review pricing strategy for low performers"
    ]
}

print("="*50)
print("FINAL REPORT")
print("="*50)
for key, value in report.items():
    print(f"{key}: {value}")
print("="*50)

return report
""",
                    "dependencies": ["aggregate-data"],
                    "priority": 1
                }
            ]
        }
    }
    
    result = workflow(
        tool=tool_use,
        system_prompt="You are a data processing assistant. Execute the Python code to process and analyze data.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"\nData pipeline workflow creation result: {result}")
    return result

def example_parallel_computation():
    """Create a workflow with parallel Python computations"""
    print("\n=== Creating Parallel Computation Workflow ===")
    
    tool_use = {
        "toolUseId": "parallel-computation-workflow",
        "input": {
            "action": "create",
            "workflow_id": "parallel-computation-demo",
            "tasks": [
                {
                    "task_id": "compute-primes",
                    "description": """Find prime numbers up to 100:

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

primes = [n for n in range(2, 101) if is_prime(n)]
print(f"Found {len(primes)} prime numbers")
print(f"First 10 primes: {primes[:10]}")
return primes
""",
                    "priority": 5
                },
                {
                    "task_id": "compute-squares",
                    "description": """Compute squares of numbers:

squares = {n: n**2 for n in range(1, 21)}
print(f"Squares of numbers 1-20: {squares}")
return squares
""",
                    "priority": 5
                },
                {
                    "task_id": "compute-factorials",
                    "description": """Compute factorials:

import math

factorials = {n: math.factorial(n) for n in range(10)}
print(f"Factorials 0-9: {factorials}")
return factorials
""",
                    "priority": 5
                },
                {
                    "task_id": "combine-computations",
                    "description": """Combine all computation results:

# In a real workflow, these would come from task dependencies
combined_results = {
    "computation_type": "Mathematical Operations",
    "total_computations": 3,
    "computation_names": ["primes", "squares", "factorials"],
    "summary": "Successfully computed prime numbers, squares, and factorials in parallel"
}

print(f"Combined computation results: {combined_results}")
return combined_results
""",
                    "dependencies": ["compute-primes", "compute-squares", "compute-factorials"],
                    "priority": 1
                }
            ]
        }
    }
    
    result = workflow(
        tool=tool_use,
        system_prompt="You are a mathematical computation assistant. Execute the Python code for calculations.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"\nParallel computation workflow creation result: {result}")
    return result

def start_workflow(workflow_id):
    """Start a workflow execution"""
    print(f"\n=== Starting Workflow: {workflow_id} ===")
    
    tool_use = {
        "toolUseId": f"start-{workflow_id}",
        "input": {
            "action": "start",
            "workflow_id": workflow_id
        }
    }
    
    try:
        result = workflow(
            tool=tool_use,
            system_prompt="You are a Python programming assistant. Execute the Python code provided in each task.",
            inference_config={},
            messages=[],
            tool_config={}
        )
        print(f"Start result: {result}")
        return result
    except Exception as e:
        print(f"Note: Workflow execution requires a configured LLM agent")
        print(f"Error: {e}")
        return None

def check_workflow_status(workflow_id):
    """Check workflow status"""
    print(f"\n=== Checking Status: {workflow_id} ===")
    
    tool_use = {
        "toolUseId": f"status-{workflow_id}",
        "input": {
            "action": "status",
            "workflow_id": workflow_id
        }
    }
    
    result = workflow(
        tool=tool_use,
        system_prompt="You are a workflow assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    
    print(f"Status: {result}")
    return result

def cleanup_workflow(workflow_id):
    """Delete a workflow"""
    tool_use = {
        "toolUseId": f"delete-{workflow_id}",
        "input": {
            "action": "delete",
            "workflow_id": workflow_id
        }
    }
    
    workflow(
        tool=tool_use,
        system_prompt="You are a workflow assistant.",
        inference_config={},
        messages=[],
        tool_config={}
    )
    print(f"Cleaned up workflow: {workflow_id}")

def main():
    """Run examples of Python function workflows"""
    print("=== Python Functions as Workflow Tasks ===")
    print(f"Workflow directory: {WORKFLOW_DIR}")
    
    # Example 1: Basic Python functions
    result1 = example_python_functions_workflow()
    if result1["status"] == "success":
        check_workflow_status("python-functions-demo")
        # Uncomment to start execution (requires configured LLM)
        # start_workflow("python-functions-demo")
        cleanup_workflow("python-functions-demo")
    
    # Example 2: Data processing pipeline
    result2 = example_data_processing_pipeline()
    if result2["status"] == "success":
        check_workflow_status("data-pipeline-demo")
        # Uncomment to start execution (requires configured LLM)
        # start_workflow("data-pipeline-demo")
        cleanup_workflow("data-pipeline-demo")
    
    # Example 3: Parallel computations
    result3 = example_parallel_computation()
    if result3["status"] == "success":
        check_workflow_status("parallel-computation-demo")
        # Uncomment to start execution (requires configured LLM)
        # start_workflow("parallel-computation-demo")
        cleanup_workflow("parallel-computation-demo")
    
    print("\n=== Summary ===")
    print("Created workflows that demonstrate:")
    print("1. Basic Python function execution")
    print("2. Data processing pipeline with dependencies")
    print("3. Parallel mathematical computations")
    print("\nNote: To actually execute these workflows, you need a configured LLM agent.")
    print("The workflow system will pass the Python code to the agent for execution.")

if __name__ == "__main__":
    # Add datetime import for the workflow tasks
    from datetime import datetime
    main()