#!/usr/bin/env python3
"""Simple test of the CLI without browser tasks."""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from manus_use.cli_enhanced import main

# Test cases that don't require browser
test_cases = [
    # 1. Simple calculation
    {
        "args": ["-p", "Calculate 25 * 4"],
        "description": "Simple calculation"
    },
    
    # 2. Code generation
    {
        "args": ["-p", "Write a Python function to check if a number is prime"],
        "description": "Code generation"
    },
    
    # 3. File operation (if tools work)
    {
        "args": ["-p", "Create a file called test.txt with the content 'Hello World'"],
        "description": "File operation"
    },
    
    # 4. Multi-step task (should trigger multi-agent)
    {
        "args": ["--mode", "multi", "-p", "First calculate 10 + 20, then create a Python function that returns this sum"],
        "description": "Multi-step task"
    }
]

print("Testing ManusUse CLI\n")

for i, test in enumerate(test_cases, 1):
    print(f"\n{'='*60}")
    print(f"Test {i}: {test['description']}")
    print(f"{'='*60}")
    
    # Set command line arguments
    sys.argv = ["test_cli"] + test["args"]
    
    try:
        main()
    except SystemExit:
        pass
    except Exception as e:
        print(f"Error: {e}")
    
    print()  # Add spacing between tests