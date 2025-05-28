#!/usr/bin/env python3
"""Demo script to test the enhanced CLI functionality."""

import sys
import os

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from manus_use.cli_enhanced import main

if __name__ == "__main__":
    # Test with different commands
    print("Testing ManusUse Enhanced CLI\n")
    
    # Show version
    print("1. Testing --version flag:")
    sys.argv = ['test_cli', '--version']
    try:
        main()
    except SystemExit:
        pass
    
    print("\n" + "="*50 + "\n")
    
    # Test single prompt mode with a simple task
    print("2. Testing single prompt mode (simple task):")
    sys.argv = ['test_cli', '-p', 'What is 2 + 2?']
    try:
        main()
    except SystemExit:
        pass
    
    print("\n" + "="*50 + "\n")
    
    # Test with browser task
    print("3. Testing browser mode (would require browser agent):")
    sys.argv = ['test_cli', '--mode', 'browser', '-p', 'Search for Python tutorials']
    try:
        main()
    except SystemExit:
        pass
    
    print("\n" + "="*50 + "\n")
    
    # Test with complex task that should trigger multi-agent
    print("4. Testing auto mode with complex task:")
    sys.argv = ['test_cli', '-p', 'First analyze the current date and time, then create a summary report about it']
    try:
        main()
    except SystemExit:
        pass