#!/usr/bin/env python3
"""Quick interactive demo of ManusUse CLI."""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from manus_use.cli_enhanced import main

print("""
╔════════════════════════════════════════════════════════════════╗
║                  ManusUse Interactive Demo                     ║
╚════════════════════════════════════════════════════════════════╝

This will start the interactive CLI. Try these commands:

1. Simple math: "What is 25 * 4?"
2. Code task: "Write a Python function to reverse a string"
3. Complex task: "Analyze the current date and create a report"
4. Browser task: "/mode browser" then "Search for Python news"
5. Type "/exit" to quit

Starting interactive mode...
""")

# Start interactive mode
sys.argv = ['interactive_demo']
main()