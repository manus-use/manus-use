#!/usr/bin/env python3
"""Demo script showing how to use the ManusUse CLI."""

import subprocess
import sys
import time

def run_command(cmd, description=""):
    """Run a command and display it nicely."""
    if description:
        print(f"\n{'='*60}")
        print(f"📌 {description}")
        print(f"{'='*60}")
    
    print(f"$ {cmd}")
    print()
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(f"⚠️  {result.stderr}", file=sys.stderr)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("⏱️  Command timed out after 30 seconds")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    """Demonstrate CLI usage."""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║               ManusUse CLI Usage Demo                         ║
╚═══════════════════════════════════════════════════════════════╝

This demo shows different ways to use the ManusUse CLI.
""")
    
    # Demo 1: Show version
    run_command(
        "cd /Users/x/Develop/manus/manus-use && source venv/bin/activate && python -m manus_use.cli_enhanced --version",
        "1. Show version information"
    )
    
    # Demo 2: Simple calculation
    run_command(
        "cd /Users/x/Develop/manus/manus-use && source venv/bin/activate && python -m manus_use.cli_enhanced -p 'Calculate 15 * 23'",
        "2. Simple calculation with single agent"
    )
    
    # Demo 3: Complex task (triggers multi-agent)
    run_command(
        "cd /Users/x/Develop/manus/manus-use && source venv/bin/activate && python -m manus_use.cli_enhanced -p 'Analyze the current time and then create a simple report about it'",
        "3. Complex task with multi-agent orchestration"
    )
    
    # Demo 4: Force single agent mode
    run_command(
        "cd /Users/x/Develop/manus/manus-use && source venv/bin/activate && python -m manus_use.cli_enhanced --mode single -p 'What is the capital of France?'",
        "4. Force single agent mode"
    )
    
    # Demo 5: Show help
    run_command(
        "cd /Users/x/Develop/manus/manus-use && source venv/bin/activate && python -m manus_use.cli_enhanced --help",
        "5. Show help and available options"
    )
    
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                    Interactive Mode                           ║
╚═══════════════════════════════════════════════════════════════╝

To start interactive mode, run:
$ python -m manus_use.cli_enhanced

In interactive mode, you can:
- Type tasks naturally
- Use /mode to switch between auto/single/multi/browser modes
- Use /history to see command history  
- Use /clear to clear the screen
- Use /exit to quit

Example session:
[auto] > What is 2 + 2?
[auto] > /mode multi
[multi] > Analyze data and create a report
[multi] > /exit
""")

if __name__ == "__main__":
    main()