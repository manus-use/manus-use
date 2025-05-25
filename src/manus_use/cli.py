"""Command-line interface for ManusUse."""

import sys
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt

from .agents import ManusAgent
from .config import Config


console = Console()


def main():
    """Main CLI entry point."""
    console.print("[bold blue]Welcome to ManusUse![/bold blue]")
    console.print("An advanced AI agent framework powered by Strands SDK\n")
    
    # Load configuration
    config = Config.from_file()
    
    # Create default agent
    console.print("Initializing agent...", style="dim")
    try:
        agent = ManusAgent(config=config)
        console.print("✓ Agent initialized successfully\n", style="green")
    except Exception as e:
        console.print(f"✗ Failed to initialize agent: {e}", style="red")
        sys.exit(1)
        
    # Interactive loop
    console.print("Type your requests below (type 'exit' to quit):\n")
    
    while True:
        try:
            # Get user input
            user_input = Prompt.ask("\n[bold cyan]You[/bold cyan]")
            
            if user_input.lower() in ["exit", "quit", "bye"]:
                console.print("\n[bold blue]Goodbye![/bold blue]")
                break
                
            # Process with agent
            console.print("\n[bold green]Agent[/bold green]: ", end="")
            
            with console.status("Thinking...", spinner="dots"):
                response = agent(user_input)
                
            console.print(response)
            
        except KeyboardInterrupt:
            console.print("\n\n[bold blue]Goodbye![/bold blue]")
            break
        except Exception as e:
            console.print(f"\n[red]Error: {e}[/red]")
            

if __name__ == "__main__":
    main()