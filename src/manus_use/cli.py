"""Command-line interface for ManusUse."""

import argparse
import re
import sys

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from .agents import ManusAgent
from .config import Config
from .multi_agents import Orchestrator


console = Console()


def is_complex_task(user_input: str) -> bool:
    """Determine if a task requires multi-agent orchestration."""
    # Keywords that indicate complex tasks
    complex_indicators = [
        r'\band\b.*\band\b',  # Multiple "and" conjunctions
        r'\bthen\b',          # Sequential tasks
        r'\bafter\b',         # Dependency indicators
        r'\banalyze\b.*\b(create|generate|build)',  # Analysis + creation
        r'\bcompare\b.*\bsummarize',  # Multiple analysis steps
        r'\bmultiple\b',      # Explicit mention of multiple items
        r'\bsteps?\b',        # Mention of steps
        r'\bworkflow\b',      # Workflow tasks
        r'(first|second|third|finally)',  # Ordered tasks
        r'\b(visuali[sz]e|chart|graph)\b.*\b(analyze|data)',  # Data viz + analysis
        r'\bbrowse\b.*\b(extract|analyze)',  # Web + analysis
        r'\bresearch\b.*\b(implement|create)',  # Research + creation
    ]
    
    # Check length - very long requests often contain multiple tasks
    if len(user_input.split()) > 30:
        return True
    
    # Check for multiple sentence/clauses
    if len(re.split(r'[.;]', user_input)) > 2:
        return True
    
    # Check for complex indicators
    for pattern in complex_indicators:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True
    
    return False


def display_task_plan(tasks):
    """Display the execution plan in a formatted table."""
    table = Table(title="Execution Plan", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="cyan", width=6)
    table.add_column("Task", style="white")
    table.add_column("Agent", style="yellow")
    table.add_column("Dependencies", style="blue")
    
    for task in tasks:
        deps = ", ".join(task.dependencies) if task.dependencies else "None"
        table.add_row(
            task.task_id,
            task.description[:50] + "..." if len(task.description) > 50 else task.description,
            task.agent_type.value,
            deps
        )
    
    console.print(table)


def main():
    """Main CLI entry point."""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="ManusUse - Advanced AI Agent Framework")
    parser.add_argument(
        "--mode", 
        choices=["auto", "single", "multi"], 
        default="auto",
        help="Execution mode: auto (detect complexity), single (single agent), multi (multi-agent)"
    )
    parser.add_argument(
        "--show-plan",
        action="store_true",
        help="Show execution plan for multi-agent tasks"
    )
    args = parser.parse_args()
    
    console.print("[bold blue]Welcome to ManusUse![/bold blue]")
    console.print("An advanced AI agent framework powered by Strands SDK")
    console.print(f"Mode: [cyan]{args.mode}[/cyan]\n")
    
    # Load configuration
    config = Config.from_file()
    
    # Initialize agents
    console.print("Initializing agents...", style="dim")
    try:
        # Always create single agent
        agent = ManusAgent(config=config)
        
        # Create orchestrator for multi-agent mode
        orchestrator = None
        if args.mode in ["auto", "multi"]:
            orchestrator = Orchestrator(config=config)
            
        console.print("✓ Agents initialized successfully\n", style="green")
    except Exception as e:
        console.print(f"✗ Failed to initialize agents: {e}", style="red")
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
            
            # Determine execution mode
            use_multi_agent = False
            if args.mode == "multi":
                use_multi_agent = True
            elif args.mode == "auto" and is_complex_task(user_input):
                use_multi_agent = True
                console.print("\n[dim]Detected complex task - using multi-agent orchestration[/dim]")
            
            # Execute task
            if use_multi_agent and orchestrator:
                # Multi-agent execution
                console.print("\n[bold green]Orchestrator[/bold green]: Planning execution...\n")
                
                # Show execution plan if requested
                if args.show_plan:
                    planner = orchestrator.agents.get("planner")
                    if planner:
                        tasks = planner.create_plan(user_input)
                        display_task_plan(tasks)
                        console.print()
                
                # Execute with progress indication
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
                ) as progress:
                    task = progress.add_task("Executing multi-agent workflow...", total=None)
                    
                    # Run orchestrator
                    result = orchestrator.run(user_input)
                    
                    progress.update(task, completed=True)
                
                # Display results
                if result.success:
                    console.print(Panel(
                        result.output,
                        title="[bold green]Result[/bold green]",
                        border_style="green"
                    ))
                else:
                    console.print(Panel(
                        f"Task failed: {result.error}",
                        title="[bold red]Error[/bold red]",
                        border_style="red"
                    ))
            else:
                # Single agent execution
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