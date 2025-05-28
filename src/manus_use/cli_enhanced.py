#!/usr/bin/env python3
"""Enhanced CLI for ManusUse with streaming support and better UX."""

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any

import click
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.markdown import Markdown

from .agents import ManusAgent, BrowserUseAgent
from .config import Config
from .multi_agents import Orchestrator, PlanningAgent

# Initialize console
console = Console()

# Paths
CONFIG_DIR = Path.home() / '.config' / 'manus-use'
HISTORY_FILE = CONFIG_DIR / 'history.json'
CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_history() -> List[str]:
    """Load command history."""
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE) as f:
                return json.load(f)
        except:
            pass
    return []


def save_history(history: List[str]) -> None:
    """Save command history."""
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history[-100:], f)  # Keep last 100 commands


def detect_task_complexity(task: str) -> tuple[bool, str]:
    """Detect if task is complex and return reasoning."""
    indicators = {
        'sequential': ['then', 'after', 'next', 'finally'],
        'multiple': ['and also', 'as well as', 'plus', 'both'],
        'analysis': ['analyze', 'compare', 'evaluate', 'assess'],
        'creation': ['create', 'generate', 'build', 'write'],
        'web': ['browse', 'search', 'find online', 'web'],
        'data': ['visualize', 'chart', 'graph', 'plot'],
    }
    
    task_lower = task.lower()
    matched = []
    
    for category, keywords in indicators.items():
        if any(kw in task_lower for kw in keywords):
            matched.append(category)
    
    is_complex = len(matched) >= 2 or len(task.split()) > 30
    
    if is_complex:
        reason = f"Detected: {', '.join(matched)}" if matched else "Long task description"
        return True, reason
    return False, ""


class EnhancedCLI:
    """Enhanced CLI with better UX and streaming support."""
    
    def __init__(self, config: Config):
        self.config = config
        self.history = load_history()
        self.agent: Optional[ManusAgent] = None
        self.orchestrator: Optional[Orchestrator] = None
        self.browser_agent: Optional[BrowserUseAgent] = None
        
    def setup_agents(self, mode: str = 'auto') -> None:
        """Initialize agents based on mode."""
        with console.status("Initializing agents...", spinner="dots"):
            try:
                # Always create basic agent
                self.agent = ManusAgent(config=self.config)
                
                # Create orchestrator for multi-agent tasks
                if mode in ['auto', 'multi']:
                    self.orchestrator = Orchestrator(config=self.config)
                
                # Create browser agent if needed
                if mode in ['browser', 'auto']:
                    self.browser_agent = BrowserUseAgent(
                        config=self.config,
                        headless=self.config.browser_use.headless
                    )
                    
                console.print("✅ Agents initialized", style="green")
            except Exception as e:
                console.print(f"❌ Failed to initialize agents: {e}", style="red")
                sys.exit(1)
    
    async def run_single_agent(self, task: str) -> None:
        """Run task with single agent."""
        console.print(Panel(task, title="[cyan]Task[/cyan]", border_style="cyan"))
        
        with console.status("Thinking...", spinner="dots"):
            try:
                response = await asyncio.to_thread(self.agent, task)
                console.print("\n[green]Response:[/green]")
                
                # Format response nicely
                if isinstance(response, str):
                    # Check if it's code
                    if any(response.startswith(prefix) for prefix in ['```', 'def ', 'class ', 'import ']):
                        syntax = Syntax(response, "python", theme="monokai")
                        console.print(syntax)
                    # Check if it's markdown
                    elif any(char in response for char in ['#', '**', '- ', '1. ']):
                        md = Markdown(response)
                        console.print(md)
                    else:
                        console.print(response)
                else:
                    console.print(response)
                    
            except Exception as e:
                console.print(f"[red]Error:[/red] {e}")
    
    async def run_multi_agent(self, task: str) -> None:
        """Run task with multi-agent orchestration."""
        console.print(Panel(task, title="[cyan]Complex Task[/cyan]", border_style="cyan"))
        
        # First, show the plan
        console.print("\n[yellow]Creating execution plan...[/yellow]")
        
        try:
            # Get the plan
            planner = getattr(self.orchestrator, 'planner', None) or PlanningAgent(config=self.config)
            if planner:
                plan = planner.create_plan(task)
                
                # Display plan in a nice table
                table = Table(title="Execution Plan", show_header=True)
                table.add_column("Step", style="cyan", width=6)
                table.add_column("Task", style="white")
                table.add_column("Agent", style="yellow")
                table.add_column("Deps", style="blue")
                
                for i, task_plan in enumerate(plan, 1):
                    deps = ", ".join(task_plan.dependencies) if task_plan.dependencies else "-"
                    table.add_row(
                        str(i),
                        task_plan.description[:50] + "..." if len(task_plan.description) > 50 else task_plan.description,
                        task_plan.agent_type.value,
                        deps
                    )
                
                console.print(table)
                console.print()
            
            # Execute with progress
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=console
            ) as progress:
                task_id = progress.add_task("Executing workflow...", total=100)
                
                # Run orchestrator
                result = await self.orchestrator.run_async(task)
                
                progress.update(task_id, completed=100)
            
            # Display result
            if result.success:
                console.print(Panel(
                    result.output,
                    title="[green]✅ Success[/green]",
                    border_style="green"
                ))
            else:
                console.print(Panel(
                    result.error,
                    title="[red]❌ Error[/red]",
                    border_style="red"
                ))
                
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
    
    async def run_browser_task(self, task: str) -> None:
        """Run task with browser agent."""
        console.print(Panel(task, title="[cyan]Browser Task[/cyan]", border_style="cyan"))
        
        # Check if we want streaming
        if hasattr(self.browser_agent, 'stream_async'):
            console.print("[yellow]Streaming browser actions...[/yellow]\n")
            
            try:
                async for event in self.browser_agent.stream_async(task):
                    if event['type'] == 'step_update':
                        console.print(f"[blue]Step {event['step']}:[/blue] {event.get('url', 'Loading...')}")
                        if event.get('next_goal'):
                            console.print(f"  [dim]Goal: {event['next_goal']}[/dim]")
                    elif event['type'] == 'final_result':
                        console.print(f"\n[green]✅ Task completed[/green]")
                        if event.get('content'):
                            console.print(Panel(event['content'], title="Result", border_style="green"))
                    elif event['type'] == 'error':
                        console.print(f"[red]❌ Error: {event['message']}[/red]")
            except Exception as e:
                console.print(f"[red]Error:[/red] {e}")
        else:
            # Fallback to non-streaming
            with console.status("Browser working...", spinner="dots"):
                try:
                    result = await self.browser_agent(task)
                    console.print(Panel(str(result), title="[green]Result[/green]", border_style="green"))
                except Exception as e:
                    console.print(f"[red]Error:[/red] {e}")
    
    async def run_task(self, task: str, mode: str = 'auto') -> None:
        """Run a task with appropriate agent(s)."""
        # Add to history
        self.history.append(task)
        save_history(self.history)
        
        # Detect complexity if in auto mode
        if mode == 'auto':
            is_complex, reason = detect_task_complexity(task)
            
            # Check for browser-specific keywords
            if any(kw in task.lower() for kw in ['browse', 'web', 'website', 'url', 'online']):
                mode = 'browser'
                console.print("[dim]Detected browser task[/dim]")
            elif is_complex:
                mode = 'multi'
                console.print(f"[dim]Detected complex task ({reason})[/dim]")
            else:
                mode = 'single'
        
        # Execute based on mode
        if mode == 'browser' and self.browser_agent:
            await self.run_browser_task(task)
        elif mode == 'multi' and self.orchestrator:
            await self.run_multi_agent(task)
        else:
            await self.run_single_agent(task)
    
    def interactive_mode(self) -> None:
        """Run in interactive mode."""
        console.print(Panel(
            "[bold cyan]ManusUse Interactive Mode[/bold cyan]\n"
            "Type your tasks below. Special commands:\n"
            "  • [yellow]/mode[/yellow] - Switch between auto/single/multi/browser modes\n"
            "  • [yellow]/history[/yellow] - Show command history\n"
            "  • [yellow]/clear[/yellow] - Clear screen\n"
            "  • [yellow]/exit[/yellow] - Exit",
            title="Welcome",
            border_style="cyan"
        ))
        
        mode = 'auto'
        
        while True:
            try:
                # Show current mode
                mode_color = {'auto': 'yellow', 'single': 'green', 'multi': 'cyan', 'browser': 'blue'}[mode]
                prompt_text = f"[{mode_color}][{mode}][/{mode_color}] > "
                
                # Get input
                user_input = Prompt.ask(prompt_text)
                
                if not user_input.strip():
                    continue
                
                # Handle special commands
                if user_input.startswith('/'):
                    command = user_input[1:].lower()
                    
                    if command == 'exit':
                        console.print("[yellow]Goodbye![/yellow]")
                        break
                    elif command == 'clear':
                        console.clear()
                    elif command == 'history':
                        for i, cmd in enumerate(self.history[-10:], 1):
                            console.print(f"{i}. {cmd}")
                    elif command.startswith('mode'):
                        parts = command.split()
                        if len(parts) > 1 and parts[1] in ['auto', 'single', 'multi', 'browser']:
                            mode = parts[1]
                            console.print(f"Mode switched to: {mode}")
                        else:
                            console.print("Available modes: auto, single, multi, browser")
                    else:
                        console.print(f"Unknown command: {user_input}")
                    continue
                
                # Run the task
                asyncio.run(self.run_task(user_input, mode))
                console.print()  # Add spacing
                
            except KeyboardInterrupt:
                console.print("\n[yellow]Use /exit to quit[/yellow]")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")


@click.command()
@click.option('--mode', type=click.Choice(['auto', 'single', 'multi', 'browser']), 
              default='auto', help='Execution mode')
@click.option('--config', type=click.Path(exists=True), help='Path to config file')
@click.option('-p', '--prompt', type=str, help='Run a single task')
@click.option('--headless/--no-headless', default=True, help='Run browser in headless mode')
@click.option('--stream/--no-stream', default=True, help='Enable streaming for browser tasks')
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('--version', is_flag=True, help='Show version')
def main(mode: str, config: Optional[str], prompt: Optional[str], 
         headless: bool, stream: bool, debug: bool, version: bool):
    """ManusUse Enhanced CLI - Advanced AI Agent Framework
    
    Run without arguments for interactive mode, or use -p/--prompt for single commands.
    
    Examples:
        manus-use                                    # Interactive mode
        manus-use -p "analyze this data"            # Single command
        manus-use --mode browser -p "search web"    # Browser mode
        manus-use --mode multi -p "complex task"    # Multi-agent mode
    """
    if version:
        console.print("[bold cyan]ManusUse v1.0.0[/bold cyan]")
        console.print("Advanced AI Agent Framework powered by Strands SDK")
        return
    
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Load configuration
    try:
        cfg = Config.from_file(config) if config else Config.from_file()
    except Exception as e:
        console.print(f"[red]Error loading config: {e}[/red]")
        sys.exit(1)
    
    # Override settings
    cfg.browser_use.headless = headless
    
    # Create CLI instance
    cli = EnhancedCLI(cfg)
    cli.setup_agents(mode)
    
    # Run prompt or interactive mode
    if prompt:
        asyncio.run(cli.run_task(prompt, mode))
    else:
        cli.interactive_mode()


if __name__ == "__main__":
    main()