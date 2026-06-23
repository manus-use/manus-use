"""Command-line interface for ManusUse."""

import argparse
import re
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from . import __version__
from .config import Config
from .multi_agents import Orchestrator


console = Console()


def is_complex_task(user_input: str) -> bool:
    """Determine if a task requires multi-agent orchestration."""
    complex_indicators = [
        r'\band\b.*\band\b',
        r'\bthen\b',
        r'\bafter\b',
        r'\banalyze\b.*\b(create|generate|build)',
        r'\bcompare\b.*\bsummarize',
        r'\bmultiple\b',
        r'\bsteps?\b',
        r'\bworkflow\b',
        r'(first|second|third|finally)',
        r'\b(visuali[sz]e|chart|graph)\b.*\b(analyze|data)',
        r'\bbrowse\b.*\b(extract|analyze)',
        r'\bresearch\b.*\b(implement|create)',
    ]

    if len(user_input.split()) > 30:
        return True

    if len(re.split(r'[.;]', user_input)) > 2:
        return True

    for pattern in complex_indicators:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True

    return False


def display_task_plan(tasks) -> None:
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
            deps,
        )

    console.print(table)


def _make_agent(agent_type: str, config: Config):
    """Instantiate the requested agent type."""
    if agent_type == "browser":
        from .agents import BrowserUseAgent
        return BrowserUseAgent(config=config)
    if agent_type == "data":
        from .agents import DataAnalysisAgent
        return DataAnalysisAgent(config=config)
    if agent_type == "mcp":
        from .agents import MCPAgent
        return MCPAgent(config=config)
    # default: manus
    from .agents import ManusAgent
    return ManusAgent(config=config)


def _run_single_shot(
    task: str,
    *,
    mode: str,
    agent_type: str,
    show_plan: bool,
    output: Optional[Path],
    config: Config,
) -> int:
    """Execute a single task non-interactively and exit.

    Returns an exit code (0 = success, 1 = failure).
    """
    try:
        agent = _make_agent(agent_type, config)
    except Exception as exc:
        console.print(f"[red]✗ Failed to initialise agent: {exc}[/red]")
        return 1

    use_multi_agent = mode == "multi" or (mode == "auto" and is_complex_task(task))

    result_text: str
    if use_multi_agent:
        console.print("[dim]Detected complex task – using multi-agent orchestration[/dim]")
        orchestrator = Orchestrator(config=config)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            _ptask = progress.add_task("Running workflow…", total=None)
            result = orchestrator.run(task)
            progress.update(_ptask, completed=True)

        if not result.success:
            console.print(Panel(
                f"Task failed: {result.error}",
                title="[bold red]Error[/bold red]",
                border_style="red",
            ))
            return 1
        result_text = result.output
    else:
        with console.status("Running…", spinner="dots"):
            response = agent(task)
        result_text = str(response)

    console.print(Panel(result_text, title="[bold green]Result[/bold green]", border_style="green"))

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(result_text, encoding="utf-8")
        console.print(f"[dim]Output saved to {output}[/dim]")

    return 0


def _run_interactive(
    *,
    mode: str,
    agent_type: str,
    show_plan: bool,
    config: Config,
) -> None:
    """Run the interactive REPL loop."""
    console.print("[bold blue]Welcome to ManusUse![/bold blue]")
    console.print("An advanced AI agent framework powered by Strands SDK")
    console.print(f"Mode: [cyan]{mode}[/cyan]  Agent: [cyan]{agent_type}[/cyan]\n")

    console.print("Initialising agents…", style="dim")
    try:
        agent = _make_agent(agent_type, config)
        orchestrator = None
        if mode in ("auto", "multi"):
            orchestrator = Orchestrator(config=config)
        console.print("✓ Agents initialised\n", style="green")
    except Exception as exc:
        console.print(f"[red]✗ Failed to initialise agents: {exc}[/red]")
        sys.exit(1)

    console.print("Type your requests below (type 'exit' to quit):\n")

    while True:
        try:
            user_input = Prompt.ask("\n[bold cyan]You[/bold cyan]")

            if user_input.lower() in ("exit", "quit", "bye"):
                console.print("\n[bold blue]Goodbye![/bold blue]")
                break

            use_multi_agent = mode == "multi" or (
                mode == "auto" and is_complex_task(user_input)
            )

            if use_multi_agent and orchestrator:
                console.print("\n[bold green]Orchestrator[/bold green]: Planning execution…\n")

                if show_plan:
                    planner = orchestrator.agents.get("planner")
                    if planner:
                        tasks = planner.create_plan(user_input)
                        display_task_plan(tasks)
                        console.print()
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                ) as progress:
                    _ptask = progress.add_task("Executing multi-agent workflow…", total=None)
                    result = orchestrator.run(user_input)
                    progress.update(_ptask, completed=True)

                if result.success:
                    console.print(Panel(
                        result.output,
                        title="[bold green]Result[/bold green]",
                        border_style="green",
                    ))
                else:
                    console.print(Panel(
                        f"Task failed: {result.error}",
                        title="[bold red]Error[/bold red]",
                        border_style="red",
                    ))
            else:
                console.print("\n[bold green]Agent[/bold green]: ", end="")
                with console.status("Thinking…", spinner="dots"):
                    response = agent(user_input)
                console.print(response)

        except KeyboardInterrupt:
            console.print("\n\n[bold blue]Goodbye![/bold blue]")
            break
        except Exception as exc:
            console.print(f"\n[red]Error: {exc}[/red]")


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="ManusUse – Advanced AI Agent Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Single-shot (non-interactive)\n"
            "  manus-use \"Create a factorial function in Python\"\n"
            "  manus-use --agent browser \"Find the top 5 trending GitHub repos today\"\n"
            "  manus-use --output result.txt \"Summarise the latest AI news\"\n\n"
            "  # Interactive REPL\n"
            "  manus-use\n"
            "  manus-use --mode multi\n"
        ),
    )

    parser.add_argument(
        "task",
        nargs="?",
        default=None,
        help="Task to execute (omit for interactive mode)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"manus-use {__version__}",
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "single", "multi"],
        default="auto",
        help="Execution mode: auto (detect complexity), single, or multi (default: auto)",
    )
    parser.add_argument(
        "--agent",
        choices=["manus", "browser", "data", "mcp"],
        default="manus",
        dest="agent_type",
        help="Agent type to use for single-agent execution (default: manus)",
    )
    parser.add_argument(
        "--show-plan",
        action="store_true",
        help="Show the multi-agent execution plan before running",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        type=Path,
        default=None,
        help="Save the result to FILE (single-shot mode only)",
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        type=Path,
        default=None,
        help="Path to a config.toml file (overrides default search paths)",
    )

    args = parser.parse_args()

    config = Config.from_file(args.config)

    if args.task is not None:
        # Non-interactive single-shot mode
        exit_code = _run_single_shot(
            args.task,
            mode=args.mode,
            agent_type=args.agent_type,
            show_plan=args.show_plan,
            output=args.output,
            config=config,
        )
        sys.exit(exit_code)
    else:
        if args.output is not None:
            parser.error("--output requires a task argument")
        _run_interactive(
            mode=args.mode,
            agent_type=args.agent_type,
            show_plan=args.show_plan,
            config=config,
        )


if __name__ == "__main__":
    main()
