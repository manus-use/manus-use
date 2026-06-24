"""Command-line interface for ManusUse."""

import argparse
import os
import re
import shutil
import sys
from pathlib import Path

import toml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from . import __version__
from .config import Config
from .multi_agents import Orchestrator

console = Console()


# ---------------------------------------------------------------------------
# Complexity heuristic
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Execution plan display
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Agent factory
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Single-shot and interactive runners
# ---------------------------------------------------------------------------

def _run_single_shot(
    task: str,
    *,
    mode: str,
    agent_type: str,
    show_plan: bool,
    output: Path | None,
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


# ---------------------------------------------------------------------------
# manus-use init
# ---------------------------------------------------------------------------

# Provider metadata: (display_name, default_model, env_var_for_api_key, needs_api_key)
_PROVIDERS = {
    "openai": ("OpenAI", "gpt-4o", "OPENAI_API_KEY", True),
    "anthropic": ("Anthropic", "claude-3-5-sonnet-20241022", "ANTHROPIC_API_KEY", True),
    "bedrock": ("AWS Bedrock", "us.anthropic.claude-3-5-sonnet-20241022-v2:0", None, False),
    "ollama": ("Ollama (local)", "llama3.2", None, False),
}

_DEFAULT_CONFIG_PATH = Path.home() / ".manus-use" / "config.toml"


def _cmd_init(args: argparse.Namespace) -> int:  # noqa: C901
    """Guided interactive config generator."""
    console.print(Panel(
        "[bold]Welcome to [cyan]manus-use init[/cyan]![/bold]\n"
        "This wizard will create a [yellow]config.toml[/yellow] for you.",
        border_style="blue",
    ))

    # Destination path
    dest: Path = args.output or _DEFAULT_CONFIG_PATH
    if dest.exists() and not args.force:
        overwrite = Confirm.ask(
            f"[yellow]{dest}[/yellow] already exists. Overwrite?", default=False
        )
        if not overwrite:
            console.print("[dim]Aborted – existing config left unchanged.[/dim]")
            return 0

    # Provider selection
    console.print("\n[bold]Choose a provider:[/bold]")
    provider_keys = list(_PROVIDERS.keys())
    for i, key in enumerate(provider_keys, 1):
        display, default_model, env_var, needs_key = _PROVIDERS[key]
        env_hint = f" (env: [dim]{env_var}[/dim])" if env_var else ""
        console.print(f"  [cyan]{i}[/cyan]. {display}{env_hint}")

    while True:
        choice = Prompt.ask(
            "Provider",
            default="1",
            choices=[str(i) for i in range(1, len(provider_keys) + 1)],
            show_choices=False,
        )
        provider = provider_keys[int(choice) - 1]
        break

    display_name, default_model, env_var, needs_key = _PROVIDERS[provider]

    # Model
    model = Prompt.ask(
        f"\n[bold]Model ID[/bold] for {display_name}",
        default=default_model,
    )

    # API key / region
    api_key: str | None = None
    aws_region: str | None = None
    base_url: str | None = None

    if needs_key:
        env_val = os.environ.get(env_var, "") if env_var else ""
        if env_val:
            console.print(
                f"[green]✓[/green] Found [dim]{env_var}[/dim] in environment "
                "(will be used at runtime – not stored in config)."
            )
            store_key = Confirm.ask("Store API key in config file anyway?", default=False)
        else:
            console.print(f"[yellow]![/yellow] [dim]{env_var}[/dim] not set in environment.")
            store_key = Confirm.ask("Enter API key now and store in config?", default=True)

        if store_key:
            api_key = Prompt.ask(f"[bold]{env_var}[/bold]", password=True)

    elif provider == "bedrock":
        aws_region = Prompt.ask(
            "\n[bold]AWS region[/bold]",
            default=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        )
    elif provider == "ollama":
        base_url = Prompt.ask(
            "\n[bold]Ollama base URL[/bold]",
            default="http://localhost:11434",
        )

    # Sandbox
    sandbox_enabled = Confirm.ask("\n[bold]Enable Docker sandbox?[/bold]", default=True)

    # Assemble config dict
    llm_section: dict = {"provider": provider, "model": model}
    if api_key:
        llm_section["api_key"] = api_key
    if aws_region:
        llm_section["aws_region"] = aws_region
    if base_url:
        llm_section["base_url"] = base_url

    config_data: dict = {
        "llm": llm_section,
        "sandbox": {"enabled": sandbox_enabled},
    }

    # Write
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "w", encoding="utf-8") as fh:
        toml.dump(config_data, fh)

    console.print(Panel(
        f"[green]✓ Config written to[/green] [bold]{dest}[/bold]\n\n"
        f"Run [cyan]manus-use doctor[/cyan] to verify your setup.",
        border_style="green",
        title="[bold green]Done![/bold green]",
    ))
    return 0


# ---------------------------------------------------------------------------
# manus-use doctor
# ---------------------------------------------------------------------------

# (package_import, pip_extra, description)
_PROVIDER_PACKAGES: dict[str, list[tuple[str, str, str]]] = {
    "openai": [("openai", "openai", "OpenAI SDK")],
    "anthropic": [("anthropic", "anthropic", "Anthropic SDK")],
    "bedrock": [("boto3", "boto3", "AWS boto3")],
    "ollama": [("ollama", "ollama", "Ollama client")],
}

_ALWAYS_CHECK: list[tuple[str, str, str]] = [
    ("strands", "strands-agents", "Strands Agents SDK"),
    ("rich", "rich", "Rich (terminal UI)"),
    ("toml", "toml", "TOML parser"),
    ("pydantic", "pydantic", "Pydantic"),
]


def _check_import(package: str) -> bool:
    """Return True if *package* is importable."""
    import importlib
    try:
        importlib.import_module(package)
        return True
    except ImportError:
        return False


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Check packages, config, and environment variables."""
    console.print(Panel(
        "[bold cyan]manus-use doctor[/bold cyan] – environment diagnostics",
        border_style="blue",
    ))

    issues: list[str] = []

    # ------------------------------------------------------------------
    # 1. Core packages
    # ------------------------------------------------------------------
    console.print("\n[bold]Core packages[/bold]")
    for pkg, pip_name, desc in _ALWAYS_CHECK:
        ok = _check_import(pkg)
        status = "[green]✓[/green]" if ok else "[red]✗[/red]"
        note = "" if ok else f"  → [dim]pip install {pip_name}[/dim]"
        console.print(f"  {status} {desc} ([dim]{pkg}[/dim]){note}")
        if not ok:
            issues.append(f"Missing package: {pip_name}")

    # ------------------------------------------------------------------
    # 2. Config file
    # ------------------------------------------------------------------
    console.print("\n[bold]Configuration[/bold]")
    config_path: Path | None = args.config

    if config_path is None:
        search_paths = [
            Path("config.toml"),
            Path("config/config.toml"),
            _DEFAULT_CONFIG_PATH,
        ]
        for p in search_paths:
            if p.exists():
                config_path = p
                break

    if config_path and config_path.exists():
        console.print(f"  [green]✓[/green] Config found: [bold]{config_path}[/bold]")
        try:
            config = Config.from_file(config_path)
        except Exception as exc:
            console.print(f"  [red]✗[/red] Failed to parse config: {exc}")
            issues.append(f"Config parse error: {exc}")
            config = Config()
    else:
        console.print(
            "  [yellow]![/yellow] No config file found "
            "(run [cyan]manus-use init[/cyan] to create one)"
        )
        config = Config()

    # ------------------------------------------------------------------
    # 3. Provider packages + env vars
    # ------------------------------------------------------------------
    provider = (config.llm.provider or "openai").lower()
    console.print(f"\n[bold]Provider[/bold]: [cyan]{provider}[/cyan]  model: [cyan]{config.llm.model}[/cyan]")

    pkg_checks = _PROVIDER_PACKAGES.get(provider, [])
    for pkg, pip_name, desc in pkg_checks:
        ok = _check_import(pkg)
        status = "[green]✓[/green]" if ok else "[red]✗[/red]"
        note = "" if ok else f"  → [dim]pip install {pip_name}[/dim]"
        console.print(f"  {status} {desc} ([dim]{pkg}[/dim]){note}")
        if not ok:
            issues.append(f"Missing provider package: {pip_name}")

    # Env var checks
    provider_envs: dict[str, list[tuple[str, bool]]] = {
        "openai": [("OPENAI_API_KEY", True)],
        "anthropic": [("ANTHROPIC_API_KEY", True)],
        "bedrock": [
            ("AWS_ACCESS_KEY_ID", False),
            ("AWS_SECRET_ACCESS_KEY", False),
            ("AWS_DEFAULT_REGION", False),
        ],
        "ollama": [],
    }
    for env_var, required in provider_envs.get(provider, []):
        val = os.environ.get(env_var)
        in_config = False
        if provider == "openai" and env_var == "OPENAI_API_KEY":
            in_config = bool(config.llm.api_key)
        elif provider == "anthropic" and env_var == "ANTHROPIC_API_KEY":
            in_config = bool(config.llm.api_key)

        if val or in_config:
            src = "config" if (not val and in_config) else "env"
            console.print(f"  [green]✓[/green] {env_var} ([dim]{src}[/dim])")
        elif required:
            console.print(
                f"  [red]✗[/red] {env_var} not set "
                "(required – set it or store in config.toml)"
            )
            issues.append(f"Missing env var: {env_var}")
        else:
            console.print(f"  [yellow]![/yellow] {env_var} not set (optional for Bedrock)")

    # ------------------------------------------------------------------
    # 4. Optional tools
    # ------------------------------------------------------------------
    console.print("\n[bold]Optional tools[/bold]")
    _optional: list[tuple[str, str, str]] = [
        ("docker", "docker", "Docker (sandbox execution)"),
        ("playwright", "playwright", "Playwright (browser agent)"),
        ("pandas", "pandas", "Pandas (data analysis agent)"),
    ]
    for pkg, pip_name, desc in _optional:
        ok = _check_import(pkg)
        status = "[green]✓[/green]" if ok else "[dim]-[/dim]"
        note = "" if ok else f"  [dim](optional – pip install {pip_name})[/dim]"
        console.print(f"  {status} {desc}{note}")

    # Docker daemon reachable?
    if shutil.which("docker"):
        import subprocess
        result = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=5
        )
        if result.returncode == 0:
            console.print("  [green]✓[/green] Docker daemon reachable")
        else:
            console.print("  [yellow]![/yellow] Docker installed but daemon not running")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    console.print()
    if not issues:
        console.print(Panel(
            "[bold green]All checks passed![/bold green] "
            "Your environment looks ready.",
            border_style="green",
        ))
        return 0
    else:
        issue_list = "\n".join(f"  • {i}" for i in issues)
        console.print(Panel(
            f"[bold red]{len(issues)} issue(s) found:[/bold red]\n{issue_list}",
            border_style="red",
        ))
        return 1


# ---------------------------------------------------------------------------
# main() entry point
# ---------------------------------------------------------------------------

_SUBCOMMANDS = {"init", "doctor"}


def _build_run_parser() -> argparse.ArgumentParser:
    """Build the top-level run/interactive parser."""
    parser = argparse.ArgumentParser(
        prog="manus-use",
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
            "  manus-use --mode multi\n\n"
            "  # Setup helpers\n"
            "  manus-use init           # create ~/.manus-use/config.toml interactively\n"
            "  manus-use doctor         # check packages, config, and API keys\n"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"manus-use {__version__}",
    )
    parser.add_argument(
        "task",
        nargs="?",
        default=None,
        help="Task to execute (omit for interactive mode)",
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
    return parser


def _build_init_parser() -> argparse.ArgumentParser:
    """Build the `init` subcommand parser."""
    parser = argparse.ArgumentParser(
        prog="manus-use init",
        description="Guided wizard to create a manus-use configuration file.",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        type=Path,
        default=None,
        help=f"Where to write config (default: {_DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing config without prompting",
    )
    return parser


def _build_doctor_parser() -> argparse.ArgumentParser:
    """Build the `doctor` subcommand parser."""
    parser = argparse.ArgumentParser(
        prog="manus-use doctor",
        description="Diagnose your manus-use installation: packages, config file, API keys.",
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        type=Path,
        default=None,
        help="Path to a config.toml file to validate (overrides default search paths)",
    )
    return parser


def main() -> None:
    """Main CLI entry point."""
    argv = sys.argv[1:]

    # Check whether the first non-flag token is a known subcommand.
    first_positional = next((a for a in argv if not a.startswith("-")), None)

    if first_positional == "init":
        idx = argv.index("init")
        args = _build_init_parser().parse_args(argv[idx + 1 :])
        sys.exit(_cmd_init(args))

    if first_positional == "doctor":
        idx = argv.index("doctor")
        args = _build_doctor_parser().parse_args(argv[idx + 1 :])
        sys.exit(_cmd_doctor(args))

    # Default: run / interactive
    run_parser = _build_run_parser()
    args = run_parser.parse_args(argv)

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
            run_parser.error("--output requires a task argument")
        _run_interactive(
            mode=args.mode,
            agent_type=args.agent_type,
            show_plan=args.show_plan,
            config=config,
        )


if __name__ == "__main__":
    main()
