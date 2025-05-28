"""Enhanced Command-line interface for ManusUse with Textual TUI."""

import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import click
from rich.console import Console
from rich.panel import Panel

try:
    from textual import events
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container, HorizontalGroup, VerticalScroll
    from textual.widgets import Footer, Header, Input, Label, Link, RichLog, Static
except ImportError:
    print('⚠️ CLI addon is not installed. Please install it with: `pip install textual rich` and try again.')
    sys.exit(1)

from .agents import ManusAgent, BrowserUseAgent, DataAnalysisAgent, MCPAgent
from .config import Config
from .multi_agents import Orchestrator

# Paths
USER_CONFIG_DIR = Path.home() / '.config' / 'manus-use'
USER_CONFIG_FILE = USER_CONFIG_DIR / 'config.json'
COMMAND_HISTORY_FILE = USER_CONFIG_DIR / 'history.json'

# Default settings
MAX_HISTORY_LENGTH = 100

# Ensure directories exist
USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)

# Logo
MANUS_LOGO = """
[bold cyan]╔═╗╔═╗╔═╗╦ ╦╔═╗  ╦ ╦╔═╗╔═╗[/bold cyan]
[bold cyan]║║║╠═╣║ ║║ ║╚═╗  ║ ║╚═╗║╣ [/bold cyan]
[bold cyan]╩ ╩╩ ╩╝╚╝╚═╝╚═╝  ╚═╝╚═╝╚═╝[/bold cyan]
[dim]Advanced AI Agent Framework powered by Strands SDK[/dim]
"""

# Textual border styles
TEXTUAL_BORDER_STYLES = {
    'logo': 'blue',
    'info': 'blue',
    'input': 'orange3',
    'working': 'yellow',
    'completion': 'green',
    'error': 'red'
}


def load_command_history() -> List[str]:
    """Load command history from file."""
    if not COMMAND_HISTORY_FILE.exists():
        return []
    try:
        with open(COMMAND_HISTORY_FILE) as f:
            return json.load(f)
    except:
        return []


def save_command_history(history: List[str]) -> None:
    """Save command history to file."""
    # Limit history length
    if len(history) > MAX_HISTORY_LENGTH:
        history = history[-MAX_HISTORY_LENGTH:]
    
    with open(COMMAND_HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)


def is_complex_task(user_input: str) -> bool:
    """Determine if a task requires multi-agent orchestration."""
    import re
    
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
    
    # Check length
    if len(user_input.split()) > 30:
        return True
    
    # Check for multiple sentences
    if len(re.split(r'[.;]', user_input)) > 2:
        return True
    
    # Check for complex indicators
    for pattern in complex_indicators:
        if re.search(pattern, user_input, re.IGNORECASE):
            return True
    
    return False


class ManusUseApp(App):
    """ManusUse TUI application."""

    CSS = """
    #main-container {
        height: 100%;
        layout: vertical;
    }
    
    #logo-panel {
        width: 100%;
        height: auto;
        content-align: center middle;
        text-align: center;
        border: solid $primary;
        margin: 0 0 1 0;
        min-height: 7;
    }
    
    #info-panels {
        display: none;
        layout: horizontal;
        height: auto;
        min-height: 10;
        margin: 0 0 1 0;
    }
    
    #agent-panel, #task-panel {
        width: 1fr;
        height: 100%;
        border: solid $primary-darken-2;
        padding: 1;
        overflow: auto;
    }
    
    #agent-panel {
        margin-right: 1;
    }
    
    #results-container {
        height: 1fr;
        overflow: auto;
        border: none;
        margin: 0 0 1 0;
    }
    
    #results-log {
        height: auto;
        overflow-y: scroll;
        background: $surface;
        color: $text;
        width: 100%;
    }
    
    #task-input-container {
        border: solid $accent;
        padding: 1;
        height: auto;
        dock: bottom;
    }
    
    #task-label {
        color: $accent;
        padding-bottom: 1;
    }
    
    #task-input {
        width: 100%;
    }
    
    .working-indicator {
        color: $warning;
    }
    """

    BINDINGS = [
        Binding('ctrl+c', 'quit', 'Quit', priority=True, show=True),
        Binding('ctrl+q', 'quit', 'Quit', priority=True),
        Binding('ctrl+d', 'quit', 'Quit', priority=True),
        Binding('ctrl+l', 'clear', 'Clear logs', show=True),
        Binding('tab', 'toggle_mode', 'Toggle single/multi agent', show=True),
    ]

    def __init__(self, config: Config, mode: str = 'auto', *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = config
        self.mode = mode  # 'auto', 'single', 'multi'
        self.agent: Optional[ManusAgent] = None
        self.orchestrator: Optional[Orchestrator] = None
        self.command_history = load_command_history()
        self.history_index = len(self.command_history)
        self.current_task: Optional[str] = None
        self.running = False
        
        # Initialize agents
        self._init_agents()
    
    def _init_agents(self) -> None:
        """Initialize agents based on configuration."""
        try:
            # Always create single agent
            self.agent = ManusAgent(config=self.config)
            
            # Create orchestrator for multi-agent mode
            if self.mode in ['auto', 'multi']:
                self.orchestrator = Orchestrator(config=self.config)
        except Exception as e:
            logging.error(f"Failed to initialize agents: {e}")
            self.exit(f"Failed to initialize agents: {e}")
    
    def on_mount(self) -> None:
        """Set up components when app is mounted."""
        # Set up logging to RichLog
        self._setup_richlog_logging()
        
        # Focus the input field
        self.query_one('#task-input').focus()
        
        # Start info panel updates
        self.update_info_panels()
    
    def _setup_richlog_logging(self) -> None:
        """Set up logging to redirect to RichLog widget."""
        rich_log = self.query_one('#results-log')
        
        class RichLogHandler(logging.Handler):
            def __init__(self, rich_log: RichLog):
                super().__init__()
                self.rich_log = rich_log
            
            def emit(self, record):
                msg = self.format(record)
                self.rich_log.write(msg)
        
        # Configure root logger
        handler = RichLogHandler(rich_log)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', '%H:%M:%S'))
        
        root = logging.getLogger()
        root.handlers = []
        root.addHandler(handler)
        root.setLevel(logging.INFO)
    
    def update_info_panels(self) -> None:
        """Update information panels with current state."""
        if self.running:
            self.update_agent_panel()
            self.update_task_panel()
        
        # Schedule next update
        self.set_timer(1.0, self.update_info_panels)
    
    def update_agent_panel(self) -> None:
        """Update agent information panel."""
        agent_info = self.query_one('#agent-info')
        agent_info.clear()
        
        # Show current mode
        mode_color = {'auto': 'yellow', 'single': 'green', 'multi': 'cyan'}[self.mode]
        agent_info.write(f'[bold]Mode:[/bold] [{mode_color}]{self.mode.upper()}[/{mode_color}]')
        
        # Show agent status
        if self.running:
            if self.orchestrator and self.mode in ['auto', 'multi'] and is_complex_task(self.current_task or ''):
                agent_info.write('[bold]Agents:[/bold] [cyan]Multi-agent orchestration[/cyan]')
                # Show active agents if available
                if hasattr(self.orchestrator, 'agents'):
                    active_agents = list(self.orchestrator.agents.keys())
                    agent_info.write(f'[dim]Active: {", ".join(active_agents)}[/dim]')
            else:
                agent_info.write('[bold]Agent:[/bold] [green]ManusAgent (single)[/green]')
                # Show tools if available
                if self.agent and hasattr(self.agent, 'tools'):
                    tool_count = len(self.agent.tools)
                    agent_info.write(f'[dim]Tools: {tool_count} loaded[/dim]')
        else:
            agent_info.write('[dim]No task running[/dim]')
        
        # Show model info
        if self.config.llm:
            model = f"{self.config.llm.provider}/{self.config.llm.model}"
            agent_info.write(f'[bold]Model:[/bold] [blue]{model}[/blue]')
    
    def update_task_panel(self) -> None:
        """Update task information panel."""
        task_info = self.query_one('#task-info')
        task_info.clear()
        
        if self.current_task:
            task_info.write(f'[bold]Current Task:[/bold]')
            task_info.write(self.current_task[:100] + '...' if len(self.current_task) > 100 else self.current_task)
            
            if self.running:
                task_info.write('\n[yellow]Status:[/yellow] [yellow]Running[/yellow] [blink]...[/blink]')
            else:
                task_info.write('\n[green]Status:[/green] [green]Completed[/green]')
    
    def hide_intro_panel(self) -> None:
        """Hide intro panel and show info panels."""
        logo_panel = self.query_one('#logo-panel')
        info_panels = self.query_one('#info-panels')
        
        if logo_panel.display:
            logo_panel.display = False
            info_panels.display = True
    
    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle task input submission."""
        if event.input.id == 'task-input':
            task = event.input.value.strip()
            if not task:
                return
            
            # Add to history
            if task and (not self.command_history or task != self.command_history[-1]):
                self.command_history.append(task)
                save_command_history(self.command_history)
            
            # Reset history index
            self.history_index = len(self.command_history)
            
            # Hide intro panel
            self.hide_intro_panel()
            
            # Clear input
            event.input.value = ''
            
            # Run task
            self.run_task(task)
    
    def run_task(self, task: str) -> None:
        """Run task in background worker."""
        self.current_task = task
        self.running = True
        
        # Clear log
        self.query_one('#results-log').clear()
        
        # Determine if we should use multi-agent
        use_multi = False
        if self.mode == 'multi':
            use_multi = True
        elif self.mode == 'auto' and is_complex_task(task):
            use_multi = True
            logging.info("Detected complex task - using multi-agent orchestration")
        
        # Create async task
        async def run_async():
            try:
                if use_multi and self.orchestrator:
                    # Multi-agent execution
                    logging.info("Starting multi-agent workflow...")
                    result = await self.orchestrator.run_async(task)
                    
                    if result.success:
                        logging.info(f"✅ Success: {result.output}")
                    else:
                        logging.error(f"❌ Error: {result.error}")
                else:
                    # Single agent execution
                    logging.info("Starting single agent...")
                    response = await asyncio.create_task(asyncio.to_thread(self.agent, task))
                    logging.info(f"✅ {response}")
                    
            except Exception as e:
                logging.error(f"❌ Error: {e}")
            finally:
                self.running = False
                self.query_one('#task-input').focus()
        
        # Run worker
        self.run_worker(run_async)
    
    async def on_key(self, event: events.Key) -> None:
        """Handle key events."""
        # Handle up/down arrows for history navigation
        if event.key == 'up' and self.query_one('#task-input').has_focus:
            if self.history_index > 0:
                self.history_index -= 1
                self.query_one('#task-input').value = self.command_history[self.history_index]
            event.stop()
        elif event.key == 'down' and self.query_one('#task-input').has_focus:
            if self.history_index < len(self.command_history) - 1:
                self.history_index += 1
                self.query_one('#task-input').value = self.command_history[self.history_index]
            elif self.history_index == len(self.command_history) - 1:
                self.history_index += 1
                self.query_one('#task-input').value = ''
            event.stop()
    
    def action_toggle_mode(self) -> None:
        """Toggle between single and multi agent modes."""
        modes = ['auto', 'single', 'multi']
        current_index = modes.index(self.mode)
        self.mode = modes[(current_index + 1) % len(modes)]
        self.update_agent_panel()
    
    def action_clear(self) -> None:
        """Clear the results log."""
        self.query_one('#results-log').clear()
    
    async def action_quit(self) -> None:
        """Quit the application."""
        self.exit()
    
    def compose(self) -> ComposeResult:
        """Create the UI layout."""
        yield Header()
        
        with Container(id='main-container'):
            # Logo panel
            yield Static(MANUS_LOGO, id='logo-panel', markup=True)
            
            # Info panels (hidden by default)
            with Container(id='info-panels'):
                # Agent panel
                with Container(id='agent-panel'):
                    yield RichLog(id='agent-info', markup=True, highlight=True, wrap=True)
                
                # Task panel
                with Container(id='task-panel'):
                    yield RichLog(id='task-info', markup=True, highlight=True, wrap=True)
            
            # Results container
            with VerticalScroll(id='results-container'):
                yield RichLog(id='results-log', markup=True, highlight=True, wrap=True, auto_scroll=True)
            
            # Input container
            with Container(id='task-input-container'):
                yield Label('🤖 What would you like me to do?', id='task-label')
                yield Input(placeholder='Enter your task...', id='task-input')
        
        yield Footer()


# Console for non-TUI output
console = Console()


async def run_single_prompt(prompt: str, config: Config, mode: str = 'auto') -> None:
    """Run a single prompt without TUI."""
    try:
        # Determine if we should use multi-agent
        use_multi = False
        if mode == 'multi':
            use_multi = True
        elif mode == 'auto' and is_complex_task(prompt):
            use_multi = True
            console.print("[dim]Detected complex task - using multi-agent orchestration[/dim]")
        
        with console.status("Working...", spinner="dots"):
            if use_multi:
                orchestrator = Orchestrator(config=config)
                result = await orchestrator.run_async(prompt)
                
                if result.success:
                    console.print(Panel(result.output, title="[green]Success[/green]", border_style="green"))
                else:
                    console.print(Panel(result.error, title="[red]Error[/red]", border_style="red"))
            else:
                agent = ManusAgent(config=config)
                response = await asyncio.create_task(asyncio.to_thread(agent, prompt))
                console.print(Panel(str(response), title="[green]Response[/green]", border_style="green"))
                
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@click.command()
@click.option('--version', is_flag=True, help='Print version and exit')
@click.option('--mode', type=click.Choice(['auto', 'single', 'multi']), default='auto', 
              help='Execution mode: auto (detect complexity), single (single agent), multi (multi-agent)')
@click.option('--config', type=click.Path(exists=True), help='Path to config file')
@click.option('-p', '--prompt', type=str, help='Run a single task without the TUI')
@click.option('--headless', is_flag=True, help='Run browser in headless mode')
@click.option('--debug', is_flag=True, help='Enable debug logging')
def main(version: bool, mode: str, config: Optional[str], prompt: Optional[str], 
         headless: bool, debug: bool):
    """ManusUse - Advanced AI Agent Framework
    
    Run without arguments to start the interactive TUI, or use -p/--prompt for single commands.
    """
    if version:
        console.print("[bold cyan]ManusUse v1.0.0[/bold cyan]")
        sys.exit(0)
    
    # Configure logging
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    # Load configuration
    if config:
        cfg = Config.from_file(config)
    else:
        cfg = Config.from_file()
    
    # Override headless setting if specified
    if headless:
        cfg.browser_use.headless = True
    
    # Run single prompt or start TUI
    if prompt:
        asyncio.run(run_single_prompt(prompt, cfg, mode))
    else:
        # Start TUI
        app = ManusUseApp(config=cfg, mode=mode)
        app.run()


if __name__ == "__main__":
    main()