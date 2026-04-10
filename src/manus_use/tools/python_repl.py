"""
Fixed python_repl wrapper that addresses PTY cleanup and status handling bugs.

This module wraps strands_tools.python_repl with fixes for:
1. Proper exit status checking using WIFEXITED/WEXITSTATUS instead of raw status comparison
2. Safe PTY cleanup that avoids sending signals to already-reaped processes
"""

import os
import signal
import sys
import time
import traceback
from typing import Any, Callable, List, Optional

from strands.types.tools import ToolResult, ToolUse

try:
    from strands_tools.python_repl import (
        TOOL_SPEC,
        OutputCapture,
        ReplState,
        clean_ansi,
        console_util,
        get_user_input,
        repl_state,
    )
    from strands_tools.utils import console_util
    from strands_tools.utils.user_input import get_user_input
except ImportError:
    from strands_tools import python_repl as _original
    TOOL_SPEC = _original.TOOL_SPEC
    OutputCapture = _original.OutputCapture
    ReplState = _original.ReplState
    clean_ansi = _original.clean_ansi
    repl_state = _original.repl_state
    console_util = _original
    get_user_input = _original.get_user_input


class FixedPtyManager:
    """PTY manager with proper process lifecycle handling."""

    def __init__(self, callback: Optional[Callable] = None):
        self.supervisor_fd = -1
        self.worker_fd = -1
        self.pid = -1
        self.output_buffer: List[str] = []
        self.input_buffer: List[str] = []
        self.stop_event = False
        self.callback = callback
        self._child_exited = False

    def start(self, code: str) -> None:
        import fcntl
        import pty
        import struct
        import termios
        import threading
        
        self.supervisor_fd, self.worker_fd = pty.openpty()
        term_size = struct.pack("HHHH", 24, 80, 0, 0)
        fcntl.ioctl(self.worker_fd, termios.TIOCSWINSZ, term_size)

        self.pid = os.fork()

        if self.pid == 0:
            try:
                os.close(self.supervisor_fd)
                os.dup2(self.worker_fd, 0)
                os.dup2(self.worker_fd, 1)
                os.dup2(self.worker_fd, 2)
                os.close(self.worker_fd)
                
                namespace = repl_state.get_namespace()
                exec(code, namespace)
                os._exit(0)
            except Exception:
                traceback.print_exc(file=sys.stderr)
                os._exit(1)
        else:
            os.close(self.worker_fd)
            
            reader = threading.Thread(target=self._read_output)
            reader.daemon = True
            reader.start()

            input_handler = threading.Thread(target=self._handle_input)
            input_handler.daemon = True
            input_handler.start()

    def _read_output(self) -> None:
        import select
        import sys
        
        buffer = ""
        incomplete_bytes = b""

        while not self.stop_event:
            try:
                if self.supervisor_fd < 0:
                    break

                try:
                    r, _, _ = select.select([self.supervisor_fd], [], [], 0.1)
                except (OSError, ValueError):
                    break

                if self.supervisor_fd in r:
                    try:
                        raw_data = os.read(self.supervisor_fd, 1024)
                    except (OSError, ValueError):
                        break

                    if not raw_data:
                        break

                    full_data = incomplete_bytes + raw_data

                    try:
                        data = full_data.decode("utf-8")
                        incomplete_bytes = b""
                    except UnicodeDecodeError as e:
                        if e.start > 0:
                            data = full_data[:e.start].decode("utf-8")
                            incomplete_bytes = full_data[e.start:]
                        else:
                            incomplete_bytes = full_data
                            continue

                    if data:
                        buffer += data

                        while "\n" in buffer:
                            line, buffer = buffer.split("\n", 1)
                            cleaned = clean_ansi(line + "\n")
                            self.output_buffer.append(cleaned)

                            if self.callback:
                                try:
                                    self.callback(cleaned)
                                except Exception:
                                    pass

                        if buffer:
                            cleaned = clean_ansi(buffer)
                            if self.callback:
                                try:
                                    self.callback(cleaned)
                                except Exception:
                                    pass

            except (OSError, IOError) as e:
                if hasattr(e, "errno") and e.errno == 9:
                    break
                continue

            except Exception:
                break

        if buffer:
            try:
                cleaned = clean_ansi(buffer)
                self.output_buffer.append(cleaned)
                if self.callback:
                    self.callback(cleaned)
            except Exception:
                pass

    def _handle_input(self) -> None:
        import select
        import sys
        
        while not self.stop_event:
            try:
                r, _, _ = select.select([sys.stdin], [], [], 0.1)
                if sys.stdin in r:
                    input_data = ""
                    while True:
                        char = sys.stdin.read(1)
                        if not char or char == "\n":
                            input_data += "\n"
                            break
                        input_data += char

                    if input_data:
                        if input_data not in self.input_buffer:
                            self.input_buffer.append(input_data)
                            if self.supervisor_fd >= 0:
                                try:
                                    os.write(self.supervisor_fd, input_data.encode())
                                except (OSError, ValueError):
                                    break

            except (OSError, IOError):
                break

    def get_output(self) -> str:
        raw = "".join(self.output_buffer)
        clean = clean_ansi(raw)

        max_len = int(os.environ.get("PYTHON_REPL_BINARY_MAX_LEN", "100"))
        if "\\x" in clean and len(clean) > max_len:
            return f"{clean[:max_len]}... [binary content truncated]"
        return clean

    def stop(self) -> None:
        self.stop_event = True

        if self.pid > 0 and not self._child_exited:
            try:
                pid, _ = os.waitpid(self.pid, os.WNOHANG)
                if pid == 0:
                    os.kill(self.pid, signal.SIGTERM)
                    time.sleep(0.1)
                    try:
                        pid, _ = os.waitpid(self.pid, os.WNOHANG)
                        if pid == 0:
                            os.kill(self.pid, signal.SIGKILL)
                            os.waitpid(self.pid, 0)
                    except OSError:
                        pass
            except (OSError, ProcessLookupError):
                pass
            finally:
                self.pid = -1

        if self.supervisor_fd >= 0:
            try:
                os.close(self.supervisor_fd)
            except OSError:
                pass
            finally:
                self.supervisor_fd = -1


def python_repl(tool: ToolUse, **kwargs: Any) -> ToolResult:
    """Execute Python code with proper PTY cleanup and status handling."""
    import sys
    from datetime import datetime
    from io import StringIO
    
    console = console_util.create()

    tool_use_id = tool["toolUseId"]
    tool_input = tool["input"]

    code = tool_input["code"]
    interactive = os.environ.get("PYTHON_REPL_INTERACTIVE", str(tool_input.get("interactive", True))).lower() == "true"
    reset_state = os.environ.get("PYTHON_REPL_RESET_STATE", str(tool_input.get("reset_state", False))).lower() == "true"

    strands_dev = os.environ.get("BYPASS_TOOL_CONSENT", "").lower() == "true"
    non_interactive_mode = kwargs.get("non_interactive_mode", False)

    try:
        if reset_state:
            console.print("[yellow]Resetting REPL state...[/]")
            repl_state.clear_state()
            console.print("[green]REPL state reset complete[/]")

        from rich.panel import Panel
        from rich.syntax import Syntax
        
        console.print(
            Panel(
                Syntax(code, "python", theme="monokai"),
                title="[bold blue]Executing Python Code[/]",
            )
        )

        if not strands_dev and not non_interactive_mode:
            from rich.table import Table
            from rich import box
            
            details_table = Table(show_header=False, box=box.SIMPLE)
            details_table.add_column("Property", style="cyan", justify="right")
            details_table.add_column("Value", style="green")

            details_table.add_row("Code Length", f"{len(code)} characters")
            details_table.add_row("Line Count", f"{len(code.splitlines())} lines")
            details_table.add_row("Mode", "Interactive" if interactive else "Standard")
            details_table.add_row("Reset State", "Yes" if reset_state else "No")

            console.print(
                Panel(
                    details_table,
                    title="[bold blue]🐍 Python Code Execution Preview",
                    border_style="blue",
                    box=box.ROUNDED,
                )
            )
            
            user_input = get_user_input(
                "<yellow><bold>Do you want to proceed with Python code execution?</bold> [y/*]</yellow>"
            )
            if user_input.lower().strip() != "y":
                cancellation_reason = (
                    user_input
                    if user_input.strip() != "n"
                    else get_user_input("Please provide a reason for cancellation:")
                )
                error_message = f"Python code execution cancelled by the user. Reason: {cancellation_reason}"
                error_panel = Panel(
                    f"[bold blue]{error_message}[/bold blue]",
                    title="[bold blue]❌ Cancelled",
                    border_style="blue",
                    box=box.ROUNDED,
                )
                console.print(error_panel)
                return {
                    "toolUseId": tool_use_id,
                    "status": "error",
                    "content": [{"text": error_message}],
                }

        start_time = datetime.now()
        output = None

        try:
            if interactive:
                console.print("[green]Running in interactive mode...[/]")
                pty_mgr = FixedPtyManager()
                pty_mgr.start(code)

                exit_code = None
                while True:
                    try:
                        pid, status = os.waitpid(pty_mgr.pid, os.WNOHANG)
                        if pid != 0:
                            if os.WIFEXITED(status):
                                exit_code = os.WEXITSTATUS(status)
                            elif os.WIFSIGNALED(status):
                                exit_code = 128 + os.WTERMSIG(status)
                            else:
                                exit_code = status
                            pty_mgr._child_exited = True
                            break
                    except OSError:
                        break

                output = pty_mgr.get_output()
                pty_mgr.stop()

                if exit_code == 0:
                    repl_state.save_state(code)
            else:
                console.print("[blue]Running in standard mode...[/]")
                captured = OutputCapture()
                with captured as output_capture:
                    repl_state.execute(code)
                    output = output_capture.get_output()
                    if output:
                        console.print("[cyan]Output:[/]")
                        console.print(output)

            duration = (datetime.now() - start_time).total_seconds()
            user_objects = repl_state.get_user_objects()

            status = f"✓ Code executed successfully ({duration:.2f}s)"
            if user_objects:
                status += f"\nUser objects in namespace: {len(user_objects)} items"
                for name, value in user_objects.items():
                    status += f"\n - {name} = {value}"
            console.print(f"[bold green]{status}[/]")

            return {
                "toolUseId": tool_use_id,
                "status": "success",
                "content": [{"text": output if output else "Code executed successfully"}],
            }

        except RecursionError:
            console.print("[yellow]Recursion error detected - resetting state...[/]")
            repl_state.clear_state()
            raise

    except Exception as e:
        from pathlib import Path
        
        error_tb = traceback.format_exc()
        error_time = datetime.now()

        from rich.panel import Panel
        from rich.syntax import Syntax
        
        console.print(
            Panel(
                Syntax(error_tb, "python", theme="monokai"),
                title="[bold red]Python Error[/]",
                border_style="red",
            )
        )

        errors_dir = os.path.join(Path.cwd(), "errors")
        os.makedirs(errors_dir, exist_ok=True)
        error_file = os.path.join(errors_dir, "errors.txt")

        error_msg = f"\n[{error_time.isoformat()}] Python REPL Error:\nCode:\n{code}\nError:\n{error_tb}\n"

        with open(error_file, "a") as f:
            f.write(error_msg)

        suggestion = ""
        if isinstance(e, RecursionError):
            suggestion = "\nTo fix this, try running with reset_state=True"

        return {
            "toolUseId": tool_use_id,
            "status": "error",
            "content": [{"text": f"{error_msg}{suggestion}"}],
        }


__all__ = ["python_repl", "TOOL_SPEC"]
