"""Code execution tool with sandbox support."""

import asyncio
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Optional, Tuple

from strands import tool

from ..config import Config
from ..sandbox import DockerSandbox


class CodeExecutor:
    """Handles code execution with or without sandbox."""
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config.from_file()
        self._sandbox = None
        
    async def _get_sandbox(self) -> Optional[DockerSandbox]:
        """Get or create sandbox instance."""
        if not self.config.sandbox.enabled:
            return None
            
        if self._sandbox is None:
            self._sandbox = DockerSandbox(
                image=self.config.sandbox.docker_image,
                memory_limit=self.config.sandbox.memory_limit,
                cpu_limit=self.config.sandbox.cpu_limit,
            )
            await self._sandbox.start()
            
        return self._sandbox
        
    async def execute_python(
        self, 
        code: str, 
        timeout: Optional[int] = None
    ) -> Tuple[str, str, int]:
        """Execute Python code."""
        timeout = timeout or self.config.sandbox.timeout
        
        sandbox = await self._get_sandbox()
        if sandbox:
            # Execute in sandbox
            return await sandbox.execute_code(code, language="python", timeout=timeout)
        else:
            # Execute locally (less secure)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
                f.write(code)
                f.flush()
                
                try:
                    result = subprocess.run(
                        ["python", f.name],
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                    )
                    return result.stdout, result.stderr, result.returncode
                finally:
                    Path(f.name).unlink()
                    
    async def execute_bash(
        self,
        command: str,
        timeout: Optional[int] = None
    ) -> Tuple[str, str, int]:
        """Execute bash command."""
        timeout = timeout or self.config.sandbox.timeout
        
        sandbox = await self._get_sandbox()
        if sandbox:
            # Execute in sandbox
            return await sandbox.execute_command(command, timeout=timeout)
        else:
            # Execute locally (less secure)
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout, result.stderr, result.returncode
            
    async def cleanup(self):
        """Clean up sandbox resources."""
        if self._sandbox:
            await self._sandbox.stop()
            self._sandbox = None


# Global executor instance
_executor = None


def get_executor(config: Optional[Config] = None) -> CodeExecutor:
    """Get global executor instance."""
    global _executor
    if _executor is None:
        _executor = CodeExecutor(config)
    return _executor


@tool
async def code_execute(
    code: str,
    language: str = "python",
    timeout: Optional[int] = None,
) -> Dict[str, any]:
    """Execute code in a sandboxed environment.
    
    Args:
        code: Code to execute
        language: Programming language (python or bash)
        timeout: Execution timeout in seconds
        
    Returns:
        Dictionary with execution results:
        - stdout: Standard output
        - stderr: Standard error  
        - exit_code: Exit code (0 for success)
        - error: Error message if execution failed
    """
    executor = get_executor()
    
    try:
        if language.lower() == "python":
            stdout, stderr, exit_code = await executor.execute_python(code, timeout)
        elif language.lower() in ["bash", "sh", "shell"]:
            stdout, stderr, exit_code = await executor.execute_bash(code, timeout)
        else:
            return {
                "stdout": "",
                "stderr": f"Unsupported language: {language}",
                "exit_code": 1,
                "error": f"Language '{language}' is not supported. Use 'python' or 'bash'."
            }
            
        return {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "error": stderr if exit_code != 0 else None
        }
    except asyncio.TimeoutError:
        return {
            "stdout": "",
            "stderr": f"Execution timed out after {timeout} seconds",
            "exit_code": -1,
            "error": "Timeout"
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": str(e),
            "exit_code": -1,
            "error": f"Execution failed: {str(e)}"
        }


# Make synchronous version for compatibility
def code_execute_sync(
    code: str,
    language: str = "python", 
    timeout: Optional[int] = None,
) -> Dict[str, any]:
    """Synchronous version of code_execute."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(
            code_execute(code, language, timeout)
        )
    finally:
        loop.close()