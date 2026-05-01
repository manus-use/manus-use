"""Docker-based sandbox for secure code execution."""

import asyncio
import tempfile
import uuid
from pathlib import Path
from typing import Optional, Tuple

import docker
from docker.errors import ContainerError, ImageNotFound

from manus_use.utils.docker_client import (
    docker_retry,
    get_docker_client,
    safe_kill_remove_container,
    wait_for_container_running,
)


class DockerSandbox:
    """Docker container sandbox for code execution."""
    
    def __init__(
        self,
        image: str = "python:3.12-slim",
        memory_limit: str = "512m",
        cpu_limit: float = 1.0,
        network_disabled: bool = False,
    ):
        """Initialize Docker sandbox.
        
        Args:
            image: Docker image to use
            memory_limit: Memory limit (e.g., "512m", "1g")
            cpu_limit: CPU limit (1.0 = 1 CPU core)
            network_disabled: Whether to disable network access
        """
        self.image = image
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.network_disabled = network_disabled
        
        self.client = None
        self.container = None
        self.container_name = f"manus-sandbox-{uuid.uuid4().hex[:8]}"
        
    async def start(self):
        """Start the sandbox container."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._start_sync)
        
    def _start_sync(self):
        """Synchronous container start."""
        self.client = get_docker_client()
        
        # Pull image if not available
        try:
            docker_retry("images.get", lambda: self.client.images.get(self.image))
        except ImageNotFound:
            print(f"Pulling Docker image: {self.image}")
            docker_retry("images.pull", lambda: self.client.images.pull(self.image))
            
        # Create and start container
        self.container = docker_retry(
            "containers.run(sandbox)",
            lambda: self.client.containers.run(
                self.image,
                name=self.container_name,
                detach=True,
                tty=True,
                stdin_open=True,
                mem_limit=self.memory_limit,
                cpu_quota=int(self.cpu_limit * 100000),
                cpu_period=100000,
                network_disabled=self.network_disabled,
                remove=False,  # We'll remove it manually
                # Do not assume `/bin/bash` exists in the image.
                command="sleep infinity",
                labels={
                    "manus_use.component": "docker_sandbox",
                    "manus_use.sandbox_uid": self.container_name,
                },
            ),
        )

        wait_for_container_running(self.container, timeout=20)
        
    async def stop(self):
        """Stop and remove the sandbox container."""
        if self.container:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._stop_sync)
            
    def _stop_sync(self):
        """Synchronous container stop."""
        safe_kill_remove_container(self.container)
        self.container = None

        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass
        self.client = None
        
    async def execute_code(
        self,
        code: str,
        language: str = "python",
        timeout: Optional[int] = 30,
    ) -> Tuple[str, str, int]:
        """Execute code in the sandbox.
        
        Args:
            code: Code to execute
            language: Programming language
            timeout: Execution timeout in seconds
            
        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        if not self.container:
            raise RuntimeError("Sandbox container is not running")
            
        loop = asyncio.get_event_loop()
        
        # Create temporary file with code
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=f".{self._get_file_extension(language)}",
            delete=False
        ) as f:
            f.write(code)
            temp_file = f.name
            
        try:
            # Copy file to container
            container_path = f"/tmp/code.{self._get_file_extension(language)}"
            await loop.run_in_executor(
                None,
                self._copy_to_container,
                temp_file,
                container_path
            )
            
            # Execute code
            command = self._get_execution_command(language, container_path)
            return await self.execute_command(command, timeout)
            
        finally:
            # Clean up temp file
            Path(temp_file).unlink(missing_ok=True)
            
    async def execute_command(
        self,
        command: str,
        timeout: Optional[int] = 30,
    ) -> Tuple[str, str, int]:
        """Execute a command in the sandbox.
        
        Args:
            command: Command to execute
            timeout: Execution timeout in seconds
            
        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        if not self.container:
            raise RuntimeError("Sandbox container is not running")
            
        loop = asyncio.get_event_loop()
        
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    self._execute_sync,
                    command
                ),
                timeout=timeout
            )
            return result
        except asyncio.TimeoutError:
            # Try to stop the execution
            try:
                exec_info = self.container.exec_run("pkill -9 -f " + command.split()[0])
            except:
                pass
            return "", f"Command timed out after {timeout} seconds", -1
            
    def _execute_sync(self, command: str) -> Tuple[str, str, int]:
        """Synchronous command execution."""
        exec_result = docker_retry(
            "container.exec_run(sandbox)",
            lambda: self.container.exec_run(
                command,
                stdout=True,
                stderr=True,
                demux=True,
            ),
        )
        
        stdout = exec_result.output[0] if exec_result.output[0] else b""
        stderr = exec_result.output[1] if exec_result.output[1] else b""
        
        return (
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
            exec_result.exit_code
        )
        
    def _copy_to_container(self, local_path: str, container_path: str):
        """Copy file to container."""
        with open(local_path, "rb") as f:
            data = f.read()
            
        # Use tar format for put_archive
        import tarfile
        import io
        
        tar_stream = io.BytesIO()
        tar = tarfile.TarFile(fileobj=tar_stream, mode="w")
        
        tarinfo = tarfile.TarInfo(name=Path(container_path).name)
        tarinfo.size = len(data)
        tarinfo.mode = 0o755
        
        tar.addfile(tarinfo, io.BytesIO(data))
        tar.close()
        
        self.container.put_archive(
            Path(container_path).parent,
            tar_stream.getvalue()
        )
        
    def _get_file_extension(self, language: str) -> str:
        """Get file extension for language."""
        extensions = {
            "python": "py",
            "javascript": "js",
            "typescript": "ts",
            "bash": "sh",
            "shell": "sh",
            "sh": "sh",
        }
        return extensions.get(language.lower(), "txt")
        
    def _get_execution_command(self, language: str, file_path: str) -> str:
        """Get command to execute file based on language."""
        commands = {
            # Prefer python3, fall back to python.
            "python": (
                f"sh -lc \"command -v python3 >/dev/null 2>&1 && exec python3 {file_path} || exec python {file_path}\""
            ),
            "javascript": f"node {file_path}",
            "bash": f"bash {file_path}",
            "shell": f"sh {file_path}",
            "sh": f"sh {file_path}",
        }
        return commands.get(language.lower(), f"cat {file_path}")
