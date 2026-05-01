"""Docker client utilities for reliable daemon connection.

Handles various Docker daemon configurations including:
- Docker Desktop on macOS
- OrbStack
- Colima
- Standard Linux Docker
- Custom DOCKER_HOST settings
"""

import os
import platform
import random
import socket
import time
from pathlib import Path
from typing import Callable, Optional, Tuple, TypeVar

import docker
from docker.errors import APIError, DockerException, NotFound

T = TypeVar("T")


class DockerConnectionError(Exception):
    """Raised when Docker daemon connection fails."""
    
    def __init__(self, message: str, diagnosis: str, remediation: str):
        self.message = message
        self.diagnosis = diagnosis
        self.remediation = remediation
        super().__init__(f"{message}\n\nDiagnosis: {diagnosis}\n\nRemediation: {remediation}")


def _get_default_docker_hosts() -> list[Tuple[str, str]]:
    """Get list of potential Docker socket paths with their descriptions.
    
    Returns list of (host_url, description) tuples to try in order.
    """
    hosts = []
    
    if platform.system() == "Darwin":
        home = Path.home()
        hosts.extend([
            (f"unix://{home}/.docker/run/docker.sock", "Docker Desktop"),
            (f"unix://{home}/.orbstack/run/docker.sock", "OrbStack"),
            (f"unix://{home}/.colima/docker.sock", "Colima"),
            (f"unix://{home}/Library/Containers/com.docker.docker/Data/docker.raw.sock", 
             "Docker Desktop (legacy)"),
        ])
    
    hosts.extend([
        ("unix:///var/run/docker.sock", "Standard Linux/Unix socket"),
    ])
    
    return hosts


def _check_docker_context() -> Optional[Tuple[str, str]]:
    """Check if Docker CLI context is set and return its endpoint.
    
    Returns (host_url, description) if context is configured, else None.
    """
    try:
        import json
        docker_config = Path.home() / ".docker" / "config.json"
        if docker_config.exists():
            config = json.loads(docker_config.read_text())
            current_context = config.get("currentContext")
            if current_context:
                context_meta_dir = Path.home() / ".docker" / "contexts" / "meta"
                for context_dir in context_meta_dir.glob("*"):
                    meta_file = context_dir / "meta.json"
                    if meta_file.exists():
                        meta = json.loads(meta_file.read_text())
                        if meta.get("Name") == current_context:
                            endpoint = meta.get("Endpoints", {}).get("docker", {}).get("Host")
                            if endpoint:
                                return (endpoint, f"Docker context: {current_context}")
    except Exception:
        pass
    return None


def _is_socket_accessible(host: str) -> bool:
    """Check if a Unix socket path is accessible."""
    if not host.startswith("unix://"):
        return False
    
    socket_path = host[7:]  # Remove "unix://" prefix
    path = Path(socket_path)
    
    if not path.exists():
        return False
    
    if not path.is_socket():
        return False
    
    return True


def get_docker_client(timeout: int = 10) -> docker.DockerClient:
    """Create a Docker client with automatic socket detection.
    
    Automatically detects and connects to the Docker daemon, handling:
    - DOCKER_HOST environment variable (highest priority)
    - Docker CLI context configuration
    - Platform-specific default socket locations
    
    Args:
        timeout: Connection timeout in seconds
        
    Returns:
        docker.DockerClient: Connected Docker client
        
    Raises:
        DockerConnectionError: If Docker daemon is unavailable with detailed diagnosis
    """
    errors = []
    
    if env_host := os.environ.get("DOCKER_HOST"):
        try:
            client = docker.DockerClient(base_url=env_host, timeout=timeout)
            client.ping()
            return client
        except Exception as e:
            errors.append(f"DOCKER_HOST ({env_host}): {e}")
    
    if context_info := _check_docker_context():
        host_url, description = context_info
        try:
            client = docker.DockerClient(base_url=host_url, timeout=timeout)
            client.ping()
            return client
        except Exception as e:
            errors.append(f"Docker context ({description}): {e}")
    
    for host_url, description in _get_default_docker_hosts():
        if not _is_socket_accessible(host_url):
            continue
            
        try:
            client = docker.DockerClient(base_url=host_url, timeout=timeout)
            client.ping()
            return client
        except Exception as e:
            errors.append(f"{description} ({host_url}): {e}")
    
    diagnosis, remediation = _diagnose_docker_issue(errors)
    raise DockerConnectionError(
        message="Failed to connect to Docker daemon",
        diagnosis=diagnosis,
        remediation=remediation
    )


def _diagnose_docker_issue(errors: list[str]) -> Tuple[str, str]:
    """Diagnose Docker connection issues and provide remediation steps.
    
    Args:
        errors: List of connection errors encountered
        
    Returns:
        Tuple of (diagnosis, remediation) messages
    """
    system = platform.system()
    
    no_sockets_found = not any("unix://" in e for e in errors)
    permission_denied = any("Permission denied" in str(e) for e in errors)
    connection_refused = any("Connection refused" in str(e) for e in errors)
    
    if no_sockets_found:
        if system == "Darwin":
            diagnosis = "No Docker daemon socket found. Docker Desktop, OrbStack, or Colima may not be running."
            remediation = """To fix this issue:
1. Start Docker Desktop, OrbStack, or Colima
2. Verify Docker is running with: docker ps
3. If using Docker Desktop, check that it's fully started (whale icon in menu bar)
4. If using Colima, run: colima start

Alternative: Set DOCKER_HOST environment variable:
  export DOCKER_HOST=unix://$HOME/.docker/run/docker.sock"""
        else:
            diagnosis = "Docker daemon socket not found at /var/run/docker.sock"
            remediation = """To fix this issue:
1. Start the Docker daemon: sudo systemctl start docker
2. Verify Docker is running: sudo systemctl status docker
3. Add your user to the docker group: sudo usermod -aG docker $USER
4. Log out and back in for group changes to take effect"""
    
    elif permission_denied:
        diagnosis = "Permission denied when accessing Docker socket"
        remediation = """To fix this issue:
1. Add your user to the docker group: sudo usermod -aG docker $USER
2. Log out and back in for group changes to take effect
3. Verify with: docker ps

Alternative: Use sudo for Docker commands (not recommended)"""
    
    elif connection_refused:
        diagnosis = "Docker daemon is not accepting connections"
        remediation = """To fix this issue:
1. Restart Docker daemon
2. For Docker Desktop: quit and restart the application
3. For Linux: sudo systemctl restart docker
4. Check Docker logs for errors"""
    
    else:
        diagnosis = f"Docker daemon connection failed. Errors encountered:\n" + "\n".join(f"  - {e}" for e in errors)
        remediation = """To diagnose and fix:
1. Verify Docker is installed: docker --version
2. Check if Docker daemon is running: docker ps
3. For Docker Desktop users, ensure it's fully started
4. Try setting DOCKER_HOST explicitly:
   export DOCKER_HOST=unix://$HOME/.docker/run/docker.sock  # Docker Desktop
   export DOCKER_HOST=unix://$HOME/.orbstack/run/docker.sock  # OrbStack
5. Check Docker context: docker context ls"""
    
    return diagnosis, remediation


def check_docker_available() -> Tuple[bool, Optional[str]]:
    """Check if Docker daemon is available without raising an exception.
    
    Returns:
        Tuple of (is_available, error_message)
        If available, error_message is None
    """
    try:
        client = get_docker_client()
        client.close()
        return True, None
    except DockerConnectionError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Unexpected error checking Docker availability: {e}"


# -----------------------------------------------------------------------------
# Resilience helpers (retry/polling/idempotent cleanup)
# -----------------------------------------------------------------------------


def is_transient_docker_error(exc: BaseException) -> bool:
    """Best-effort classification of Docker errors that are usually retryable.

    This is intentionally conservative: only obvious daemon/API/transport failures
    are treated as transient.
    """

    if isinstance(exc, (DockerException, APIError)):
        msg = str(exc).lower()
        # Some API errors are deterministic; treat conflict as non-transient.
        if "conflict" in msg or "already in use" in msg:
            return False
        return True

    # Avoid importing requests/urllib3 directly; classify by type name and message.
    tname = type(exc).__name__.lower()
    msg = str(exc).lower()
    transient_signatures = (
        "connection aborted",
        "connection reset",
        "connection refused",
        "broken pipe",
        "bad response from docker engine",
        "read timed out",
        "timed out",
        "timeout",
        "tls handshake timeout",
        "i/o timeout",
        "temporarily unavailable",
        "unexpected eof",
        "eof",
        "server error",
        "service unavailable",
        "too many requests",
    )
    if any(s in msg for s in transient_signatures):
        return True
    if tname in {"readtimeout", "connecttimeout", "connectionerror", "protocolerror"}:
        return True
    return False


def docker_retry(
    op_name: str,
    fn: Callable[[], T],
    *,
    attempts: int = 4,
    base_delay: float = 0.25,
    max_delay: float = 2.5,
    jitter: float = 0.20,
    deadline: float | None = None,
) -> T:
    """Retry an operation on transient Docker/transport errors.

    - Conservative retries by default.
    - Deadline-aware: if `deadline` is provided, stops retrying when exceeded.
    """

    last_exc: BaseException | None = None
    for attempt in range(1, max(attempts, 1) + 1):
        if deadline is not None and time.time() >= deadline:
            break
        try:
            return fn()
        except BaseException as e:
            last_exc = e
            if attempt >= attempts or not is_transient_docker_error(e):
                raise

            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            delay = max(0.0, delay + random.uniform(-jitter, jitter) * delay)
            if deadline is not None:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                delay = min(delay, max(0.0, remaining))
            print(f"[docker_retry] {op_name} transient failure (attempt {attempt}/{attempts}): {e}")
            time.sleep(delay)
    assert last_exc is not None
    raise last_exc


def wait_for_container_running(container, *, timeout: int = 20) -> None:
    """Wait until Docker reports the container is running, or raise."""

    deadline = time.time() + timeout

    def _reload() -> None:
        container.reload()

    while time.time() < deadline:
        docker_retry("container.reload", _reload, deadline=deadline)
        state = (container.attrs or {}).get("State", {})
        if state.get("Running") is True:
            return
        # If container exited, stop waiting early.
        if state.get("Status") in {"exited", "dead"}:
            raise RuntimeError(
                f"Container is not running (status={state.get('Status')}, exit_code={state.get('ExitCode')})"
            )
        time.sleep(0.25)
    raise TimeoutError("Timed out waiting for container to be running")


def wait_for_container_healthy(container, *, timeout: int = 30) -> None:
    """Wait until a healthcheck reports healthy.

    If no healthcheck is configured, returns immediately.
    """

    deadline = time.time() + timeout

    def _reload() -> None:
        container.reload()

    docker_retry("container.reload", _reload, deadline=deadline)
    health = ((container.attrs or {}).get("State", {}) or {}).get("Health")
    if not isinstance(health, dict):
        return

    while time.time() < deadline:
        docker_retry("container.reload", _reload, deadline=deadline)
        health = ((container.attrs or {}).get("State", {}) or {}).get("Health") or {}
        status = health.get("Status")
        if status == "healthy":
            return
        if status == "unhealthy":
            raise RuntimeError("Container became unhealthy")
        time.sleep(0.5)
    raise TimeoutError("Timed out waiting for container to become healthy")


def safe_kill_remove_container(container, *, force: bool = True) -> None:
    """Best-effort kill+remove. Idempotent against NotFound."""

    if container is None:
        return
    try:
        docker_retry("container.kill", lambda: container.kill())
    except NotFound:
        return
    except Exception:
        pass
    try:
        docker_retry("container.remove", lambda: container.remove(force=force))
    except NotFound:
        return
    except Exception:
        pass


def safe_remove_network(network) -> None:
    """Best-effort remove network. Idempotent against NotFound."""

    if network is None:
        return
    try:
        docker_retry("network.remove", lambda: network.remove())
    except NotFound:
        return
    except Exception:
        pass


def safe_remove_image(client: docker.DockerClient | None, image_id: str | None) -> None:
    """Best-effort image removal. Idempotent against NotFound."""

    if client is None or not image_id:
        return
    try:
        docker_retry("image.remove", lambda: client.images.remove(image_id, force=True))
    except NotFound:
        return
    except Exception:
        pass
