"""Tests for tools module."""

import pytest
import asyncio
import sys
import types
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from manus_use.tools import get_tools_by_names
from manus_use.tools.file_operations import (
    file_delete,
    file_list,
    file_move,
    file_read,
    file_write,
)
from manus_use.tools.browser_utils import prepare_evaluate_script
from manus_use.tools.patches.use_browser_patch import apply_comprehensive_patch
from manus_use.tools.patches import use_browser_patch as use_browser_patch_module
from manus_use.agents.browser_use_agent import BrowserUseAgent
from manus_use.sandbox.exploit_sandbox import InterpreterNotFoundError


def test_verify_exploit_returns_structured_infra_error_on_transient_run_failure(monkeypatch):
    """verify_exploit should classify transient docker/runtime failures as infra_error with error metadata."""

    from manus_use.tools import verify_exploit as verify_exploit_module

    class FakeClient:
        def ping(self):
            return True

        def close(self):
            return None

    class FakeSandbox:
        def __init__(self, timeout=300):
            self.timeout = timeout
            self.build_log = ""
            self.target_container = object()

        def build_target(self, dockerfile_content: str):
            return "img"

        def start_target(self, image_id: str, environment=None):
            return None

        def wait_for_target(self, port: int, timeout: int = 60):
            return True

        def run_exploit(self, code: str, language: str = "python", env=None):
            raise RuntimeError("connection reset by peer")

        def get_target_logs(self):
            return ""

        def get_target_exit_code(self):
            return None

        def get_docker_ps_all(self):
            return ""

        def cleanup(self):
            return None

    monkeypatch.setattr(verify_exploit_module, "ExploitSandbox", FakeSandbox)
    monkeypatch.setattr(verify_exploit_module, "get_docker_client", lambda: FakeClient())

    tool_use = {
        "toolUseId": "t1",
        "input": {
            "dockerfile_content": "FROM python:3.12-slim\nCMD ['sleep','infinity']",
            "exploit_code": "print('hi')",
            "exploit_language": "python",
            "cve_id": "CVE-TEST",
            "target_info": {
                "affected_software": "test",
                "affected_versions": "0",
                "vulnerability_type": "RCE",
            },
            "exploit_mode": "remote",
            "target_port": 80,
        },
    }

    result = verify_exploit_module.verify_exploit(tool_use)
    assert result["status"] == "success"

    payload = result["content"][0]["json"]
    assert payload["verification_status"] == "infra_error"
    assert payload["error"]["stage"] == "run_exploit"
    assert payload["error"]["retryable"] is True


def test_verify_exploit_classifies_missing_interpreter_in_runner_as_infra_error(monkeypatch):
    """Missing interpreter in the remote exploit runner should be reported as infra_error."""

    from manus_use.tools import verify_exploit as verify_exploit_module

    class FakeClient:
        def ping(self):
            return True

        def close(self):
            return None

    class FakeSandbox:
        def __init__(self, timeout=300):
            self.timeout = timeout
            self.build_log = ""
            self.target_container = None
            self.exploit_container = None

        def build_target(self, dockerfile_content: str):
            return "img"

        def start_target(self, image_id: str, environment=None):
            return None

        def wait_for_target(self, port: int, timeout: int = 60):
            return True

        def run_exploit(self, code: str, language: str = "python", env=None):
            raise InterpreterNotFoundError(
                container_role="runner",
                language=language,
                candidates=["bash"],
                details="bash not found",
            )

        def get_target_logs(self):
            return ""

        def get_target_exit_code(self):
            return None

        def get_docker_ps_all(self):
            return ""

        def cleanup(self):
            return None

    monkeypatch.setattr(verify_exploit_module, "ExploitSandbox", FakeSandbox)
    monkeypatch.setattr(verify_exploit_module, "get_docker_client", lambda: FakeClient())

    tool_use = {
        "toolUseId": "t_runner",
        "input": {
            "dockerfile_content": "FROM alpine:3.19\nCMD ['sleep','infinity']",
            "exploit_code": "echo hi",
            "exploit_language": "bash",
            "cve_id": "CVE-TEST",
            "target_info": {
                "affected_software": "test",
                "affected_versions": "0",
                "vulnerability_type": "RCE",
            },
            "exploit_mode": "remote",
            "target_port": 80,
        },
    }

    result = verify_exploit_module.verify_exploit(tool_use)
    assert result["status"] == "success"

    payload = result["content"][0]["json"]
    assert payload["verification_status"] == "infra_error"
    assert payload["error"]["stage"] == "interpreter_preflight"
    assert payload["error"]["retryable"] is False


def test_verify_exploit_classifies_missing_interpreter_in_target_as_target_error(monkeypatch):
    """Missing interpreter in the local target container should be reported as target_error."""

    from manus_use.tools import verify_exploit as verify_exploit_module

    class FakeClient:
        def ping(self):
            return True

        def close(self):
            return None

    class FakeSandbox:
        def __init__(self, timeout=300):
            self.timeout = timeout
            self.build_log = ""
            self.target_container = None
            self.exploit_container = None

        def build_target(self, dockerfile_content: str):
            return "img"

        def start_target(self, image_id: str, environment=None):
            return None

        def run_local_exploit(self, code: str, language: str = "python", env=None):
            raise InterpreterNotFoundError(
                container_role="target",
                language=language,
                candidates=["python3", "python"],
                details="python3/python not found",
            )

        def get_target_logs(self):
            return ""

        def get_target_exit_code(self):
            return None

        def get_docker_ps_all(self):
            return ""

        def cleanup(self):
            return None

    monkeypatch.setattr(verify_exploit_module, "ExploitSandbox", FakeSandbox)
    monkeypatch.setattr(verify_exploit_module, "get_docker_client", lambda: FakeClient())

    tool_use = {
        "toolUseId": "t_target",
        "input": {
            "dockerfile_content": "FROM alpine:3.19\nCMD ['sleep','infinity']",
            "exploit_code": "print('hi')",
            "exploit_language": "python",
            "cve_id": "CVE-TEST",
            "target_info": {
                "affected_software": "test",
                "affected_versions": "0",
                "vulnerability_type": "LPE",
            },
            "exploit_mode": "local",
        },
    }

    result = verify_exploit_module.verify_exploit(tool_use)
    assert result["status"] == "success"

    payload = result["content"][0]["json"]
    assert payload["verification_status"] == "target_error"
    assert payload["error"]["stage"] == "interpreter_preflight"
    assert payload["error"]["retryable"] is False


def test_file_read_write(tmp_path):
    """Test file read and write operations."""
    # Write a file
    test_file = tmp_path / "test.txt"
    content = "Hello, ManusUse!"
    
    result = file_write(str(test_file), content)
    assert "Successfully wrote" in result
    
    # Read the file
    read_content = file_read(str(test_file))
    assert read_content == content


def test_file_list(tmp_path):
    """Test file listing."""
    # Create some test files
    (tmp_path / "file1.txt").write_text("content1")
    (tmp_path / "file2.py").write_text("content2")
    (tmp_path / "subdir").mkdir()
    
    # List all files
    files = file_list(str(tmp_path))
    assert len(files) == 3
    assert "file1.txt" in files
    assert "file2.py" in files
    assert "subdir" in files
    
    # List with pattern
    py_files = file_list(str(tmp_path), "*.py")
    assert len(py_files) == 1
    assert "file2.py" in py_files


def test_file_delete(tmp_path):
    """Test file deletion."""
    # Create and delete a file
    test_file = tmp_path / "delete_me.txt"
    test_file.write_text("delete this")
    
    result = file_delete(str(test_file))
    assert "Deleted file" in result
    assert not test_file.exists()
    
    # Delete empty directory
    test_dir = tmp_path / "empty_dir"
    test_dir.mkdir()
    
    result = file_delete(str(test_dir))
    assert "Deleted empty directory" in result
    assert not test_dir.exists()


def test_file_move(tmp_path):
    """Test file move/rename."""
    # Create source file
    src = tmp_path / "source.txt"
    src.write_text("move me")
    
    dst = tmp_path / "destination.txt"
    
    result = file_move(str(src), str(dst))
    assert "Moved" in result
    assert not src.exists()
    assert dst.exists()
    assert dst.read_text() == "move me"


def test_get_tools_by_names():
    """Test tool retrieval by names."""
    tools = get_tools_by_names(["file_read", "file_write"])
    assert len(tools) == 2
    
    # Check that we got the right tools
    tool_names = [t.__name__ for t in tools]
    assert any(name.endswith("file_read") for name in tool_names)
    assert any(name.endswith("file_write") for name in tool_names)


def test_file_errors():
    """Test error handling in file operations."""
    # Read non-existent file
    with pytest.raises(FileNotFoundError):
        file_read("/non/existent/file.txt")
        
    # List non-existent directory
    with pytest.raises(FileNotFoundError):
        file_list("/non/existent/directory")
        
    # Delete non-existent file
    with pytest.raises(FileNotFoundError):
        file_delete("/non/existent/file.txt")
        
    # Move non-existent file
    with pytest.raises(FileNotFoundError):
        file_move("/non/existent/source.txt", "/tmp/dest.txt")


def test_prepare_evaluate_script_wraps_top_level_return_and_null_guards_dom_reads():
    """Top-level returns and raw DOM reads are normalized before evaluate()."""
    script = 'return document.querySelector("main").textContent'

    prepared = prepare_evaluate_script(script)

    assert prepared.startswith("() => {")
    assert "?.textContent ?? null" in prepared
    assert "return" in prepared


def test_prepare_evaluate_script_preserves_valid_function_shape():
    """Existing evaluate functions should not be double-wrapped."""
    script = "() => document.body.innerText"

    assert prepare_evaluate_script(script) == script


def _install_fake_use_browser_module(monkeypatch, page_factory=None):
    use_browser_patch_module._PATCH_STATE.update(
        {
            "applied": False,
            "original_init": None,
            "original_handle_action": None,
        }
    )

    package = types.ModuleType("strands_tools")
    package.__path__ = []
    module = types.ModuleType("strands_tools.use_browser")

    class FakePage:
        def __init__(self):
            self.url = "https://example.com"
            self.text_calls = []
            self.html_calls = []
            self.evaluate_calls = []

        async def text_content(self, selector, timeout=None):
            self.text_calls.append((selector, timeout))
            return f"text for {selector}"

        async def wait_for_selector(self, selector, timeout=None, state=None):
            self.html_calls.append((selector, timeout, state))
            return True

        async def inner_html(self, selector):
            return f"<div>{selector}</div>"

        async def content(self):
            return "<html><body>ok</body></html>"

        async def evaluate(self, script):
            self.evaluate_calls.append(script)
            return None

    class BrowserApiMethods:
        @staticmethod
        async def get_text(page, selector):
            return f"original text {selector}"

        @staticmethod
        async def get_html(page, selector=None):
            return f"original html {selector}"

        @staticmethod
        async def evaluate(page, script):
            return script

        @staticmethod
        async def plain_action(page, selector):
            return f"plain:{selector}"

    original_get_text = BrowserApiMethods.get_text
    original_get_html = BrowserApiMethods.get_html

    class BrowserManager:
        def __init__(self):
            self.page = page_factory() if page_factory else FakePage()
            self._actions = {
                "get_text": original_get_text,
                "get_html": original_get_html,
                "evaluate": BrowserApiMethods.evaluate,
                "plain_action": BrowserApiMethods.plain_action,
            }

        async def ensure_browser(self, launch_options=None):
            return self.page, None

    module.BrowserApiMethods = BrowserApiMethods
    module.BrowserManager = BrowserManager
    package.use_browser = module

    monkeypatch.setitem(sys.modules, "strands_tools", package)
    monkeypatch.setitem(sys.modules, "strands_tools.use_browser", module)
    return module


def test_apply_comprehensive_patch_filters_timeout_args_for_compatible_actions(monkeypatch):
    """Patch should rebind stale actions and only inject supported kwargs."""
    fake_module = _install_fake_use_browser_module(monkeypatch)

    assert apply_comprehensive_patch(default_timeout_ms=4321, max_retries=1) is True

    manager = fake_module.BrowserManager()

    async def run_actions():
        text_result = await manager.handle_action(
            "get_text",
            args={"selector": "main", "timeout_ms": 1234},
        )
        plain_result = await manager.handle_action(
            "plain_action",
            args={"selector": "main", "timeout_ms": 9999},
        )
        return text_result, plain_result

    text_result, plain_result = asyncio.run(run_actions())

    assert text_result == [{"text": "Text content: text for main"}]
    assert manager.page.text_calls == [("main", 1234)]
    assert plain_result == [{"text": "plain:main"}]


def test_get_html_waits_for_attached_not_visible(monkeypatch):
    """HTML extraction should not require selector visibility (e.g. <title> in <head>)."""
    fake_module = _install_fake_use_browser_module(monkeypatch)

    assert apply_comprehensive_patch(default_timeout_ms=4321, max_retries=1) is True

    manager = fake_module.BrowserManager()

    async def run_action():
        return await manager.handle_action(
            "get_html",
            args={"selector": "title", "timeout_ms": 1234},
        )

    result = asyncio.run(run_action())

    assert result == [{"text": "<div>title</div>"}]
    assert manager.page.html_calls == [("title", 1234, "attached")]


def test_get_html_falls_back_to_full_page_content_when_selector_missing(monkeypatch):
    """get_html should return full page HTML when the provided selector never appears."""

    class MissingSelectorHtmlPage:
        def __init__(self):
            self.url = "https://example.com/some/page"
            self.html_calls = []
            self.content_calls = 0

        async def wait_for_selector(self, selector, timeout=None, state=None):
            self.html_calls.append((selector, timeout, state))
            raise PlaywrightTimeoutError("timeout")

        async def inner_html(self, selector):
            raise AssertionError("inner_html should not run when wait_for_selector times out")

        async def content(self):
            self.content_calls += 1
            return "<html><body><main>fallback</main></body></html>"

        async def evaluate(self, script):
            return None

    fake_module = _install_fake_use_browser_module(monkeypatch, page_factory=MissingSelectorHtmlPage)

    assert apply_comprehensive_patch(default_timeout_ms=2000, max_retries=1) is True

    manager = fake_module.BrowserManager()

    async def run_action():
        return await manager.handle_action(
            "get_html",
            args={"selector": "div.commit", "timeout_ms": 1234},
        )

    result = asyncio.run(run_action())

    assert result == [{"text": "<html><body><main>fallback</main></body></html>"}]
    assert manager.page.html_calls == [("div.commit", 1234, "attached")]
    assert manager.page.content_calls == 1


def test_apply_comprehensive_patch_normalizes_quoted_selector(monkeypatch):
    """Quoted CSS selectors should be normalized before reaching Playwright."""
    fake_module = _install_fake_use_browser_module(monkeypatch)

    assert apply_comprehensive_patch(default_timeout_ms=2000, max_retries=1) is True

    manager = fake_module.BrowserManager()

    async def run_action():
        return await manager.handle_action(
            "get_text",
            args={"selector": '".commit-msg"', "timeout_ms": 1234},
        )

    result = asyncio.run(run_action())

    assert result == [{"text": "Text content: text for .commit-msg"}]
    assert manager.page.text_calls == [('.commit-msg', 1234)]


def test_apply_comprehensive_patch_preserves_attribute_selector_with_internal_quotes(monkeypatch):
    """Valid attribute selectors should not be over-normalized."""
    fake_module = _install_fake_use_browser_module(monkeypatch)

    assert apply_comprehensive_patch(default_timeout_ms=2000, max_retries=1) is True

    manager = fake_module.BrowserManager()
    selector = '[data-test="commit-msg"]'

    async def run_action():
        return await manager.handle_action(
            "get_text",
            args={"selector": selector, "timeout_ms": 1234},
        )

    result = asyncio.run(run_action())

    assert result == [{"text": f"Text content: text for {selector}"}]
    assert manager.page.text_calls == [(selector, 1234)]


def test_apply_comprehensive_patch_does_not_retry_invalid_selector_errors(monkeypatch):
    """Selector parse failures should surface immediately instead of being retried."""

    class InvalidSelectorPage:
        def __init__(self):
            self.url = "https://example.com"
            self.text_calls = []

        async def text_content(self, selector, timeout=None):
            self.text_calls.append((selector, timeout))
            raise ValueError(
                'Page.wait_for_selector: Unexpected token "" while parsing css selector "div["'
            )

        async def evaluate(self, script):
            return None

    fake_module = _install_fake_use_browser_module(monkeypatch, page_factory=InvalidSelectorPage)

    assert apply_comprehensive_patch(default_timeout_ms=2000, max_retries=3) is True

    manager = fake_module.BrowserManager()

    async def run_action():
        return await manager.handle_action(
            "get_text",
            args={"selector": "div[", "timeout_ms": 1234},
        )

    result = asyncio.run(run_action())

    assert result[0]["text"].startswith("Error: Invalid CSS selector 'div[':")
    assert len(manager.page.text_calls) == 1


def test_get_html_on_raw_patch_page_bypasses_selector_wait(monkeypatch):
    """Patch-like URLs should return page content without waiting on selectors."""

    class RawPatchHtmlPage:
        def __init__(self):
            self.url = "https://example.com/commit.patch"
            self.html_calls = []

        async def wait_for_selector(self, selector, timeout=None, state=None):
            self.html_calls.append((selector, timeout, state))
            raise AssertionError("wait_for_selector should not run for raw patch pages")

        async def inner_html(self, selector):
            raise AssertionError("inner_html should not run for raw patch pages")

        async def content(self):
            return "<html><body><pre>diff --git a/x b/x</pre></body></html>"

        async def evaluate(self, script):
            return None

    fake_module = _install_fake_use_browser_module(monkeypatch, page_factory=RawPatchHtmlPage)

    assert apply_comprehensive_patch(default_timeout_ms=2000, max_retries=1) is True

    manager = fake_module.BrowserManager()

    async def run_action():
        return await manager.handle_action(
            "get_html",
            args={"selector": "pre", "timeout_ms": 1234},
        )

    result = asyncio.run(run_action())

    assert result == [{"text": "<html><body><pre>diff --git a/x b/x</pre></body></html>"}]
    assert manager.page.html_calls == []


def test_get_text_on_raw_patch_page_falls_back_to_raw_text(monkeypatch):
    """Patch-like URLs should fall back to raw text extraction after selector timeouts."""

    class RawPatchTextPage:
        def __init__(self):
            self.url = "https://example.com/commit.patch"
            self.text_calls = []
            self.evaluate_calls = []

        async def text_content(self, selector, timeout=None):
            self.text_calls.append((selector, timeout))
            raise PlaywrightTimeoutError("timeout")

        async def evaluate(self, script):
            self.evaluate_calls.append(script)
            if "document.querySelector('pre')" in script:
                return "diff --git a/foo b/foo\n+fix"
            return None

    fake_module = _install_fake_use_browser_module(monkeypatch, page_factory=RawPatchTextPage)

    assert apply_comprehensive_patch(default_timeout_ms=2000, max_retries=1) is True

    manager = fake_module.BrowserManager()

    async def run_action():
        return await manager.handle_action(
            "get_text",
            args={"selector": "pre", "timeout_ms": 1234},
        )

    result = asyncio.run(run_action())

    assert result == [{"text": "Text content (fallback 'raw_text_page'): diff --git a/foo b/foo\n+fix"}]
    assert manager.page.text_calls == [("pre", 1234)]


def test_apply_comprehensive_patch_normalizes_evaluate_scripts(monkeypatch):
    """Evaluate actions should receive function-shaped, null-safe JavaScript."""
    fake_module = _install_fake_use_browser_module(monkeypatch)

    apply_comprehensive_patch(default_timeout_ms=2000, max_retries=1)
    manager = fake_module.BrowserManager()

    async def run_action():
        return await manager.handle_action(
            "evaluate",
            args={"script": 'return document.querySelector("main").textContent'},
        )

    result = asyncio.run(run_action())

    normalized_script = result[0]["text"]
    assert normalized_script.startswith("() => {")
    assert "?.textContent ?? null" in normalized_script


@patch("manus_use.agents.browser_use_agent.BROWSER_USE_AVAILABLE", True)
@patch("manus_use.agents.browser_use_agent.ChatBedrock", create=True)
@patch("manus_use.agents.browser_use_agent.ChatOpenAI", create=True)
@patch("manus_use.agents.browser_use_agent.apply_comprehensive_patch")
def test_browser_use_agent_applies_patch_config(mock_apply_patch, _mock_openai, _mock_bedrock):
    """BrowserUseAgent should push timeout/retry config into the patch layer."""
    browser_config = Mock()
    browser_config.headless = True
    browser_config.enable_memory = False
    browser_config.max_steps = 10
    browser_config.max_actions_per_step = 5
    browser_config.use_vision = True
    browser_config.save_conversation_path = None
    browser_config.max_error_length = 400
    browser_config.tool_calling_method = "auto"
    browser_config.keep_alive = False
    browser_config.disable_security = False
    browser_config.extra_chromium_args = []
    browser_config.timeout = 25
    browser_config.retry_count = 7
    browser_config.debug = False
    browser_config.save_screenshots = False
    browser_config.screenshot_path = None

    config = Mock()
    config.browser_use = browser_config
    config.get_model = Mock(return_value=Mock())

    BrowserUseAgent(config=config)

    mock_apply_patch.assert_called_with(default_timeout_ms=25000, max_retries=7)
