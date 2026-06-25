"""Tests verifying that all manus_use modules are importable as an installed package.

These tests guard against ``from src.manus_use.<...>`` imports and module-level
side-effects (network connections, filesystem mutations) that break the package
when installed via ``pip install manus-use``.

Background
----------
Several tools inside ``src/manus_use/tools/`` previously used the path
``from src.manus_use.config import Config``.  That import happens to work when
running pytest from the repository root (because ``src/`` is on ``sys.path``),
but it fails with ``ModuleNotFoundError: No module named 'src'`` for any user
who installed the package via pip.  The correct import is
``from manus_use.config import Config``.

``submit_cves.py`` additionally had a module-level ``MCPClient.start()`` call
that attempted a TCP connection to ``localhost:3001`` on import, causing every
test run (and every ``import manus_use``) to fail with a network error unless
a local MCP server happened to be running.
"""

from __future__ import annotations

import importlib
import sys

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_import(module_name: str):
    """Import *module_name* from scratch (drop any cached version first)."""
    # Remove the module and any sub-modules from the cache so the import is
    # always fresh, regardless of what other tests imported earlier.
    for key in list(sys.modules.keys()):
        if key == module_name or key.startswith(module_name + "."):
            del sys.modules[key]
    return importlib.import_module(module_name)


# ---------------------------------------------------------------------------
# Import-stability tests
# ---------------------------------------------------------------------------


class TestModuleImports:
    """Each module must be importable without errors or network side-effects."""

    def test_create_lark_document_importable(self):
        """create_lark_document uses the correct package-relative import."""
        mod = _fresh_import("manus_use.tools.create_lark_document")
        assert hasattr(mod, "TOOL_SPEC")
        assert mod.TOOL_SPEC["name"] == "create_lark_document"

    def test_search_for_exploits_importable(self):
        """search_for_exploits uses the correct package-relative import."""
        mod = _fresh_import("manus_use.tools.search_for_exploits")
        assert hasattr(mod, "TOOL_SPEC")
        assert mod.TOOL_SPEC["name"] == "search_for_exploits"

    def test_get_github_advisory_importable(self):
        """get_github_advisory uses the correct package-relative import."""
        mod = _fresh_import("manus_use.tools.get_github_advisory")
        assert hasattr(mod, "get_github_advisory")

    def test_submit_cves_importable_without_mcp_server(self, monkeypatch):
        """submit_cves must NOT connect to an MCP server on import.

        The MCP client initialisation must be deferred to first use so the
        module is importable even when no local MCP server is running.
        """
        # Poison the MCP-client constructor so any eager initialisation raises.
        import unittest.mock as mock  # noqa: PLC0415

        with mock.patch(
            "strands.tools.mcp.mcp_client.MCPClient.start",
            side_effect=AssertionError("MCPClient.start must NOT be called at import time"),
        ):
            mod = _fresh_import("manus_use.tools.submit_cves")

        assert hasattr(mod, "TOOL_SPEC")
        assert mod.TOOL_SPEC["name"] == "submit_cves"

    def test_workflow_agent_importable(self):
        """workflow_agent must not use sys.path.insert for src/ directory."""
        mod = _fresh_import("manus_use.multi_agents.workflow_agent")
        assert hasattr(mod, "WorkflowAgent")

    def test_workflow_agent_no_src_path_injection(self):
        """Importing workflow_agent must not leave a stale 'src' path on sys.path."""
        original_path = list(sys.path)
        _fresh_import("manus_use.multi_agents.workflow_agent")
        # Any path that looks like '.../manus-use/src' or '.../manus-use-.../src'
        # should NOT have been inserted by the module.
        new_entries = [p for p in sys.path if p not in original_path]
        src_injections = [p for p in new_entries if p.endswith("/src")]
        assert src_injections == [], (
            f"workflow_agent injected unexpected sys.path entries: {src_injections}"
        )


# ---------------------------------------------------------------------------
# No ``from src.`` imports anywhere in the installed package
# ---------------------------------------------------------------------------


def test_no_src_prefix_imports_in_package(tmp_path):
    """No source file under src/manus_use/ should use 'from src.' imports.

    Such imports break pip-installed packages.  This test walks the source
    tree and fails immediately if any such pattern is found.
    """
    import pathlib  # noqa: PLC0415
    import re  # noqa: PLC0415

    pattern = re.compile(r"^\s*from\s+src\.", re.MULTILINE)

    src_root = pathlib.Path(__file__).resolve().parents[1] / "src" / "manus_use"
    violations = []
    for py_file in sorted(src_root.rglob("*.py")):
        text = py_file.read_text(encoding="utf-8")
        if pattern.search(text):
            violations.append(str(py_file.relative_to(src_root.parent.parent)))

    assert violations == [], (
        "Found 'from src.' imports in the following files — "
        "these break the installed package:\n  "
        + "\n  ".join(violations)
    )


def test_no_sys_path_src_injection_in_package():
    """No source file under src/manus_use/ should call sys.path.insert to add 'src/'.

    Injecting the source tree into sys.path at module level is a development
    hack that breaks installed packages and test isolation.
    """
    import pathlib  # noqa: PLC0415
    import re  # noqa: PLC0415

    # Match lines like: sys.path.insert(0, str(Path(__file__).parent / "src"))
    # or: sys.path.insert(0, "/some/absolute/src")
    pattern = re.compile(r'sys\.path\.insert.*["\']src["\']', re.MULTILINE)

    src_root = pathlib.Path(__file__).resolve().parents[1] / "src" / "manus_use"
    violations = []
    for py_file in sorted(src_root.rglob("*.py")):
        text = py_file.read_text(encoding="utf-8")
        if pattern.search(text):
            violations.append(str(py_file.relative_to(src_root.parent.parent)))

    assert violations == [], (
        "Found sys.path.insert('src') calls in the following files — "
        "these break the installed package:\n  "
        + "\n  ".join(violations)
    )
