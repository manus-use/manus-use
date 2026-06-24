"""Tests for CLI single-shot mode, --version, --agent, and --output flags."""

import sys
from pathlib import Path
from unittest import mock

import pytest
from click.testing import CliRunner  # noqa: F401 – not used here; argparse tested directly

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _invoke_main(argv, *, patch_single_shot=True, single_shot_rc=0):
    """Call cli.main() with a patched sys.argv.

    patch_single_shot=True stubs out _run_single_shot so we only test CLI
    parsing, not actual agent execution.
    """
    from manus_use import cli

    captured = {}

    def fake_single_shot(task, *, mode, agent_type, show_plan, output, config):
        captured["task"] = task
        captured["mode"] = mode
        captured["agent_type"] = agent_type
        captured["show_plan"] = show_plan
        captured["output"] = output
        return single_shot_rc

    with mock.patch.object(sys, "argv", ["manus-use"] + argv):
        with mock.patch.object(cli, "_run_single_shot", side_effect=fake_single_shot) as m_ss:
            with mock.patch.object(cli, "_run_interactive") as m_int:
                with mock.patch("manus_use.cli.Config") as m_cfg:
                    m_cfg.from_file.return_value = mock.MagicMock()
                    try:
                        cli.main()
                    except SystemExit as exc:
                        captured["exit_code"] = exc.code

    captured["_run_single_shot"] = m_ss
    captured["_run_interactive"] = m_int
    return captured


# ---------------------------------------------------------------------------
# --version
# ---------------------------------------------------------------------------

def test_version_flag():
    """--version prints version string and exits 0."""
    from manus_use import __version__
    from manus_use import cli

    with mock.patch.object(sys, "argv", ["manus-use", "--version"]):
        with pytest.raises(SystemExit) as exc_info:
            cli.main()
    assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# Single-shot mode (positional task argument)
# ---------------------------------------------------------------------------

def test_single_shot_dispatches_task():
    """`manus-use 'do X'` routes to _run_single_shot with correct task."""
    captured = _invoke_main(["do X"])
    assert captured["task"] == "do X"
    assert captured["_run_single_shot"].called
    assert not captured["_run_interactive"].called


def test_single_shot_default_flags():
    """Default mode=auto, agent_type=manus, show_plan=False, output=None."""
    captured = _invoke_main(["some task"])
    assert captured["mode"] == "auto"
    assert captured["agent_type"] == "manus"
    assert captured["show_plan"] is False
    assert captured["output"] is None


def test_single_shot_mode_flag():
    """--mode single is forwarded to _run_single_shot."""
    captured = _invoke_main(["task", "--mode", "single"])
    assert captured["mode"] == "single"


def test_single_shot_multi_mode_flag():
    """--mode multi is forwarded to _run_single_shot."""
    captured = _invoke_main(["task", "--mode", "multi"])
    assert captured["mode"] == "multi"


def test_single_shot_agent_browser():
    """--agent browser sets agent_type='browser'."""
    captured = _invoke_main(["task", "--agent", "browser"])
    assert captured["agent_type"] == "browser"


def test_single_shot_agent_data():
    """--agent data sets agent_type='data'."""
    captured = _invoke_main(["task", "--agent", "data"])
    assert captured["agent_type"] == "data"


def test_single_shot_show_plan():
    """--show-plan is forwarded to _run_single_shot."""
    captured = _invoke_main(["task", "--show-plan"])
    assert captured["show_plan"] is True


def test_single_shot_output_flag(tmp_path):
    """--output <file> sets the output path in _run_single_shot."""
    out = tmp_path / "result.txt"
    captured = _invoke_main(["task", "--output", str(out)])
    assert captured["output"] == out


def test_single_shot_nonzero_exit():
    """_run_single_shot returning 1 causes sys.exit(1)."""
    captured = _invoke_main(["failing task"], single_shot_rc=1)
    assert captured.get("exit_code") == 1


# ---------------------------------------------------------------------------
# Interactive mode (no positional task)
# ---------------------------------------------------------------------------

def test_no_task_goes_interactive():
    """Omitting the task argument invokes _run_interactive."""
    captured = _invoke_main([])
    assert captured["_run_interactive"].called
    assert not captured["_run_single_shot"].called


def test_output_without_task_is_error():
    """--output without a task argument should produce an argparse error (exit 2)."""
    from manus_use import cli

    with mock.patch.object(sys, "argv", ["manus-use", "--output", "out.txt"]):
        with mock.patch("manus_use.cli.Config") as m_cfg:
            m_cfg.from_file.return_value = mock.MagicMock()
            with pytest.raises(SystemExit) as exc_info:
                cli.main()
    assert exc_info.value.code == 2


# ---------------------------------------------------------------------------
# _run_single_shot output-file writing
# ---------------------------------------------------------------------------

def test_run_single_shot_writes_output_file(tmp_path):
    """_run_single_shot saves result text to the specified output path."""
    from manus_use import cli
    from manus_use.config import Config, LLMConfig

    out_file = tmp_path / "out.txt"
    fake_config = mock.MagicMock(spec=Config)

    fake_agent = mock.MagicMock()
    fake_agent.return_value = "hello world"

    with mock.patch.object(cli, "_make_agent", return_value=fake_agent):
        rc = cli._run_single_shot(
            "say hello",
            mode="single",
            agent_type="manus",
            show_plan=False,
            output=out_file,
            config=fake_config,
        )

    assert rc == 0
    assert out_file.read_text(encoding="utf-8") == "hello world"


def test_run_single_shot_no_output_file(tmp_path):
    """_run_single_shot with output=None does not write any file."""
    from manus_use import cli
    from manus_use.config import Config

    fake_config = mock.MagicMock(spec=Config)
    fake_agent = mock.MagicMock()
    fake_agent.return_value = "result"

    with mock.patch.object(cli, "_make_agent", return_value=fake_agent):
        rc = cli._run_single_shot(
            "task",
            mode="single",
            agent_type="manus",
            show_plan=False,
            output=None,
            config=fake_config,
        )

    assert rc == 0
    # No files should have been written in tmp_path
    assert list(tmp_path.iterdir()) == []
