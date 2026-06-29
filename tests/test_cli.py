"""Tests for CLI single-shot mode, --version, --agent, --output, --format, and history flags."""

import json
import sys
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
    from manus_agent import cli

    captured = {}

    def fake_single_shot(task, *, mode, agent_type, show_plan, output, fmt, no_history, config, stream=False):
        captured["task"] = task
        captured["mode"] = mode
        captured["agent_type"] = agent_type
        captured["show_plan"] = show_plan
        captured["output"] = output
        captured["fmt"] = fmt
        captured["no_history"] = no_history
        return single_shot_rc

    with mock.patch.object(sys, "argv", ["manus-agent"] + argv):
        with mock.patch.object(cli, "_run_single_shot", side_effect=fake_single_shot) as m_ss:
            with mock.patch.object(cli, "_run_interactive") as m_int:
                with mock.patch("manus_agent.cli.Config") as m_cfg:
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
    from manus_agent import cli

    with mock.patch.object(sys, "argv", ["manus-agent", "--version"]):
        with pytest.raises(SystemExit) as exc_info:
            cli.main()
    assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# Single-shot mode (positional task argument)
# ---------------------------------------------------------------------------


def test_single_shot_dispatches_task():
    """`manus-agent 'do X'` routes to _run_single_shot with correct task."""
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
    from manus_agent import cli

    with mock.patch.object(sys, "argv", ["manus-agent", "--output", "out.txt"]):
        with mock.patch("manus_agent.cli.Config") as m_cfg:
            m_cfg.from_file.return_value = mock.MagicMock()
            with pytest.raises(SystemExit) as exc_info:
                cli.main()
    assert exc_info.value.code == 2


# ---------------------------------------------------------------------------
# _run_single_shot output-file writing
# ---------------------------------------------------------------------------


def test_run_single_shot_writes_output_file(tmp_path):
    """_run_single_shot saves result text to the specified output path."""
    from manus_agent import cli
    from manus_agent.config import Config

    out_file = tmp_path / "out.txt"
    fake_config = mock.MagicMock(spec=Config)

    fake_agent = mock.MagicMock()
    fake_agent.return_value = "hello world"

    with mock.patch.object(cli, "_make_agent", return_value=fake_agent):
        with mock.patch.object(cli, "_append_history"):
            rc = cli._run_single_shot(
                "say hello",
                mode="single",
                agent_type="manus",
                show_plan=False,
                output=out_file,
                fmt="text",
                no_history=False,
                config=fake_config,
            )

    assert rc == 0
    assert out_file.read_text(encoding="utf-8") == "hello world"


def test_run_single_shot_no_output_file(tmp_path):
    """_run_single_shot with output=None does not write any file."""
    from manus_agent import cli
    from manus_agent.config import Config

    fake_config = mock.MagicMock(spec=Config)
    fake_agent = mock.MagicMock()
    fake_agent.return_value = "result"

    with mock.patch.object(cli, "_make_agent", return_value=fake_agent):
        with mock.patch.object(cli, "_append_history"):
            rc = cli._run_single_shot(
                "task",
                mode="single",
                agent_type="manus",
                show_plan=False,
                output=None,
                fmt="text",
                no_history=False,
                config=fake_config,
            )

    assert rc == 0
    # No files should have been written in tmp_path
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# --format flag (CLI parsing)
# ---------------------------------------------------------------------------


def test_format_default_is_text():
    """fmt defaults to 'text' when --format is not passed."""
    captured = _invoke_main(["some task"])
    assert captured["fmt"] == "text"


def test_format_json_flag():
    """--format json is forwarded to _run_single_shot."""
    captured = _invoke_main(["some task", "--format", "json"])
    assert captured["fmt"] == "json"


def test_format_flag_rejected_without_task():
    """--format json without a task argument exits non-zero."""
    captured = _invoke_main(["--format", "json"])
    assert captured.get("exit_code", 0) != 0


def test_no_history_default_false():
    """--no-history defaults to False."""
    captured = _invoke_main(["some task"])
    assert captured["no_history"] is False


def test_no_history_flag():
    """--no-history is forwarded to _run_single_shot."""
    captured = _invoke_main(["some task", "--no-history"])
    assert captured["no_history"] is True


# ---------------------------------------------------------------------------
# --format json in _run_single_shot (output to stdout/file)
# ---------------------------------------------------------------------------


def test_run_single_shot_json_format_stdout(tmp_path, capsys):
    """--format json writes a valid JSON object to stdout."""
    from manus_agent import cli
    from manus_agent.config import Config

    fake_config = mock.MagicMock(spec=Config)
    fake_agent = mock.MagicMock()
    fake_agent.return_value = "42 is the answer"

    with mock.patch.object(cli, "_make_agent", return_value=fake_agent):
        with mock.patch.object(cli, "_append_history"):
            rc = cli._run_single_shot(
                "what is 6 × 7",
                mode="single",
                agent_type="manus",
                show_plan=False,
                output=None,
                fmt="json",
                no_history=False,
                config=fake_config,
            )

    assert rc == 0
    captured_stdout = capsys.readouterr().out
    data = json.loads(captured_stdout)
    assert data["task"] == "what is 6 × 7"
    assert data["result"] == "42 is the answer"
    assert data["agent"] == "manus"
    assert "mode" in data


def test_run_single_shot_json_format_writes_json_to_file(tmp_path):
    """--format json + --output FILE writes valid JSON to the file."""
    from manus_agent import cli
    from manus_agent.config import Config

    out_file = tmp_path / "result.json"
    fake_config = mock.MagicMock(spec=Config)
    fake_agent = mock.MagicMock()
    fake_agent.return_value = "some answer"

    with mock.patch.object(cli, "_make_agent", return_value=fake_agent):
        with mock.patch.object(cli, "_append_history"):
            rc = cli._run_single_shot(
                "do something",
                mode="single",
                agent_type="manus",
                show_plan=False,
                output=out_file,
                fmt="json",
                no_history=False,
                config=fake_config,
            )

    assert rc == 0
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["result"] == "some answer"


# ---------------------------------------------------------------------------
# _append_history
# ---------------------------------------------------------------------------


def test_append_history_creates_file(tmp_path):
    """_append_history creates the history file and writes a valid JSON record."""
    from manus_agent import cli

    hist_path = tmp_path / ".manus-agent" / "history.jsonl"

    with mock.patch.object(cli, "_HISTORY_PATH", hist_path):
        cli._append_history(
            "my task",
            "my result",
            agent_type="manus",
            mode="single",
            success=True,
            format="text",
        )

    assert hist_path.exists()
    record = json.loads(hist_path.read_text(encoding="utf-8").strip())
    assert record["task"] == "my task"
    assert record["result"] == "my result"
    assert record["agent"] == "manus"
    assert record["mode"] == "single"
    assert record["success"] is True
    assert record["format"] == "text"
    assert "timestamp" in record


def test_append_history_appends_multiple(tmp_path):
    """Multiple calls to _append_history write one record per line."""
    from manus_agent import cli

    hist_path = tmp_path / "history.jsonl"

    with mock.patch.object(cli, "_HISTORY_PATH", hist_path):
        for i in range(3):
            cli._append_history(
                f"task {i}",
                f"result {i}",
                agent_type="manus",
                mode="single",
                success=True,
                format="text",
            )

    lines = [line for line in hist_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 3
    records = [json.loads(line) for line in lines]
    assert records[0]["task"] == "task 0"
    assert records[2]["task"] == "task 2"


def test_no_history_flag_skips_append(tmp_path):
    """--no-history True prevents _append_history from being called."""
    from manus_agent import cli
    from manus_agent.config import Config

    fake_config = mock.MagicMock(spec=Config)
    fake_agent = mock.MagicMock()
    fake_agent.return_value = "result"

    with mock.patch.object(cli, "_make_agent", return_value=fake_agent):
        with mock.patch.object(cli, "_append_history") as m_hist:
            cli._run_single_shot(
                "task",
                mode="single",
                agent_type="manus",
                show_plan=False,
                output=None,
                fmt="text",
                no_history=True,
                config=fake_config,
            )

    m_hist.assert_not_called()


def test_history_flag_calls_append(tmp_path):
    """When no_history=False, _append_history is called after success."""
    from manus_agent import cli
    from manus_agent.config import Config

    fake_config = mock.MagicMock(spec=Config)
    fake_agent = mock.MagicMock()
    fake_agent.return_value = "result"

    with mock.patch.object(cli, "_make_agent", return_value=fake_agent):
        with mock.patch.object(cli, "_append_history") as m_hist:
            cli._run_single_shot(
                "task",
                mode="single",
                agent_type="manus",
                show_plan=False,
                output=None,
                fmt="text",
                no_history=False,
                config=fake_config,
            )

    m_hist.assert_called_once()
    call_kwargs = m_hist.call_args
    assert call_kwargs.kwargs["success"] is True


# ---------------------------------------------------------------------------
# manus-agent history subcommand
# ---------------------------------------------------------------------------


def _invoke_history(argv):
    """Call cli.main() with history subcommand argv."""
    from manus_agent import cli

    captured = {}
    with mock.patch.object(sys, "argv", ["manus-agent", "history"] + argv):
        with mock.patch.object(cli, "_cmd_history") as m_hist:
            m_hist.return_value = 0
            try:
                cli.main()
            except SystemExit as exc:
                captured["exit_code"] = exc.code
    captured["_cmd_history"] = m_hist
    return captured


def test_history_subcommand_dispatches():
    """manus-agent history dispatches to _cmd_history."""
    captured = _invoke_history([])
    assert captured["_cmd_history"].called


def test_cmd_history_no_file(tmp_path):
    """_cmd_history prints a friendly message when no history file exists."""
    from manus_agent import cli

    hist_path = tmp_path / "history.jsonl"
    args = mock.MagicMock()
    args.clear = False
    args.limit = 20
    args.fmt = "text"
    args.grep = None

    with mock.patch.object(cli, "_HISTORY_PATH", hist_path):
        rc = cli._cmd_history(args)

    assert rc == 0


def test_cmd_history_shows_records(tmp_path):
    """_cmd_history reads and displays records from the history file."""
    import datetime

    from manus_agent import cli

    hist_path = tmp_path / "history.jsonl"
    for i in range(3):
        record = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "task": f"task {i}",
            "agent": "manus",
            "mode": "single",
            "format": "text",
            "success": True,
            "result": f"result {i}",
        }
        with hist_path.open("a") as fh:
            fh.write(json.dumps(record) + "\n")

    args = mock.MagicMock()
    args.clear = False
    args.limit = 20
    args.fmt = "text"
    args.grep = None

    with mock.patch.object(cli, "_HISTORY_PATH", hist_path):
        rc = cli._cmd_history(args)

    assert rc == 0


def test_cmd_history_json_format(tmp_path, capsys):
    """_cmd_history --format json writes JSON array to stdout."""
    import datetime

    from manus_agent import cli

    hist_path = tmp_path / "history.jsonl"
    record = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "task": "test task",
        "agent": "manus",
        "mode": "single",
        "format": "text",
        "success": True,
        "result": "test result",
    }
    with hist_path.open("w") as fh:
        fh.write(json.dumps(record) + "\n")

    args = mock.MagicMock()
    args.clear = False
    args.limit = 20
    args.fmt = "json"
    args.grep = None

    with mock.patch.object(cli, "_HISTORY_PATH", hist_path):
        rc = cli._cmd_history(args)

    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert isinstance(data, list)
    assert data[0]["task"] == "test task"


def test_cmd_history_grep_filter(tmp_path):
    """_cmd_history --grep filters entries by task substring."""
    import datetime

    from manus_agent import cli

    hist_path = tmp_path / "history.jsonl"
    tasks = ["find CVE-2024", "list files", "analyze data"]
    for task in tasks:
        record = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "task": task,
            "agent": "manus",
            "mode": "single",
            "format": "text",
            "success": True,
            "result": "ok",
        }
        with hist_path.open("a") as fh:
            fh.write(json.dumps(record) + "\n")

    args = mock.MagicMock()
    args.clear = False
    args.limit = 20
    args.fmt = "json"
    args.grep = "CVE"

    with mock.patch.object(cli, "_HISTORY_PATH", hist_path):
        rc = cli._cmd_history(args)

    assert rc == 0


def test_cmd_history_clear(tmp_path):
    """_cmd_history --clear deletes the history file."""
    from manus_agent import cli

    hist_path = tmp_path / "history.jsonl"
    hist_path.write_text('{"task":"x"}\n', encoding="utf-8")

    args = mock.MagicMock()
    args.clear = True

    with mock.patch.object(cli, "_HISTORY_PATH", hist_path):
        rc = cli._cmd_history(args)

    assert rc == 0
    assert not hist_path.exists()


def test_cmd_history_limit(tmp_path, capsys):
    """_cmd_history --limit N returns at most N entries."""
    import datetime

    from manus_agent import cli

    hist_path = tmp_path / "history.jsonl"
    for i in range(10):
        record = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "task": f"task {i}",
            "agent": "manus",
            "mode": "single",
            "format": "text",
            "success": True,
            "result": f"r{i}",
        }
        with hist_path.open("a") as fh:
            fh.write(json.dumps(record) + "\n")

    args = mock.MagicMock()
    args.clear = False
    args.limit = 3
    args.fmt = "json"
    args.grep = None

    with mock.patch.object(cli, "_HISTORY_PATH", hist_path):
        rc = cli._cmd_history(args)

    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert len(data) == 3
