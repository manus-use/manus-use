"""Tests for the --stream flag in single-shot CLI mode."""

import json
import sys
from io import StringIO
from unittest import mock

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_run_parser():
    from manus_use.cli import _build_run_parser as _brp

    return _brp()


def _invoke_main(argv, *, single_shot_rc=0):
    """Call cli.main() and return captured data."""
    from manus_use import cli

    captured = {}

    def fake_single_shot(
        task,
        *,
        mode,
        agent_type,
        show_plan,
        output,
        fmt,
        no_history,
        config,
        stream=False,
    ):
        captured["task"] = task
        captured["mode"] = mode
        captured["agent_type"] = agent_type
        captured["show_plan"] = show_plan
        captured["output"] = output
        captured["fmt"] = fmt
        captured["no_history"] = no_history
        captured["stream"] = stream
        return single_shot_rc

    with mock.patch.object(sys, "argv", ["manus-use"] + argv):
        with mock.patch.object(cli, "_run_single_shot", side_effect=fake_single_shot) as m_ss:
            with mock.patch.object(cli, "_run_interactive"):
                with mock.patch("manus_use.cli.Config") as m_cfg:
                    m_cfg.from_file.return_value = mock.MagicMock()
                    try:
                        cli.main()
                    except SystemExit as exc:
                        captured["exit_code"] = exc.code

    captured["_run_single_shot"] = m_ss
    return captured


# ---------------------------------------------------------------------------
# 1. --stream flag exists in the parser
# ---------------------------------------------------------------------------


def test_stream_flag_in_parser_help():
    """--stream appears in the run parser help text."""
    parser = _build_run_parser()
    help_text = parser.format_help()
    assert "--stream" in help_text


def test_stream_flag_in_parser_actions():
    """The run parser has a --stream action registered."""
    parser = _build_run_parser()
    action_dests = {a.dest for a in parser._actions}
    assert "stream" in action_dests


# ---------------------------------------------------------------------------
# 2. --stream defaults to False
# ---------------------------------------------------------------------------


def test_stream_default_false_no_flag():
    """Parsing without --stream gives stream=False."""
    parser = _build_run_parser()
    args = parser.parse_args(["my task"])
    assert args.stream is False


def test_stream_default_false_explicit():
    """args.stream is a boolean False (not just falsy) when omitted."""
    parser = _build_run_parser()
    args = parser.parse_args(["task"])
    assert args.stream == False  # noqa: E712


def test_stream_true_when_flag_present():
    """Parsing with --stream gives stream=True."""
    parser = _build_run_parser()
    args = parser.parse_args(["--stream", "my task"])
    assert args.stream is True


# ---------------------------------------------------------------------------
# 3. main() routes --stream to _run_single_shot with stream=True
# ---------------------------------------------------------------------------


def test_main_stream_flag_forwarded():
    """main() passes stream=True to _run_single_shot when --stream used."""
    captured = _invoke_main(["--stream", "do something"])
    assert captured.get("stream") is True
    assert captured["task"] == "do something"


def test_main_no_stream_flag_forwarded_false():
    """main() passes stream=False to _run_single_shot when --stream not used."""
    captured = _invoke_main(["do something"])
    assert captured.get("stream") is False


# ---------------------------------------------------------------------------
# 4. --stream + --format json: warn to stderr, fall back to buffered JSON
# ---------------------------------------------------------------------------


def test_stream_and_json_warns_stderr(tmp_path):
    """--stream --format json writes a warning to stderr."""
    from manus_use import cli

    fake_agent = mock.MagicMock()
    fake_agent.return_value = "some result"
    fake_config = mock.MagicMock()

    stderr_capture = StringIO()

    with mock.patch("manus_use.cli._make_agent", return_value=fake_agent):
        with mock.patch("manus_use.cli._append_history"):
            with mock.patch("sys.stderr", stderr_capture):
                with mock.patch("sys.stdout", StringIO()):
                    cli._run_single_shot(
                        "task",
                        mode="single",
                        agent_type="manus",
                        show_plan=False,
                        output=None,
                        fmt="json",
                        no_history=True,
                        config=fake_config,
                        stream=True,
                    )

    warn_output = stderr_capture.getvalue()
    assert "[warn]" in warn_output
    assert "json" in warn_output.lower()


def test_stream_and_json_output_is_valid_json(tmp_path):
    """--stream --format json still produces valid JSON output."""
    from manus_use import cli

    fake_response = mock.MagicMock()
    fake_response.__str__ = lambda self: "hello result"

    fake_agent = mock.MagicMock(return_value=fake_response)
    fake_config = mock.MagicMock()

    stdout_capture = StringIO()

    with mock.patch("manus_use.cli._make_agent", return_value=fake_agent):
        with mock.patch("manus_use.cli._append_history"):
            with mock.patch("sys.stderr", StringIO()):
                with mock.patch("sys.stdout", stdout_capture):
                    cli._run_single_shot(
                        "task",
                        mode="single",
                        agent_type="manus",
                        show_plan=False,
                        output=None,
                        fmt="json",
                        no_history=True,
                        config=fake_config,
                        stream=True,
                    )

    payload = json.loads(stdout_capture.getvalue())
    assert "result" in payload
    assert payload["task"] == "task"


# ---------------------------------------------------------------------------
# 5. _run_single_shot with stream=True + PrintingCallbackHandler available
# ---------------------------------------------------------------------------


def test_stream_true_uses_printing_callback_handler():
    """With stream=True and PrintingCallbackHandler available, it is used."""
    from manus_use import cli

    fake_response = mock.MagicMock()
    fake_response.__str__ = lambda self: "streamed result"

    mock_handler_instance = mock.MagicMock()
    mock_handler_class = mock.MagicMock(return_value=mock_handler_instance)

    fake_stream_agent = mock.MagicMock(return_value=fake_response)
    fake_config = mock.MagicMock()

    make_agent_calls = []

    def capturing_make_agent(agent_type, config, **kwargs):
        make_agent_calls.append(kwargs)
        return fake_stream_agent

    with mock.patch("manus_use.cli._make_agent", side_effect=capturing_make_agent):
        with mock.patch("manus_use.cli._append_history"):
            with mock.patch("sys.stdout", StringIO()):
                with mock.patch("strands.handlers.PrintingCallbackHandler", mock_handler_class):
                    cli._run_single_shot(
                        "task",
                        mode="single",
                        agent_type="manus",
                        show_plan=False,
                        output=None,
                        fmt="text",
                        no_history=True,
                        config=fake_config,
                        stream=True,
                    )

    # The streaming agent should have been called
    fake_stream_agent.assert_called_once_with("task")
    # callback_handler was passed
    assert any("callback_handler" in call for call in make_agent_calls)


# ---------------------------------------------------------------------------
# 6. _run_single_shot with stream=True when PrintingCallbackHandler unavailable
# ---------------------------------------------------------------------------


def test_stream_true_fallback_when_import_fails():
    """When PrintingCallbackHandler is unavailable, falls back gracefully."""
    from manus_use import cli

    fake_response = mock.MagicMock()
    fake_response.__str__ = lambda self: "buffered result"
    # Make __iter__ raise TypeError so we hit the non-iterable warn path
    type(fake_response).__iter__ = mock.Mock(side_effect=TypeError("not iterable"))

    fake_config = mock.MagicMock()
    stderr_capture = StringIO()

    # Make _make_agent raise TypeError when callback_handler is passed
    # (simulates an agent that doesn't accept callback_handler)
    real_make_agent_call_count = [0]
    buffered_agent = mock.MagicMock(return_value=fake_response)

    def mock_make_agent(agent_type, config, **kwargs):
        real_make_agent_call_count[0] += 1
        if "callback_handler" in kwargs:
            raise TypeError("callback_handler not supported")
        return buffered_agent

    with mock.patch("manus_use.cli._make_agent", side_effect=mock_make_agent):
        with mock.patch("manus_use.cli._append_history"):
            with mock.patch("sys.stderr", stderr_capture):
                with mock.patch("manus_use.cli.console"):
                    rc = cli._run_single_shot(
                        "task",
                        mode="single",
                        agent_type="manus",
                        show_plan=False,
                        output=None,
                        fmt="text",
                        no_history=True,
                        config=fake_config,
                        stream=True,
                    )

    # Should not crash; returns 0
    assert rc == 0
    # The buffered (fallback) agent was called
    buffered_agent.assert_called_once_with("task")
    # The [warn] about streaming fallback was emitted
    assert "[warn]" in stderr_capture.getvalue()


# ---------------------------------------------------------------------------
# 7. _run_single_shot with stream=True when result is a generator
# ---------------------------------------------------------------------------


def test_stream_generator_result_iterates_chunks():
    """When result is a generator, chunks are printed and joined."""
    from manus_use import cli

    def fake_gen():
        yield "Hello"
        yield " "
        yield "world"

    # Make PrintingCallbackHandler import fail so we hit the fallback path
    fake_agent = mock.MagicMock(return_value=fake_gen())
    fake_config = mock.MagicMock()

    stdout_capture = StringIO()
    stderr_capture = StringIO()

    import builtins

    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        fromlist = args[2] if len(args) > 2 else []
        if name == "strands.handlers" and "PrintingCallbackHandler" in fromlist:
            raise ImportError("mocked")
        return real_import(name, *args, **kwargs)

    with mock.patch("builtins.__import__", side_effect=mock_import):
        with mock.patch("manus_use.cli._make_agent", return_value=fake_agent):
            with mock.patch("manus_use.cli._append_history"):
                with mock.patch("sys.stdout", stdout_capture):
                    with mock.patch("sys.stderr", stderr_capture):
                        rc = cli._run_single_shot(
                            "task",
                            mode="single",
                            agent_type="manus",
                            show_plan=False,
                            output=None,
                            fmt="text",
                            no_history=True,
                            config=fake_config,
                            stream=True,
                        )

    assert rc == 0
    written = stdout_capture.getvalue()
    assert "Hello" in written
    assert "world" in written


# ---------------------------------------------------------------------------
# 8. _run_single_shot with stream=False: normal buffered output (regression)
# ---------------------------------------------------------------------------


def test_stream_false_uses_buffered_path():
    """With stream=False, normal console.status path is used."""
    from manus_use import cli

    fake_response = mock.MagicMock()
    fake_response.__str__ = lambda self: "buffered result"

    fake_agent = mock.MagicMock(return_value=fake_response)
    fake_config = mock.MagicMock()

    with mock.patch("manus_use.cli._make_agent", return_value=fake_agent):
        with mock.patch("manus_use.cli._append_history"):
            with mock.patch("manus_use.cli.console"):
                rc = cli._run_single_shot(
                    "task",
                    mode="single",
                    agent_type="manus",
                    show_plan=False,
                    output=None,
                    fmt="text",
                    no_history=True,
                    config=fake_config,
                    stream=False,
                )

    assert rc == 0
    fake_agent.assert_called_once_with("task")


# ---------------------------------------------------------------------------
# 9. stream flag is only on run parser, NOT on subcommand parsers
# ---------------------------------------------------------------------------


def test_stream_not_on_analyze_parser():
    """--stream is not a recognised flag on the analyze parser."""
    from manus_use.cli import _build_analyze_parser

    parser = _build_analyze_parser()
    action_dests = {a.dest for a in parser._actions}
    assert "stream" not in action_dests


def test_stream_not_on_discover_parser():
    """--stream is not a recognised flag on the discover parser."""
    from manus_use.cli import _build_discover_parser

    parser = _build_discover_parser()
    action_dests = {a.dest for a in parser._actions}
    assert "stream" not in action_dests


def test_stream_not_on_history_parser():
    """--stream is not a recognised flag on the history parser."""
    from manus_use.cli import _build_history_parser

    parser = _build_history_parser()
    action_dests = {a.dest for a in parser._actions}
    assert "stream" not in action_dests


def test_stream_not_on_init_parser():
    """--stream is not a recognised flag on the init parser."""
    from manus_use.cli import _build_init_parser

    parser = _build_init_parser()
    action_dests = {a.dest for a in parser._actions}
    assert "stream" not in action_dests


def test_stream_not_on_doctor_parser():
    """--stream is not a recognised flag on the doctor parser."""
    from manus_use.cli import _build_doctor_parser

    parser = _build_doctor_parser()
    action_dests = {a.dest for a in parser._actions}
    assert "stream" not in action_dests


# ---------------------------------------------------------------------------
# 10. _run_single_shot stream=True, non-iterable non-str result → fallback warn
# ---------------------------------------------------------------------------


def test_stream_fallback_buffered_warning_for_non_iterable():
    """Non-iterable result in fallback path prints buffered-output warning."""
    from manus_use import cli

    # A plain object that is not iterable and not a string
    class _Opaque:
        def __str__(self):
            return "opaque result"

    fake_agent = mock.MagicMock(return_value=_Opaque())
    fake_config = mock.MagicMock()

    stderr_capture = StringIO()

    import builtins

    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        fromlist = args[2] if len(args) > 2 else []
        if name == "strands.handlers" and "PrintingCallbackHandler" in fromlist:
            raise ImportError("mocked")
        return real_import(name, *args, **kwargs)

    with mock.patch("builtins.__import__", side_effect=mock_import):
        with mock.patch("manus_use.cli._make_agent", return_value=fake_agent):
            with mock.patch("manus_use.cli._append_history"):
                with mock.patch("sys.stderr", stderr_capture):
                    with mock.patch("manus_use.cli.console"):
                        rc = cli._run_single_shot(
                            "task",
                            mode="single",
                            agent_type="manus",
                            show_plan=False,
                            output=None,
                            fmt="text",
                            no_history=True,
                            config=fake_config,
                            stream=True,
                        )

    assert rc == 0
    warn = stderr_capture.getvalue()
    assert "[warn]" in warn
    assert "buffered" in warn
