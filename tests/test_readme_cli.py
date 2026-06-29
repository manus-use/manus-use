"""Tests verifying that the CLI's --help output and subcommand routing match the README.

These tests act as living documentation: if any CLI flag, subcommand, or usage
example in the README drifts from the actual implementation, at least one test
here will catch it.
"""

from __future__ import annotations

import sys
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parser_help(build_fn_name: str) -> str:
    """Return the --help text for a named _build_*_parser function."""
    import io  # noqa: PLC0415

    from manus_agent import cli  # noqa: PLC0415

    build_fn = getattr(cli, build_fn_name)
    parser = build_fn()
    buf = io.StringIO()
    parser.print_help(buf)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Top-level help
# ---------------------------------------------------------------------------


class TestTopLevelHelp:
    def test_help_exits_zero(self):
        """`manus-agent --help` exits with code 0."""
        from manus_agent import cli  # noqa: PLC0415

        with pytest.raises(SystemExit) as exc_info:
            with mock.patch.object(sys, "argv", ["manus-agent", "--help"]):
                cli.main()
        assert exc_info.value.code == 0

    def test_help_mentions_task_positional(self, capsys):
        """`manus-agent --help` describes the [task] positional argument."""
        from manus_agent import cli  # noqa: PLC0415

        with pytest.raises(SystemExit):
            with mock.patch.object(sys, "argv", ["manus-agent", "--help"]):
                cli.main()

        out = capsys.readouterr().out
        assert "task" in out.lower()

    def test_help_mentions_subcommands(self, capsys):
        """`manus-agent --help` lists init, doctor, history, and analyze."""
        from manus_agent import cli  # noqa: PLC0415

        with pytest.raises(SystemExit):
            with mock.patch.object(sys, "argv", ["manus-agent", "--help"]):
                cli.main()

        out = capsys.readouterr().out
        for sub in ("init", "doctor", "history", "analyze"):
            assert sub in out, f"Subcommand '{sub}' not mentioned in --help output"

    def test_help_shows_format_flag(self, capsys):
        """`manus-agent --help` documents --format."""
        from manus_agent import cli  # noqa: PLC0415

        with pytest.raises(SystemExit):
            with mock.patch.object(sys, "argv", ["manus-agent", "--help"]):
                cli.main()

        out = capsys.readouterr().out
        assert "--format" in out

    def test_help_shows_no_history_flag(self, capsys):
        """`manus-agent --help` documents --no-history."""
        from manus_agent import cli  # noqa: PLC0415

        with pytest.raises(SystemExit):
            with mock.patch.object(sys, "argv", ["manus-agent", "--help"]):
                cli.main()

        out = capsys.readouterr().out
        assert "--no-history" in out


# ---------------------------------------------------------------------------
# init subcommand
# ---------------------------------------------------------------------------


class TestInitSubcommand:
    def test_init_parser_has_output_flag(self):
        """`manus-agent init` parser exposes --output."""
        assert "--output" in _parser_help("_build_init_parser")

    def test_init_parser_has_force_flag(self):
        """`manus-agent init` parser exposes --force."""
        assert "--force" in _parser_help("_build_init_parser")

    def test_init_routing_in_main(self):
        """`manus-agent init` routes to _cmd_init, not the task runner."""
        from manus_agent import cli  # noqa: PLC0415

        with mock.patch.object(cli, "_cmd_init", return_value=0) as m:
            with mock.patch.object(sys, "argv", ["manus-agent", "init"]):
                with pytest.raises(SystemExit) as exc_info:
                    cli.main()

        assert exc_info.value.code == 0
        m.assert_called_once()

    def test_init_does_not_route_to_single_shot(self):
        """`manus-agent init` must NOT invoke _run_single_shot."""
        from manus_agent import cli  # noqa: PLC0415

        with mock.patch.object(cli, "_cmd_init", return_value=0):
            with mock.patch.object(cli, "_run_single_shot") as m_shot:
                with mock.patch.object(sys, "argv", ["manus-agent", "init"]):
                    with pytest.raises(SystemExit):
                        cli.main()

        m_shot.assert_not_called()


# ---------------------------------------------------------------------------
# doctor subcommand
# ---------------------------------------------------------------------------


class TestDoctorSubcommand:
    def test_doctor_parser_has_config_flag(self):
        """`manus-agent doctor` parser exposes --config."""
        assert "--config" in _parser_help("_build_doctor_parser")

    def test_doctor_routing_in_main(self):
        """`manus-agent doctor` routes to _cmd_doctor."""
        from manus_agent import cli  # noqa: PLC0415

        with mock.patch.object(cli, "_cmd_doctor", return_value=0) as m:
            with mock.patch.object(sys, "argv", ["manus-agent", "doctor"]):
                with pytest.raises(SystemExit) as exc_info:
                    cli.main()

        assert exc_info.value.code == 0
        m.assert_called_once()

    def test_doctor_does_not_route_to_single_shot(self):
        """`manus-agent doctor` must NOT invoke _run_single_shot."""
        from manus_agent import cli  # noqa: PLC0415

        with mock.patch.object(cli, "_cmd_doctor", return_value=0):
            with mock.patch.object(cli, "_run_single_shot") as m_shot:
                with mock.patch.object(sys, "argv", ["manus-agent", "doctor"]):
                    with pytest.raises(SystemExit):
                        cli.main()

        m_shot.assert_not_called()


# ---------------------------------------------------------------------------
# analyze subcommand
# ---------------------------------------------------------------------------


class TestAnalyzeSubcommand:
    def test_analyze_parser_has_verify_flag(self):
        """`manus-agent analyze` parser exposes --verify."""
        assert "--verify" in _parser_help("_build_analyze_parser")

    def test_analyze_parser_has_output_flag(self):
        """`manus-agent analyze` parser exposes --output."""
        assert "--output" in _parser_help("_build_analyze_parser")

    def test_analyze_parser_has_config_flag(self):
        """`manus-agent analyze` parser exposes --config."""
        assert "--config" in _parser_help("_build_analyze_parser")

    def test_analyze_output_choices(self):
        """`manus-agent analyze --output` accepts text, json, and lark."""
        from manus_agent import cli  # noqa: PLC0415

        parser = cli._build_analyze_parser()
        for choice in ("text", "json", "lark"):
            args = parser.parse_args(["CVE-2025-1234", "--output", choice])
            assert args.output == choice

    def test_analyze_verify_defaults_false(self):
        """`manus-agent analyze` has --verify default to False."""
        from manus_agent import cli  # noqa: PLC0415

        args = cli._build_analyze_parser().parse_args(["CVE-2025-1234"])
        assert args.verify is False

    def test_analyze_output_default_is_text(self):
        """`manus-agent analyze` --output defaults to 'text'."""
        from manus_agent import cli  # noqa: PLC0415

        args = cli._build_analyze_parser().parse_args(["CVE-2025-1234"])
        assert args.output == "text"

    def test_analyze_cve_id_required(self):
        """`manus-agent analyze` without a CVE-ID exits with code 2."""
        from manus_agent import cli  # noqa: PLC0415

        with pytest.raises(SystemExit) as exc_info:
            cli._build_analyze_parser().parse_args([])
        assert exc_info.value.code == 2

    def test_analyze_routing_in_main(self):
        """`manus-agent analyze CVE-...` routes to _run_analyze."""
        from manus_agent import cli  # noqa: PLC0415

        captured: dict = {}

        def fake_run_analyze(*, cve_id, verify, output, config):
            captured.update(cve_id=cve_id, verify=verify, output=output)
            return 0

        with mock.patch.object(cli, "_run_analyze", side_effect=fake_run_analyze):
            with mock.patch("manus_agent.cli.Config") as m_cfg:
                m_cfg.from_file.return_value = mock.MagicMock()
                with mock.patch.object(sys, "argv", ["manus-agent", "analyze", "CVE-2025-6554"]):
                    with pytest.raises(SystemExit) as exc_info:
                        cli.main()

        assert exc_info.value.code == 0
        assert captured["cve_id"] == "CVE-2025-6554"
        assert captured["verify"] is False

    def test_analyze_verify_flag_forwarded(self):
        """`manus-agent analyze CVE-... --verify` passes verify=True to _run_analyze."""
        from manus_agent import cli  # noqa: PLC0415

        captured: dict = {}

        def fake_run_analyze(*, cve_id, verify, output, config):
            captured["verify"] = verify
            return 0

        with mock.patch.object(cli, "_run_analyze", side_effect=fake_run_analyze):
            with mock.patch("manus_agent.cli.Config") as m_cfg:
                m_cfg.from_file.return_value = mock.MagicMock()
                with mock.patch.object(sys, "argv", ["manus-agent", "analyze", "CVE-2025-6554", "--verify"]):
                    with pytest.raises(SystemExit):
                        cli.main()

        assert captured["verify"] is True

    def test_analyze_output_json_forwarded(self):
        """`manus-agent analyze CVE-... --output json` passes output='json' to _run_analyze."""
        from manus_agent import cli  # noqa: PLC0415

        captured: dict = {}

        def fake_run_analyze(*, cve_id, verify, output, config):
            captured["output"] = output
            return 0

        with mock.patch.object(cli, "_run_analyze", side_effect=fake_run_analyze):
            with mock.patch("manus_agent.cli.Config") as m_cfg:
                m_cfg.from_file.return_value = mock.MagicMock()
                with mock.patch.object(
                    sys,
                    "argv",
                    ["manus-agent", "analyze", "CVE-2024-3094", "--output", "json"],
                ):
                    with pytest.raises(SystemExit):
                        cli.main()

        assert captured["output"] == "json"


# ---------------------------------------------------------------------------
# history subcommand
# ---------------------------------------------------------------------------


class TestHistorySubcommand:
    def test_history_parser_has_limit_flag(self):
        """`manus-agent history` parser exposes --limit."""
        assert "--limit" in _parser_help("_build_history_parser")

    def test_history_parser_has_grep_flag(self):
        """`manus-agent history` parser exposes --grep."""
        assert "--grep" in _parser_help("_build_history_parser")

    def test_history_parser_has_format_flag(self):
        """`manus-agent history` parser exposes --format."""
        assert "--format" in _parser_help("_build_history_parser")

    def test_history_parser_has_clear_flag(self):
        """`manus-agent history` parser exposes --clear."""
        assert "--clear" in _parser_help("_build_history_parser")

    def test_history_routing_in_main(self):
        """`manus-agent history` routes to _cmd_history."""
        from manus_agent import cli  # noqa: PLC0415

        with mock.patch.object(cli, "_cmd_history", return_value=0) as m:
            with mock.patch.object(sys, "argv", ["manus-agent", "history"]):
                with pytest.raises(SystemExit) as exc_info:
                    cli.main()

        assert exc_info.value.code == 0
        m.assert_called_once()

    def test_history_limit_default(self):
        """`manus-agent history` --limit defaults to 20."""
        from manus_agent import cli  # noqa: PLC0415

        args = cli._build_history_parser().parse_args([])
        assert args.limit == 20

    def test_history_format_default(self):
        """`manus-agent history` --format defaults to 'text'."""
        from manus_agent import cli  # noqa: PLC0415

        args = cli._build_history_parser().parse_args([])
        assert args.fmt == "text"


# ---------------------------------------------------------------------------
# --format flag on run command
# ---------------------------------------------------------------------------


class TestFormatFlag:
    def test_format_json_is_valid(self):
        """`manus-agent task --format json` is accepted by the run parser."""
        from manus_agent import cli  # noqa: PLC0415

        args = cli._build_run_parser().parse_args(["some task", "--format", "json"])
        assert args.fmt == "json"

    def test_format_text_is_valid(self):
        """`manus-agent task --format text` is accepted by the run parser."""
        from manus_agent import cli  # noqa: PLC0415

        args = cli._build_run_parser().parse_args(["some task", "--format", "text"])
        assert args.fmt == "text"

    def test_format_default_is_text(self):
        """`--format` defaults to 'text' when omitted."""
        from manus_agent import cli  # noqa: PLC0415

        args = cli._build_run_parser().parse_args(["some task"])
        assert args.fmt == "text"

    def test_format_without_task_is_rejected(self):
        """`--format json` without a task argument exits with code 2."""
        from manus_agent import cli  # noqa: PLC0415

        with mock.patch("manus_agent.cli.Config") as m_cfg:
            m_cfg.from_file.return_value = mock.MagicMock()
            with mock.patch.object(sys, "argv", ["manus-agent", "--format", "json"]):
                with pytest.raises(SystemExit) as exc_info:
                    cli.main()

        assert exc_info.value.code == 2


# ---------------------------------------------------------------------------\n# --version flag
# ---------------------------------------------------------------------------


class TestVersionFlag:
    def test_version_exits_zero(self):
        """`manus-agent --version` exits with code 0."""
        from manus_agent import cli  # noqa: PLC0415

        with pytest.raises(SystemExit) as exc_info:
            with mock.patch.object(sys, "argv", ["manus-agent", "--version"]):
                cli.main()
        assert exc_info.value.code == 0

    def test_version_string_matches_package(self, capsys):
        """`manus-agent --version` output contains the installed package version."""
        import importlib.metadata  # noqa: PLC0415

        from manus_agent import cli  # noqa: PLC0415

        try:
            expected = importlib.metadata.version("manus-agent")
        except importlib.metadata.PackageNotFoundError:
            pytest.skip("package not installed in editable mode; skip version check")

        with pytest.raises(SystemExit):
            with mock.patch.object(sys, "argv", ["manus-agent", "--version"]):
                cli.main()

        # argparse sends --version to stdout (Python >=3.11) or stderr (<3.11)
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert expected in combined


# ---------------------------------------------------------------------------
# --agent flag
# ---------------------------------------------------------------------------


class TestAgentFlag:
    def test_agent_choices(self):
        """--agent accepts manus, browser, data, and mcp."""
        from manus_agent import cli  # noqa: PLC0415

        parser = cli._build_run_parser()
        for choice in ("manus", "browser", "data", "mcp"):
            args = parser.parse_args(["task", "--agent", choice])
            assert args.agent_type == choice

    def test_agent_default_is_manus(self):
        """--agent defaults to 'manus'."""
        from manus_agent import cli  # noqa: PLC0415

        args = cli._build_run_parser().parse_args(["task"])
        assert args.agent_type == "manus"


# ---------------------------------------------------------------------------
# --mode flag
# ---------------------------------------------------------------------------


class TestModeFlag:
    def test_mode_choices(self):
        """--mode accepts auto, single, and multi."""
        from manus_agent import cli  # noqa: PLC0415

        parser = cli._build_run_parser()
        for choice in ("auto", "single", "multi"):
            args = parser.parse_args(["task", "--mode", choice])
            assert args.mode == choice

    def test_mode_default_is_auto(self):
        """--mode defaults to 'auto'."""
        from manus_agent import cli  # noqa: PLC0415

        args = cli._build_run_parser().parse_args(["task"])
        assert args.mode == "auto"
