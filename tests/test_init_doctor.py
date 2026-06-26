"""Tests for `manus-use init` and `manus-use doctor` subcommands."""

import contextlib
import os
import sys
from unittest import mock

import pytest
import toml

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _invoke(argv: list[str], *, inputs: list[str] | None = None):
    """Call cli.main() with patched sys.argv and optional stdin inputs.

    Returns (exit_code, capsys-style stdout) via capturing sys.exit.
    """
    from manus_use import cli  # noqa: PLC0415

    exit_code = 0

    # Patch Prompt.ask / Confirm.ask so tests don't block on stdin.
    with mock.patch.object(sys, "argv", ["manus-use"] + argv):
        try:
            cli.main()
        except SystemExit as exc:
            exit_code = exc.code if isinstance(exc.code, int) else 0

    return exit_code


# ---------------------------------------------------------------------------
# init – argument parsing / flag tests
# ---------------------------------------------------------------------------


class TestInitCommand:
    def test_init_writes_config(self, tmp_path):
        """init writes a valid TOML config to the specified path."""
        from manus_use import cli

        dest = tmp_path / "config.toml"

        # Simulate user choosing: provider=1 (openai), default model,
        # no env-var found, don't store key, sandbox=yes.
        prompt_responses = iter(
            [
                "1",  # provider choice (openai)
                "gpt-4o",  # model
                "n",  # don't store api key (Confirm)
                "y",  # enable sandbox (Confirm)
            ]
        )
        confirm_responses = iter(
            [
                False,  # store key? → no
                True,  # sandbox? → yes
            ]
        )

        with mock.patch("manus_use.cli.Prompt.ask", side_effect=lambda *a, **kw: next(prompt_responses)):
            with mock.patch("manus_use.cli.Confirm.ask", side_effect=lambda *a, **kw: next(confirm_responses)):
                with mock.patch.object(sys, "argv", ["manus-use", "init", "--output", str(dest), "--force"]):
                    with pytest.raises(SystemExit) as exc_info:
                        cli.main()

        assert exc_info.value.code == 0
        assert dest.exists()
        data = toml.load(dest)
        assert data["llm"]["provider"] == "openai"
        assert data["llm"]["model"] == "gpt-4o"

    def test_init_aborts_when_no_overwrite(self, tmp_path):
        """init exits 0 without writing when user declines overwrite."""
        from manus_use import cli

        dest = tmp_path / "config.toml"
        dest.write_text("[llm]\nprovider = 'openai'\n")
        original_mtime = dest.stat().st_mtime

        with mock.patch("manus_use.cli.Confirm.ask", return_value=False):
            with mock.patch.object(sys, "argv", ["manus-use", "init", "--output", str(dest)]):
                with pytest.raises(SystemExit) as exc_info:
                    cli.main()

        assert exc_info.value.code == 0
        assert dest.stat().st_mtime == original_mtime  # file not touched

    def test_init_force_overwrites_without_prompt(self, tmp_path):
        """--force skips the overwrite prompt."""
        from manus_use import cli

        dest = tmp_path / "config.toml"
        dest.write_text("[llm]\nprovider = 'openai'\n")

        prompt_seq = iter(["1", "gpt-4o"])
        confirm_seq = iter([False, True])  # no api key, yes sandbox

        with mock.patch("manus_use.cli.Prompt.ask", side_effect=lambda *a, **kw: next(prompt_seq)):
            with mock.patch("manus_use.cli.Confirm.ask", side_effect=lambda *a, **kw: next(confirm_seq)):
                with mock.patch.object(sys, "argv", ["manus-use", "init", "--output", str(dest), "--force"]):
                    with pytest.raises(SystemExit) as exc_info:
                        cli.main()

        assert exc_info.value.code == 0
        data = toml.load(dest)
        assert data["llm"]["provider"] == "openai"

    def test_init_anthropic_with_api_key(self, tmp_path):
        """init stores api_key in config when user opts to."""
        from manus_use import cli

        dest = tmp_path / "config.toml"

        prompt_seq = iter(["2", "claude-3-5-sonnet-20241022", "sk-secret"])
        confirm_seq = iter([True, True])  # store key? yes; sandbox? yes

        env_patch = {"ANTHROPIC_API_KEY": ""}  # not set in env

        with mock.patch("manus_use.cli.Prompt.ask", side_effect=lambda *a, **kw: next(prompt_seq)):
            with mock.patch("manus_use.cli.Confirm.ask", side_effect=lambda *a, **kw: next(confirm_seq)):
                with mock.patch.dict(os.environ, env_patch, clear=False):
                    with mock.patch.object(sys, "argv", ["manus-use", "init", "--output", str(dest), "--force"]):
                        with pytest.raises(SystemExit) as exc_info:
                            cli.main()

        assert exc_info.value.code == 0
        data = toml.load(dest)
        assert data["llm"]["provider"] == "anthropic"
        assert data["llm"]["api_key"] == "sk-secret"

    def test_init_bedrock_writes_region(self, tmp_path):
        """init stores aws_region for the bedrock provider."""
        from manus_use import cli

        dest = tmp_path / "config.toml"
        # provider choice 3 = bedrock; then model, region, sandbox
        prompt_seq = iter(
            [
                "3",
                "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
                "us-west-2",
            ]
        )
        confirm_seq = iter([True])  # sandbox

        with mock.patch("manus_use.cli.Prompt.ask", side_effect=lambda *a, **kw: next(prompt_seq)):
            with mock.patch("manus_use.cli.Confirm.ask", side_effect=lambda *a, **kw: next(confirm_seq)):
                with mock.patch.object(sys, "argv", ["manus-use", "init", "--output", str(dest), "--force"]):
                    with pytest.raises(SystemExit) as exc_info:
                        cli.main()

        assert exc_info.value.code == 0
        data = toml.load(dest)
        assert data["llm"]["provider"] == "bedrock"
        assert data["llm"]["aws_region"] == "us-west-2"

    def test_init_creates_parent_directory(self, tmp_path):
        """init creates missing parent directories."""
        from manus_use import cli

        dest = tmp_path / "nested" / "dir" / "config.toml"
        assert not dest.parent.exists()

        prompt_seq = iter(["4", "llama3.2", "http://localhost:11434"])
        confirm_seq = iter([False])  # sandbox

        with mock.patch("manus_use.cli.Prompt.ask", side_effect=lambda *a, **kw: next(prompt_seq)):
            with mock.patch("manus_use.cli.Confirm.ask", side_effect=lambda *a, **kw: next(confirm_seq)):
                with mock.patch.object(sys, "argv", ["manus-use", "init", "--output", str(dest), "--force"]):
                    with pytest.raises(SystemExit) as exc_info:
                        cli.main()

        assert exc_info.value.code == 0
        assert dest.exists()


# ---------------------------------------------------------------------------
# doctor – argument parsing / logic tests
# ---------------------------------------------------------------------------


class TestDoctorCommand:
    def _run_doctor(self, extra_argv=None, env_patch=None, import_side_effects=None, mock_imports_ok=True):
        """Helper: run `manus-use doctor` and return exit code.

        Args:
            extra_argv: extra CLI arguments after ``doctor``.
            env_patch: dict patched into ``os.environ``.
            import_side_effects: set of package names to simulate as missing.
            mock_imports_ok: when True (default) patch ``_check_import`` so all
                packages that are NOT in *import_side_effects* appear installed.
                Keeps tests hermetic across CI environments that lack optional
                packages like ``strands``.
        """
        from manus_use import cli

        argv = ["manus-use", "doctor"] + (extra_argv or [])

        missing = import_side_effects or set()

        patches = [mock.patch.object(sys, "argv", argv)]
        if env_patch is not None:
            patches.append(mock.patch.dict(os.environ, env_patch))
        if mock_imports_ok or import_side_effects:
            patches.append(mock.patch("manus_use.cli._check_import", side_effect=lambda p: p not in missing))

        with mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)):
            ctx = contextlib.ExitStack()
            for p in patches:
                ctx.enter_context(p)
            with ctx:
                with pytest.raises(SystemExit) as exc_info:
                    cli.main()

        return exc_info.value.code if isinstance(exc_info.value.code, int) else 0

    def test_doctor_exits_0_all_ok(self, tmp_path):
        """doctor returns 0 when all core packages present and API key set."""

        config_file = tmp_path / "config.toml"
        config_file.write_text("[llm]\nprovider = 'openai'\nmodel = 'gpt-4o'\n")

        # mock_imports_ok=True (default) makes _check_import always return True,
        # so the test is hermetic across CI environments that lack strands etc.
        rc = self._run_doctor(
            extra_argv=["--config", str(config_file)],
            env_patch={"OPENAI_API_KEY": "sk-test"},
        )
        assert rc == 0

    def test_doctor_exits_1_missing_env_var(self, tmp_path):
        """doctor returns 1 when required env var is absent."""
        from manus_use import cli

        config_file = tmp_path / "config.toml"
        config_file.write_text("[llm]\nprovider = 'openai'\nmodel = 'gpt-4o'\n")

        # Remove OPENAI_API_KEY and any MANUS_ overrides so doctor sees a truly
        # missing API key — env-var config loading could otherwise backfill it.
        env = {k: v for k, v in os.environ.items() if k not in ("OPENAI_API_KEY",) and not k.startswith("MANUS_LLM")}
        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch.object(sys, "argv", ["manus-use", "doctor", "--config", str(config_file)]):
                with mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)):
                    with mock.patch("manus_use.cli._check_import", return_value=True):
                        with pytest.raises(SystemExit) as exc_info:
                            cli.main()

        assert exc_info.value.code == 1

    def test_doctor_exits_1_missing_package(self, tmp_path):
        """doctor returns 1 when a required package is missing."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("[llm]\nprovider = 'openai'\nmodel = 'gpt-4o'\n")

        # Pretend 'strands' is missing
        rc = self._run_doctor(
            extra_argv=["--config", str(config_file)],
            env_patch={"OPENAI_API_KEY": "sk-test"},
            import_side_effects={"strands"},
        )
        assert rc == 1

    def test_doctor_anthropic_provider(self, tmp_path):
        """doctor checks ANTHROPIC_API_KEY for anthropic provider."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("[llm]\nprovider = 'anthropic'\nmodel = 'claude-3-5-sonnet-20241022'\n")

        # mock_imports_ok=True (default) -- hermetic across CI envs lacking strands
        rc = self._run_doctor(
            extra_argv=["--config", str(config_file)],
            env_patch={"ANTHROPIC_API_KEY": "sk-ant-test"},
        )
        assert rc == 0

    def test_doctor_no_config_file_warns_but_doesnt_crash(self, tmp_path):
        """doctor with no config file still runs (exits 0 if packages+env ok)."""

        # Point to non-existent path; doctor should handle gracefully
        rc = self._run_doctor(
            extra_argv=["--config", str(tmp_path / "nonexistent.toml")],
            env_patch={"OPENAI_API_KEY": "sk-test"},
        )
        # May be 0 or 1 depending on packages, but must not raise
        assert rc in (0, 1)

    def test_doctor_api_key_in_config_counts(self, tmp_path):
        """doctor passes even without env var when api_key is stored in config."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("[llm]\nprovider = 'openai'\nmodel = 'gpt-4o'\napi_key = 'sk-config-key'\n")

        # Omit OPENAI_API_KEY; api_key in config should satisfy the check.
        # Use _run_doctor with mock_imports_ok=True (default) for hermeticity.
        env_without_key = {k: v for k, v in os.environ.items() if k != "OPENAI_API_KEY"}
        rc = self._run_doctor(
            extra_argv=["--config", str(config_file)],
            env_patch=env_without_key,
        )
        assert rc == 0

    def test_doctor_bedrock_no_required_env(self, tmp_path):
        """doctor does not require API key for bedrock provider."""
        config_file = tmp_path / "config.toml"
        config_file.write_text("[llm]\nprovider = 'bedrock'\nmodel = 'us.anthropic.claude-3-5-sonnet-20241022-v2:0'\n")

        # Strip all AWS env vars
        env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch.object(sys, "argv", ["manus-use", "doctor", "--config", str(config_file)]):
                with mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)):
                    with pytest.raises(SystemExit) as exc_info:
                        from manus_use import cli as _cli

                        _cli.main()

        # Missing optional AWS env vars should not cause exit 1
        assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# Backward-compat: existing CLI behaviour still works
# ---------------------------------------------------------------------------


class TestBackwardCompat:
    def test_single_shot_still_works(self):
        """Positional task argument still routes to _run_single_shot."""
        from manus_use import cli

        captured = {}

        def fake_ss(task, *, mode, agent_type, show_plan, output, fmt, no_history, config, stream=False):
            captured["task"] = task
            return 0

        with mock.patch.object(sys, "argv", ["manus-use", "hello world"]):
            with mock.patch.object(cli, "_run_single_shot", side_effect=fake_ss):
                with mock.patch("manus_use.cli.Config") as m_cfg:
                    m_cfg.from_file.return_value = mock.MagicMock()
                    with pytest.raises(SystemExit) as exc_info:
                        cli.main()

        assert exc_info.value.code == 0
        assert captured.get("task") == "hello world"

    def test_interactive_still_works(self):
        """No positional task → routes to _run_interactive."""
        from manus_use import cli

        with mock.patch.object(sys, "argv", ["manus-use"]):
            with mock.patch.object(cli, "_run_interactive") as m_int:
                with mock.patch("manus_use.cli.Config") as m_cfg:
                    m_cfg.from_file.return_value = mock.MagicMock()
                    cli.main()

        m_int.assert_called_once()

    def test_version_flag_still_works(self):
        """--version still exits 0 and doesn't need subcommand."""
        from manus_use import cli

        with mock.patch.object(sys, "argv", ["manus-use", "--version"]):
            with pytest.raises(SystemExit) as exc_info:
                cli.main()

        assert exc_info.value.code == 0
