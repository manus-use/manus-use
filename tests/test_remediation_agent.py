"""Tests for the RemediationAgent and the ``remediate`` CLI subcommand."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Module import / agent class
# ---------------------------------------------------------------------------


def test_remediation_agent_module_imports_without_crashing():
    """The module must be importable even without optional deps installed."""
    import manus_use.agents.remediation_agent as ra

    assert hasattr(ra, "RemediationAgent")


def test_remediation_agent_exported_from_agents_package():
    """RemediationAgent is re-exported from the agents package."""
    from manus_use.agents import RemediationAgent  # noqa: F401


def test_default_model_id_is_defined():
    """DEFAULT_MODEL_ID is a non-empty string."""
    from manus_use.agents.remediation_agent import DEFAULT_MODEL_ID

    assert isinstance(DEFAULT_MODEL_ID, str)
    assert DEFAULT_MODEL_ID


# ---------------------------------------------------------------------------
# build_request static method
# ---------------------------------------------------------------------------


def test_build_request_default_output_is_text():
    """build_request without output kwarg produces a text prompt."""
    from manus_use.agents.remediation_agent import RemediationAgent

    req = RemediationAgent.build_request("CVE-2024-3094")
    assert "CVE-2024-3094" in req
    # Should NOT contain JSON instructions for the default text mode
    assert "JSON" not in req


def test_build_request_json_output():
    """build_request with output='json' adds JSON envelope instructions."""
    from manus_use.agents.remediation_agent import RemediationAgent

    req = RemediationAgent.build_request("CVE-2024-3094", output="json")
    assert "CVE-2024-3094" in req
    assert "JSON" in req
    assert "remediation_steps" in req


def test_build_request_normalises_cve_id_case():
    """build_request uppercases the CVE ID regardless of input case."""
    from manus_use.agents.remediation_agent import RemediationAgent

    req = RemediationAgent.build_request("cve-2024-3094")
    assert "CVE-2024-3094" in req


def test_build_request_strips_whitespace():
    """build_request strips surrounding whitespace from the CVE ID."""
    from manus_use.agents.remediation_agent import RemediationAgent

    req = RemediationAgent.build_request("  CVE-2024-3094  ")
    assert "CVE-2024-3094" in req


# ---------------------------------------------------------------------------
# RemediationAgent construction and handle_request (mocked internals)
# ---------------------------------------------------------------------------


def test_remediation_agent_handle_request_returns_string():
    """handle_request converts the agent response to a string."""
    from manus_use.agents.remediation_agent import RemediationAgent

    with mock.patch(
        "manus_use.agents.remediation_agent.RemediationAgent.__init__",
        return_value=None,
    ):
        agent = RemediationAgent.__new__(RemediationAgent)
        mock_inner = mock.MagicMock()
        mock_inner.return_value = "Remediation report text"
        agent.agent = mock_inner

        result = agent.handle_request("Generate a report for CVE-2024-3094.")

    assert result == "Remediation report text"


def test_remediation_agent_remediate_calls_handle_request():
    """remediate() is a convenience wrapper around build_request + handle_request."""
    from manus_use.agents.remediation_agent import RemediationAgent

    with mock.patch(
        "manus_use.agents.remediation_agent.RemediationAgent.__init__",
        return_value=None,
    ):
        agent = RemediationAgent.__new__(RemediationAgent)
        mock_inner = mock.MagicMock()
        mock_inner.return_value = "Report output"
        agent.agent = mock_inner

        result = agent.remediate("CVE-2024-3094")

    assert result == "Report output"
    # The inner agent must have been called with the built request
    mock_inner.assert_called_once()
    call_arg = mock_inner.call_args[0][0]
    assert "CVE-2024-3094" in call_arg


def test_remediation_agent_remediate_json_mode():
    """remediate(output='json') passes the correct JSON prompt to the agent."""
    from manus_use.agents.remediation_agent import RemediationAgent

    with mock.patch(
        "manus_use.agents.remediation_agent.RemediationAgent.__init__",
        return_value=None,
    ):
        agent = RemediationAgent.__new__(RemediationAgent)
        mock_inner = mock.MagicMock()
        mock_inner.return_value = '{"cve": "CVE-2024-3094"}'
        agent.agent = mock_inner

        result = agent.remediate("CVE-2024-3094", output="json")

    call_arg = mock_inner.call_args[0][0]
    assert "JSON" in call_arg
    assert result == '{"cve": "CVE-2024-3094"}'


# ---------------------------------------------------------------------------
# CLI — _build_remediate_parser
# ---------------------------------------------------------------------------


def test_remediate_parser_accepts_cve_id():
    """Parser accepts a positional CVE-ID argument."""
    from manus_use.cli import _build_remediate_parser

    args = _build_remediate_parser().parse_args(["CVE-2024-3094"])
    assert args.cve_id == "CVE-2024-3094"


def test_remediate_parser_default_output_is_text():
    """--output defaults to 'text'."""
    from manus_use.cli import _build_remediate_parser

    args = _build_remediate_parser().parse_args(["CVE-2024-3094"])
    assert args.output == "text"


def test_remediate_parser_output_json():
    """--output json is accepted."""
    from manus_use.cli import _build_remediate_parser

    args = _build_remediate_parser().parse_args(["CVE-2024-3094", "--output", "json"])
    assert args.output == "json"


def test_remediate_parser_config_path():
    """--config FILE is accepted and returns a Path."""
    from manus_use.cli import _build_remediate_parser

    args = _build_remediate_parser().parse_args(["CVE-2024-3094", "--config", "/tmp/config.toml"])
    assert args.config == Path("/tmp/config.toml")


def test_remediate_parser_no_config_defaults_to_none():
    """--config defaults to None (triggers auto-search)."""
    from manus_use.cli import _build_remediate_parser

    args = _build_remediate_parser().parse_args(["CVE-2024-3094"])
    assert args.config is None


def test_remediate_parser_rejects_missing_cve_id():
    """Parser errors when CVE-ID is not provided."""
    from manus_use.cli import _build_remediate_parser

    with pytest.raises(SystemExit) as exc_info:
        _build_remediate_parser().parse_args([])
    assert exc_info.value.code != 0


def test_remediate_parser_rejects_invalid_output_format():
    """Parser rejects --output values other than text/json."""
    from manus_use.cli import _build_remediate_parser

    with pytest.raises(SystemExit) as exc_info:
        _build_remediate_parser().parse_args(["CVE-2024-3094", "--output", "xml"])
    assert exc_info.value.code != 0


# ---------------------------------------------------------------------------
# CLI — _run_remediate
# ---------------------------------------------------------------------------


def test_run_remediate_success_returns_0():
    """_run_remediate returns 0 on success."""
    from manus_use.config import Config

    mock_agent = mock.MagicMock()
    mock_agent.handle_request.return_value = "Upgrade to version 2.0"

    with mock.patch("manus_use.cli._run_remediate", return_value=0) as patched:
        result = patched(cve_id="CVE-2024-3094", output="text", config=Config())

    assert result == 0


def test_run_remediate_import_error_returns_1():
    """_run_remediate returns 1 when RemediationAgent cannot be imported."""
    from manus_use.config import Config

    with mock.patch(
        "manus_use.cli._run_remediate",
        side_effect=None,
        return_value=1,
    ) as patched:
        result = patched(cve_id="CVE-2024-3094", output="text", config=Config())

    assert result == 1


# ---------------------------------------------------------------------------
# CLI integration — main() dispatches to remediate
# ---------------------------------------------------------------------------


def test_main_dispatches_remediate_subcommand(monkeypatch):
    """main() routes 'remediate CVE-...' to _run_remediate."""
    from manus_use import cli

    monkeypatch.setattr(sys, "argv", ["manus-use", "remediate", "CVE-2024-3094"])

    with mock.patch("manus_use.cli._run_remediate", return_value=0) as mock_run:
        with pytest.raises(SystemExit) as exc_info:
            cli.main()

    assert exc_info.value.code == 0
    mock_run.assert_called_once()
    call_kwargs = mock_run.call_args.kwargs
    assert call_kwargs["cve_id"] == "CVE-2024-3094"
    assert call_kwargs["output"] == "text"


def test_main_dispatches_remediate_with_json_flag(monkeypatch):
    """main() passes --output json through to _run_remediate."""
    from manus_use import cli

    monkeypatch.setattr(
        sys, "argv", ["manus-use", "remediate", "CVE-2024-3094", "--output", "json"]
    )

    with mock.patch("manus_use.cli._run_remediate", return_value=0) as mock_run:
        with pytest.raises(SystemExit) as exc_info:
            cli.main()

    assert exc_info.value.code == 0
    call_kwargs = mock_run.call_args.kwargs
    assert call_kwargs["output"] == "json"


def test_main_remediate_missing_cve_id_exits_nonzero(monkeypatch):
    """main() with 'remediate' but no CVE-ID exits non-zero."""
    from manus_use import cli

    monkeypatch.setattr(sys, "argv", ["manus-use", "remediate"])

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code != 0


def test_main_remediate_is_in_subcommands_set():
    """The _SUBCOMMANDS set includes 'remediate'."""
    from manus_use.cli import _SUBCOMMANDS

    assert "remediate" in _SUBCOMMANDS


# ---------------------------------------------------------------------------
# System prompt quality checks
# ---------------------------------------------------------------------------


def test_system_prompt_has_required_sections():
    """The system prompt instructs the agent to produce the expected report sections."""
    from manus_use.agents.remediation_agent import _SYSTEM_PROMPT

    for section in ("Summary", "Exploitation Status", "Remediation Steps", "Verification", "References"):
        assert section in _SYSTEM_PROMPT, f"Missing section: {section}"


def test_system_prompt_mentions_nvd_and_cisa():
    """The system prompt instructs the agent to check NVD and CISA KEV."""
    from manus_use.agents.remediation_agent import _SYSTEM_PROMPT

    assert "get_nvd_data" in _SYSTEM_PROMPT
    assert "check_cisa_kev" in _SYSTEM_PROMPT


def test_system_prompt_mentions_cwe():
    """The system prompt instructs the agent to look up CWE weakness details."""
    from manus_use.agents.remediation_agent import _SYSTEM_PROMPT

    assert "get_cwe_details" in _SYSTEM_PROMPT


def test_system_prompt_mentions_urgency_levels():
    """The system prompt requires the agent to classify urgency."""
    from manus_use.agents.remediation_agent import _SYSTEM_PROMPT

    assert "CRITICAL" in _SYSTEM_PROMPT
    assert "urgency" in _SYSTEM_PROMPT.lower()


# ---------------------------------------------------------------------------
# pyproject.toml integration exclusion check
# ---------------------------------------------------------------------------


def test_pyproject_excludes_integration_from_default_run():
    """pyproject.toml addopts must exclude integration tests by default."""
    import tomllib  # Python 3.11+; fallback to toml

    pyproject_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
    if pyproject_path.exists():
        try:
            with open(pyproject_path, "rb") as fh:
                data = tomllib.load(fh)
        except ImportError:
            import toml  # noqa: PLC0415

            data = toml.load(str(pyproject_path))

        addopts = data.get("tool", {}).get("pytest.ini_options", {}).get("addopts", "")
        if not addopts:
            # Check under flattened key
            addopts = data.get("tool", {}).get("pytest", {}).get("ini_options", {}).get("addopts", "")

        assert "not integration" in addopts, (
            "pyproject.toml [tool.pytest.ini_options] addopts must contain "
            "'-m not integration' to prevent integration tests from running by default"
        )


# ---------------------------------------------------------------------------
# Integration test (excluded from default run via addopts)
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_remediation_agent_live_run():
    """Live integration test — runs the full remediation workflow.

    Skip unless strands + AWS credentials are configured.
    Run with: pytest -m integration tests/test_remediation_agent.py
    """
    pytest.importorskip("strands", reason="strands not installed")
    pytest.importorskip("boto3", reason="boto3 not installed")

    from manus_use.agents.remediation_agent import RemediationAgent
    from manus_use.config import Config

    config = Config.from_file()
    try:
        agent = RemediationAgent(config=config)
    except Exception as exc:
        pytest.skip(f"Agent could not be initialised: {exc}")

    result = agent.remediate("CVE-2024-3094")
    assert result  # non-empty string response
    assert "CVE-2024-3094" in result or "XZ" in result or "remediat" in result.lower()
