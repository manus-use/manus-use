"""Tests for the Vulnerability Discovery agent and the `discover` CLI subcommand."""

import sys
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Module import / agent class
# ---------------------------------------------------------------------------


def test_vd_agent_module_imports_without_crashing():
    """The module must be importable even without optional deps installed."""
    import manus_use.agents.vd_agent as vd

    assert hasattr(vd, "VulnerabilityDiscoveryAgent")


def test_vd_agent_exported_from_agents_package():
    """VulnerabilityDiscoveryAgent is re-exported from the agents package."""
    from manus_use.agents import VulnerabilityDiscoveryAgent  # noqa: F401


def test_submission_model_fields():
    """Submission pydantic model has the expected fields."""
    from manus_use.agents.vd_agent import Submission

    s = Submission(total=10, total_with_high_epss=5, total_submitted=5)
    assert s.total == 10
    assert s.total_with_high_epss == 5
    assert s.total_submitted == 5
    assert s.error is None


def test_submission_model_with_error():
    """Submission model records error string when provided."""
    from manus_use.agents.vd_agent import Submission

    s = Submission(total=0, total_with_high_epss=0, total_submitted=0, error="timeout")
    assert s.error == "timeout"


def test_default_model_id_is_defined():
    """DEFAULT_MODEL_ID is a non-empty string."""
    from manus_use.agents.vd_agent import DEFAULT_MODEL_ID

    assert isinstance(DEFAULT_MODEL_ID, str)
    assert DEFAULT_MODEL_ID


# ---------------------------------------------------------------------------
# build_request static method
# ---------------------------------------------------------------------------


def test_build_request_default_since_is_four_weeks_ago():
    """`build_request` without `since` defaults to ~4 weeks back."""
    from manus_use.agents.vd_agent import DEFAULT_LOOKBACK_DAYS, VulnerabilityDiscoveryAgent

    request = VulnerabilityDiscoveryAgent.build_request()
    expected_start = datetime.now(tz=timezone.utc) - timedelta(days=DEFAULT_LOOKBACK_DAYS)
    expected_date = expected_start.strftime("%Y-%m-%d")
    assert expected_date in request


def test_build_request_respects_since_param():
    """`build_request` embeds the explicit `since` date."""
    from manus_use.agents.vd_agent import VulnerabilityDiscoveryAgent

    request = VulnerabilityDiscoveryAgent.build_request(since="2025-01-01")
    assert "2025-01-01" in request


def test_build_request_embeds_min_epss():
    """`build_request` embeds the `min_epss` value."""
    from manus_use.agents.vd_agent import VulnerabilityDiscoveryAgent

    request = VulnerabilityDiscoveryAgent.build_request(min_epss=0.7)
    assert "0.7" in request


def test_build_request_dry_run_mode():
    """`build_request(dry_run=True)` instructs the agent NOT to submit."""
    from manus_use.agents.vd_agent import VulnerabilityDiscoveryAgent

    request = VulnerabilityDiscoveryAgent.build_request(dry_run=True)
    assert "NOT" in request.upper() or "not submit" in request.lower() or "dry-run" in request.lower()


def test_build_request_normal_mode():
    """`build_request(dry_run=False)` instructs the agent to submit."""
    from manus_use.agents.vd_agent import VulnerabilityDiscoveryAgent

    request = VulnerabilityDiscoveryAgent.build_request(dry_run=False)
    assert "submit" in request.lower()


# ---------------------------------------------------------------------------
# CLI `discover` subcommand — parser
# ---------------------------------------------------------------------------


def test_discover_help_exits_zero():
    """`manus-use discover --help` prints help and exits 0."""
    from manus_use import cli

    parser = cli._build_discover_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--help"])
    assert exc_info.value.code == 0


def test_discover_defaults():
    """`manus-use discover` with no args has expected defaults."""
    from manus_use import cli

    parser = cli._build_discover_parser()
    args = parser.parse_args([])
    assert args.since is None
    assert args.min_epss == 0.5
    assert args.output == "text"
    assert args.dry_run is False


def test_discover_since_flag():
    """`--since` is accepted and parsed."""
    from manus_use import cli

    parser = cli._build_discover_parser()
    args = parser.parse_args(["--since", "2025-03-01"])
    assert args.since == "2025-03-01"


def test_discover_min_epss_flag():
    """`--min-epss` is parsed as float."""
    from manus_use import cli

    parser = cli._build_discover_parser()
    args = parser.parse_args(["--min-epss", "0.7"])
    assert args.min_epss == pytest.approx(0.7)


def test_discover_output_json_flag():
    """`--output json` is accepted."""
    from manus_use import cli

    parser = cli._build_discover_parser()
    args = parser.parse_args(["--output", "json"])
    assert args.output == "json"


def test_discover_dry_run_flag():
    """`--dry-run` sets the flag."""
    from manus_use import cli

    parser = cli._build_discover_parser()
    args = parser.parse_args(["--dry-run"])
    assert args.dry_run is True


def test_discover_registered_in_main():
    """`manus-use discover` routes to `_run_discover`, not the task runner."""
    from manus_use import cli

    captured = {}

    def fake_run_discover(*, since, min_epss, output, dry_run, config):
        captured.update(since=since, min_epss=min_epss, output=output, dry_run=dry_run)
        return 0

    argv = [
        "manus-use",
        "discover",
        "--since",
        "2025-06-01",
        "--min-epss",
        "0.8",
        "--output",
        "json",
        "--dry-run",
    ]
    with mock.patch.object(sys, "argv", argv):
        with mock.patch.object(cli, "_run_discover", side_effect=fake_run_discover):
            with mock.patch("manus_use.cli.Config") as m_cfg:
                m_cfg.from_file.return_value = mock.MagicMock()
                with pytest.raises(SystemExit) as exc_info:
                    cli.main()

    assert exc_info.value.code == 0
    assert captured["since"] == "2025-06-01"
    assert captured["min_epss"] == pytest.approx(0.8)
    assert captured["output"] == "json"
    assert captured["dry_run"] is True


# ---------------------------------------------------------------------------
# _run_discover — unit behaviour
# ---------------------------------------------------------------------------


def test_run_discover_calls_handle_request():
    """`_run_discover` invokes `handle_request` with a request string."""
    from manus_use import cli
    from manus_use.agents.vd_agent import VulnerabilityDiscoveryAgent

    with mock.patch.object(VulnerabilityDiscoveryAgent, "__init__", return_value=None):
        with mock.patch.object(VulnerabilityDiscoveryAgent, "handle_request", return_value="RESULTS") as m_handle:
            rc = cli._run_discover(
                since="2025-06-01",
                min_epss=0.5,
                output="text",
                dry_run=False,
                config=mock.MagicMock(),
            )

    assert rc == 0
    assert m_handle.call_count == 1
    sent = m_handle.call_args.args[0]
    assert "2025-06-01" in sent


def test_run_discover_min_epss_out_of_range():
    """`_run_discover` returns 1 when `min_epss` is outside [0.0, 1.0]."""
    from manus_use import cli

    rc = cli._run_discover(
        since=None,
        min_epss=1.5,
        output="text",
        dry_run=False,
        config=mock.MagicMock(),
    )
    assert rc == 1


def test_run_discover_output_json():
    """`_run_discover` with output=json invokes `print_json` rather than `print`."""
    import json

    from manus_use import cli
    from manus_use.agents.vd_agent import VulnerabilityDiscoveryAgent

    json_calls = []

    with mock.patch.object(VulnerabilityDiscoveryAgent, "__init__", return_value=None):
        with mock.patch.object(VulnerabilityDiscoveryAgent, "handle_request", return_value="RESULT"):
            with mock.patch.object(cli.console, "print_json", side_effect=json_calls.append):
                rc = cli._run_discover(
                    since="2025-06-01",
                    min_epss=0.5,
                    output="json",
                    dry_run=False,
                    config=mock.MagicMock(),
                )

    assert rc == 0
    assert json_calls, "print_json was not called"
    data = json.loads(json_calls[0])
    assert "since" in data
    assert data["since"] == "2025-06-01"
    assert "result" in data


def test_run_discover_dry_run_request_contains_dry_run():
    """`_run_discover(dry_run=True)` forwards a dry-run request to the agent."""
    from manus_use import cli
    from manus_use.agents.vd_agent import VulnerabilityDiscoveryAgent

    requests_seen = []

    with mock.patch.object(VulnerabilityDiscoveryAgent, "__init__", return_value=None):
        with mock.patch.object(
            VulnerabilityDiscoveryAgent,
            "handle_request",
            side_effect=lambda r: requests_seen.append(r) or "RESULTS",
        ):
            cli._run_discover(
                since=None,
                min_epss=0.5,
                output="text",
                dry_run=True,
                config=mock.MagicMock(),
            )

    assert requests_seen
    req = requests_seen[0]
    # The request should mention dry-run / not submitting
    assert "NOT" in req.upper() or "not submit" in req.lower() or "dry-run" in req.lower()


# ---------------------------------------------------------------------------
# Integration test (skipped unless --run-integration is passed)
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_vd_agent_discover_integration():
    """Live integration test — runs the full discovery workflow.

    Skip unless the environment has strands + AWS credentials configured.
    Run with: pytest -m integration tests/test_vd_agent.py
    """
    pytest.importorskip("strands", reason="strands not installed")
    pytest.importorskip("boto3", reason="boto3 not installed")

    from manus_use.agents.vd_agent import VulnerabilityDiscoveryAgent
    from manus_use.config import Config

    config = Config.from_file()
    try:
        agent = VulnerabilityDiscoveryAgent(config=config)
    except Exception as exc:
        pytest.skip(f"Agent could not be initialised (likely missing MCP server): {exc}")

    result = agent.discover(since=None, min_epss=0.5, dry_run=True)
    assert result  # non-empty string response
