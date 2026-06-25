"""Tests for the Vulnerability Intelligence agent and the `analyze` CLI subcommand."""

import sys
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Module import / agent class
# ---------------------------------------------------------------------------


def test_vi_agent_module_imports_without_crashing():
    """The module must be importable even without optional deps installed."""
    import manus_use.agents.vi_agent as vi

    assert hasattr(vi, "VulnerabilityIntelligenceAgent")


def test_vi_agent_exported_from_agents_package():
    """VulnerabilityIntelligenceAgent is re-exported from the agents package."""
    from manus_use.agents import VulnerabilityIntelligenceAgent  # noqa: F401


def test_build_request_includes_cve_and_no_verify_by_default():
    """build_request embeds the CVE id and disables verification by default."""
    from manus_use.agents.vi_agent import VulnerabilityIntelligenceAgent

    request = VulnerabilityIntelligenceAgent.build_request("CVE-2025-6554")

    assert "CVE-2025-6554" in request
    assert "NOT" in request  # "Do NOT perform exploit verification."


def test_build_request_enables_verification():
    """build_request mentions the verify-exploit skill when verify=True."""
    from manus_use.agents.vi_agent import VulnerabilityIntelligenceAgent

    request = VulnerabilityIntelligenceAgent.build_request("CVE-2024-3094", verify=True)

    assert "CVE-2024-3094" in request
    assert "verify-exploit" in request


# ---------------------------------------------------------------------------
# CLI `analyze` subcommand
# ---------------------------------------------------------------------------


def test_analyze_help_exits_zero():
    """`manus-use analyze --help` prints help and exits 0."""
    from manus_use import cli

    parser = cli._build_analyze_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--help"])
    assert exc_info.value.code == 0


def test_analyze_missing_cve_is_error():
    """`manus-use analyze` with no CVE produces an argparse error (exit 2)."""
    from manus_use import cli

    parser = cli._build_analyze_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args([])
    assert exc_info.value.code == 2


def test_analyze_registered_in_main():
    """`manus-use analyze CVE-...` routes to _run_analyze, not the task runner."""
    from manus_use import cli

    captured = {}

    def fake_run_analyze(*, cve_id, verify, output, config):
        captured.update(cve_id=cve_id, verify=verify, output=output)
        return 0

    argv = ["manus-use", "analyze", "CVE-2025-6554", "--verify", "--output", "json"]
    with mock.patch.object(sys, "argv", argv):
        with mock.patch.object(cli, "_run_analyze", side_effect=fake_run_analyze):
            with mock.patch("manus_use.cli.Config") as m_cfg:
                m_cfg.from_file.return_value = mock.MagicMock()
                with pytest.raises(SystemExit) as exc_info:
                    cli.main()

    assert exc_info.value.code == 0
    assert captured["cve_id"] == "CVE-2025-6554"
    assert captured["verify"] is True
    assert captured["output"] == "json"


def test_run_analyze_calls_handle_request_with_cve():
    """_run_analyze invokes handle_request with a request string containing the CVE."""
    from manus_use import cli
    from manus_use.agents.vi_agent import VulnerabilityIntelligenceAgent

    with mock.patch.object(VulnerabilityIntelligenceAgent, "__init__", return_value=None):
        with mock.patch.object(VulnerabilityIntelligenceAgent, "handle_request", return_value="REPORT") as m_handle:
            rc = cli._run_analyze(
                cve_id="CVE-2025-6554",
                verify=False,
                output="text",
                config=mock.MagicMock(),
            )

    assert rc == 0
    assert m_handle.call_count == 1
    sent = m_handle.call_args.args[0]
    assert "CVE-2025-6554" in sent
