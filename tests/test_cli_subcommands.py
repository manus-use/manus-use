"""Comprehensive test suite for CLI subcommands.

Tests every code-path in the CLI subcommand functions that previously had
zero coverage: analyze, discover, remediate, variants, epss-trend,
patch-diff, compare, exploit-complexity, poc-search, blast-radius,
and their argument parsers.

All HTTP calls are mocked — no real network traffic.
"""

from __future__ import annotations

import json
import sys
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Parser tests — validate argparse configuration
# ---------------------------------------------------------------------------


class TestBuildAnalyzeParser:
    """Tests for _build_analyze_parser."""

    def _parser(self):
        from manus_agent.cli import _build_analyze_parser

        return _build_analyze_parser()

    def test_basic_parse(self):
        args = self._parser().parse_args(["CVE-2024-3094"])
        assert args.cve_id == "CVE-2024-3094"
        assert args.verify is False
        assert args.output == "text"
        assert args.config is None

    def test_verify_flag(self):
        args = self._parser().parse_args(["CVE-2024-3094", "--verify"])
        assert args.verify is True

    def test_output_json(self):
        args = self._parser().parse_args(["CVE-2024-3094", "--output", "json"])
        assert args.output == "json"

    def test_output_lark(self):
        args = self._parser().parse_args(["CVE-2024-3094", "--output", "lark"])
        assert args.output == "lark"

    def test_config_path(self, tmp_path):
        cfg = tmp_path / "cfg.toml"
        cfg.touch()
        args = self._parser().parse_args(["CVE-2024-3094", "--config", str(cfg)])
        assert args.config == cfg

    def test_missing_cve_id_exits(self):
        with pytest.raises(SystemExit):
            self._parser().parse_args([])

    def test_invalid_output_exits(self):
        with pytest.raises(SystemExit):
            self._parser().parse_args(["CVE-2024-3094", "--output", "xml"])


class TestBuildDiscoverParser:
    """Tests for _build_discover_parser."""

    def _parser(self):
        from manus_agent.cli import _build_discover_parser

        return _build_discover_parser()

    def test_defaults(self):
        args = self._parser().parse_args([])
        assert args.since is None
        assert args.min_epss == 0.5
        assert args.output == "text"
        assert args.dry_run is False

    def test_since_flag(self):
        args = self._parser().parse_args(["--since", "2025-06-01"])
        assert args.since == "2025-06-01"

    def test_min_epss_flag(self):
        args = self._parser().parse_args(["--min-epss", "0.5"])
        assert args.min_epss == 0.5

    def test_output_json(self):
        args = self._parser().parse_args(["--output", "json"])
        assert args.output == "json"

    def test_dry_run_flag(self):
        args = self._parser().parse_args(["--dry-run"])
        assert args.dry_run is True


class TestBuildRemediateParser:
    """Tests for _build_remediate_parser."""

    def _parser(self):
        from manus_agent.cli import _build_remediate_parser

        return _build_remediate_parser()

    def test_basic_parse(self):
        args = self._parser().parse_args(["CVE-2024-3094"])
        assert args.cve_id == "CVE-2024-3094"
        assert args.output == "text"

    def test_output_json(self):
        args = self._parser().parse_args(["CVE-2024-3094", "--output", "json"])
        assert args.output == "json"

    def test_missing_cve_id_exits(self):
        with pytest.raises(SystemExit):
            self._parser().parse_args([])


class TestBuildVariantsParser:
    """Tests for _build_variants_parser."""

    def _parser(self):
        from manus_agent.cli import _build_variants_parser

        return _build_variants_parser()

    def test_basic_parse(self):
        args = self._parser().parse_args(["CVE-2024-3094"])
        assert args.cve_id == "CVE-2024-3094"
        assert args.output == "text"

    def test_output_json(self):
        args = self._parser().parse_args(["CVE-2024-3094", "--output", "json"])
        assert args.output == "json"


class TestBuildEpssTrendParser:
    """Tests for _build_epss_trend_parser."""

    def _parser(self):
        from manus_agent.cli import _build_epss_trend_parser

        return _build_epss_trend_parser()

    def test_defaults(self):
        args = self._parser().parse_args(["CVE-2024-3094"])
        assert args.cve_id == "CVE-2024-3094"
        assert args.days == 30
        assert args.output == "text"

    def test_days_flag(self):
        args = self._parser().parse_args(["CVE-2024-3094", "--days", "90"])
        assert args.days == 90


class TestBuildPatchDiffParser:
    """Tests for _build_patch_diff_parser."""

    def _parser(self):
        from manus_agent.cli import _build_patch_diff_parser

        return _build_patch_diff_parser()

    def test_basic_parse(self):
        args = self._parser().parse_args(["CVE-2024-3094"])
        assert args.cve_id == "CVE-2024-3094"
        assert args.output == "text"


class TestBuildCompareParser:
    """Tests for _build_compare_parser."""

    def _parser(self):
        from manus_agent.cli import _build_compare_parser

        return _build_compare_parser()

    def test_basic_parse(self):
        args = self._parser().parse_args(["CVE-2024-3094", "CVE-2021-44228"])
        assert args.cve_id_a == "CVE-2024-3094"
        assert args.cve_id_b == "CVE-2021-44228"
        assert args.output == "text"

    def test_missing_second_cve_exits(self):
        with pytest.raises(SystemExit):
            self._parser().parse_args(["CVE-2024-3094"])


class TestBuildExploitComplexityParser:
    """Tests for _build_exploit_complexity_parser."""

    def _parser(self):
        from manus_agent.cli import _build_exploit_complexity_parser

        return _build_exploit_complexity_parser()

    def test_basic_parse(self):
        args = self._parser().parse_args(["CVE-2024-3094"])
        assert args.cve_id == "CVE-2024-3094"
        assert args.output == "text"


class TestBuildPocSearchParser:
    """Tests for _build_poc_search_parser."""

    def _parser(self):
        from manus_agent.cli import _build_poc_search_parser

        return _build_poc_search_parser()

    def test_basic_parse(self):
        args = self._parser().parse_args(["CVE-2024-3094"])
        assert args.cve_id == "CVE-2024-3094"
        assert args.output == "text"
        assert args.sources == ""

    def test_sources_flag(self):
        args = self._parser().parse_args(["CVE-2024-3094", "--sources", "github,nvd"])
        assert args.sources == "github,nvd"


class TestBuildBlastRadiusParser:
    """Tests for _build_blast_radius_parser."""

    def _parser(self):
        from manus_agent.cli import _build_blast_radius_parser

        return _build_blast_radius_parser()

    def test_basic_parse(self):
        args = self._parser().parse_args(["requests@2.28.0"])
        assert args.spec == "requests@2.28.0"
        assert args.max_packages == 10
        assert args.output == "text"

    def test_max_packages_flag(self):
        args = self._parser().parse_args(["CVE-2021-44228", "--max-packages", "5"])
        assert args.max_packages == 5


# ---------------------------------------------------------------------------
# _run_analyze tests
# ---------------------------------------------------------------------------


class TestRunAnalyze:
    """Tests for _run_analyze function."""

    def _run(self, **kwargs):
        from manus_agent.cli import _run_analyze

        defaults = {
            "cve_id": "CVE-2024-3094",
            "verify": False,
            "output": "text",
            "config": mock.MagicMock(),
        }
        defaults.update(kwargs)
        return _run_analyze(**defaults)

    def test_import_failure_returns_1(self):
        # Remove cached module so the lazy import inside _run_analyze fails
        saved = sys.modules.pop("manus_agent.agents", None)
        try:
            with mock.patch(
                "builtins.__import__",
                side_effect=_selective_import_error("manus_agent.agents"),
            ):
                result = self._run()
                assert result == 1
        finally:
            if saved is not None:
                sys.modules["manus_agent.agents"] = saved

    def test_agent_init_failure_returns_1(self):
        mock_module = mock.MagicMock()
        mock_module.VulnerabilityIntelligenceAgent.side_effect = RuntimeError("init boom")
        with mock.patch.dict(sys.modules, {"manus_agent.agents": mock_module}):
            result = self._run()
            assert result == 1

    def test_agent_run_failure_returns_1(self):
        mock_agent = mock.MagicMock()
        mock_agent.handle_request.side_effect = RuntimeError("run boom")
        mock_agent.build_request.return_value = "request"
        mock_module = mock.MagicMock()
        mock_module.VulnerabilityIntelligenceAgent.return_value = mock_agent
        with mock.patch.dict(sys.modules, {"manus_agent.agents": mock_module}):
            result = self._run()
            assert result == 1

    def test_text_output_success(self, capsys):
        mock_agent = mock.MagicMock()
        mock_agent.handle_request.return_value = "Report text here"
        mock_agent.build_request.return_value = "request"
        mock_module = mock.MagicMock()
        mock_module.VulnerabilityIntelligenceAgent.return_value = mock_agent
        with mock.patch.dict(sys.modules, {"manus_agent.agents": mock_module}):
            result = self._run(output="text")
            assert result == 0

    def test_json_output_success(self, capsys):
        mock_agent = mock.MagicMock()
        mock_agent.handle_request.return_value = "Report text here"
        mock_agent.build_request.return_value = "request"
        mock_module = mock.MagicMock()
        mock_module.VulnerabilityIntelligenceAgent.return_value = mock_agent
        with mock.patch.dict(sys.modules, {"manus_agent.agents": mock_module}):
            result = self._run(output="json")
            assert result == 0

    def test_lark_output_success(self):
        mock_agent = mock.MagicMock()
        mock_agent.handle_request.return_value = "Report text"
        mock_agent.build_request.return_value = "request"
        mock_module = mock.MagicMock()
        mock_module.VulnerabilityIntelligenceAgent.return_value = mock_agent
        with mock.patch.dict(sys.modules, {"manus_agent.agents": mock_module}):
            result = self._run(output="lark")
            assert result == 0

    def test_verify_flag_passed_to_agent(self):
        mock_agent = mock.MagicMock()
        mock_agent.handle_request.return_value = "Report text"
        mock_agent.build_request.return_value = "request"
        mock_module = mock.MagicMock()
        mock_module.VulnerabilityIntelligenceAgent.return_value = mock_agent
        with mock.patch.dict(sys.modules, {"manus_agent.agents": mock_module}):
            result = self._run(verify=True)
            assert result == 0
            mock_agent.build_request.assert_called_once_with("CVE-2024-3094", verify=True)


# ---------------------------------------------------------------------------
# _run_discover tests
# ---------------------------------------------------------------------------


class TestRunDiscover:
    """Tests for _run_discover function."""

    def _run(self, **kwargs):
        from manus_agent.cli import _run_discover

        defaults = {
            "since": None,
            "min_epss": 0.5,
            "output": "text",
            "dry_run": False,
            "config": mock.MagicMock(),
        }
        defaults.update(kwargs)
        return _run_discover(**defaults)

    def test_import_failure_returns_1(self):
        # Remove cached module so the lazy import inside _run_discover fails
        saved = sys.modules.pop("manus_agent.agents", None)
        try:
            with mock.patch(
                "builtins.__import__",
                side_effect=_selective_import_error("manus_agent.agents"),
            ):
                result = self._run()
                assert result == 1
        finally:
            if saved is not None:
                sys.modules["manus_agent.agents"] = saved

    def test_invalid_min_epss_too_high(self):
        result = self._run(min_epss=1.5)
        assert result == 1

    def test_invalid_min_epss_negative(self):
        result = self._run(min_epss=-0.1)
        assert result == 1

    def test_agent_init_failure_returns_1(self):
        mock_module = mock.MagicMock()
        mock_module.VulnerabilityDiscoveryAgent.side_effect = RuntimeError("init boom")
        with mock.patch.dict(sys.modules, {"manus_agent.agents": mock_module}):
            result = self._run()
            assert result == 1

    def test_agent_run_failure_returns_1(self):
        mock_agent = mock.MagicMock()
        mock_agent.handle_request.side_effect = RuntimeError("run boom")
        mock_cls = mock.MagicMock(return_value=mock_agent)
        mock_cls.build_request.return_value = "request"
        mock_module = mock.MagicMock()
        mock_module.VulnerabilityDiscoveryAgent = mock_cls
        with mock.patch.dict(sys.modules, {"manus_agent.agents": mock_module}):
            result = self._run()
            assert result == 1

    def test_text_output_success(self):
        mock_agent = mock.MagicMock()
        mock_agent.handle_request.return_value = "Discovered CVEs"
        mock_cls = mock.MagicMock(return_value=mock_agent)
        mock_cls.build_request.return_value = "request"
        mock_module = mock.MagicMock()
        mock_module.VulnerabilityDiscoveryAgent = mock_cls
        with mock.patch.dict(sys.modules, {"manus_agent.agents": mock_module}):
            result = self._run()
            assert result == 0

    def test_json_output_success(self):
        mock_agent = mock.MagicMock()
        mock_agent.handle_request.return_value = "Discovered CVEs"
        mock_cls = mock.MagicMock(return_value=mock_agent)
        mock_cls.build_request.return_value = "request"
        mock_module = mock.MagicMock()
        mock_module.VulnerabilityDiscoveryAgent = mock_cls
        with mock.patch.dict(sys.modules, {"manus_agent.agents": mock_module}):
            result = self._run(output="json")
            assert result == 0

    def test_dry_run_flag_passed(self):
        mock_agent = mock.MagicMock()
        mock_agent.handle_request.return_value = "Dry run results"
        mock_cls = mock.MagicMock(return_value=mock_agent)
        mock_cls.build_request.return_value = "request"
        mock_module = mock.MagicMock()
        mock_module.VulnerabilityDiscoveryAgent = mock_cls
        with mock.patch.dict(sys.modules, {"manus_agent.agents": mock_module}):
            result = self._run(dry_run=True)
            assert result == 0
            mock_cls.build_request.assert_called_once_with(since=None, min_epss=0.5, dry_run=True)

    def test_since_flag_passed(self):
        mock_agent = mock.MagicMock()
        mock_agent.handle_request.return_value = "Results"
        mock_cls = mock.MagicMock(return_value=mock_agent)
        mock_cls.build_request.return_value = "request"
        mock_module = mock.MagicMock()
        mock_module.VulnerabilityDiscoveryAgent = mock_cls
        with mock.patch.dict(sys.modules, {"manus_agent.agents": mock_module}):
            result = self._run(since="2025-06-01")
            assert result == 0


# ---------------------------------------------------------------------------
# _run_remediate tests
# ---------------------------------------------------------------------------


class TestRunRemediate:
    """Tests for _run_remediate function."""

    def _run(self, **kwargs):
        from manus_agent.cli import _run_remediate

        defaults = {
            "cve_id": "CVE-2024-3094",
            "output": "text",
            "config": mock.MagicMock(),
        }
        defaults.update(kwargs)
        return _run_remediate(**defaults)

    def test_import_failure_returns_1(self):
        saved = sys.modules.pop("manus_agent.agents", None)
        try:
            with mock.patch(
                "builtins.__import__",
                side_effect=_selective_import_error("manus_agent.agents"),
            ):
                result = self._run()
                assert result == 1
        finally:
            if saved is not None:
                sys.modules["manus_agent.agents"] = saved

    def test_agent_init_failure_returns_1(self):
        mock_module = mock.MagicMock()
        mock_module.RemediationAgent.side_effect = RuntimeError("init boom")
        with mock.patch.dict(sys.modules, {"manus_agent.agents": mock_module}):
            result = self._run()
            assert result == 1

    def test_agent_run_failure_returns_1(self):
        mock_agent = mock.MagicMock()
        mock_agent.handle_request.side_effect = RuntimeError("run boom")
        mock_cls = mock.MagicMock(return_value=mock_agent)
        mock_cls.build_request.return_value = "request"
        mock_module = mock.MagicMock()
        mock_module.RemediationAgent = mock_cls
        with mock.patch.dict(sys.modules, {"manus_agent.agents": mock_module}):
            result = self._run()
            assert result == 1

    def test_text_output_success(self):
        mock_agent = mock.MagicMock()
        mock_agent.handle_request.return_value = "Remediation steps"
        mock_cls = mock.MagicMock(return_value=mock_agent)
        mock_cls.build_request.return_value = "request"
        mock_module = mock.MagicMock()
        mock_module.RemediationAgent = mock_cls
        with mock.patch.dict(sys.modules, {"manus_agent.agents": mock_module}):
            result = self._run()
            assert result == 0

    def test_json_output_success(self):
        mock_agent = mock.MagicMock()
        mock_agent.handle_request.return_value = "Remediation steps"
        mock_cls = mock.MagicMock(return_value=mock_agent)
        mock_cls.build_request.return_value = "request"
        mock_module = mock.MagicMock()
        mock_module.RemediationAgent = mock_cls
        with mock.patch.dict(sys.modules, {"manus_agent.agents": mock_module}):
            result = self._run(output="json")
            assert result == 0


# ---------------------------------------------------------------------------
# _run_variants tests
# ---------------------------------------------------------------------------


class TestRunVariants:
    """Tests for _run_variants function."""

    def _run(self, argv):
        from manus_agent.cli import _run_variants

        return _run_variants(argv)

    def test_import_failure_returns_1(self, capsys):
        with mock.patch(
            "builtins.__import__",
            side_effect=_selective_import_error("manus_agent.agents.variant_agent"),
        ):
            result = self._run(["CVE-2024-3094"])
            assert result == 1
        captured = capsys.readouterr()
        assert "missing dependencies" in captured.err

    def test_text_output_success(self, capsys):
        mock_agent = mock.MagicMock()
        mock_agent.analyze_variants.return_value = "Variant analysis results"
        with mock.patch(
            "manus_agent.agents.variant_agent.VariantAnalysisAgent",
            return_value=mock_agent,
        ):
            result = self._run(["CVE-2024-3094"])
            assert result == 0
        captured = capsys.readouterr()
        assert "Variant analysis results" in captured.out

    def test_json_output_success(self, capsys):
        mock_agent = mock.MagicMock()
        mock_agent.analyze_variants.return_value = "Variant analysis"
        with mock.patch(
            "manus_agent.agents.variant_agent.VariantAnalysisAgent",
            return_value=mock_agent,
        ):
            result = self._run(["CVE-2024-3094", "--output", "json"])
            assert result == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["cve_id"] == "CVE-2024-3094"
        assert parsed["report"] == "Variant analysis"


# ---------------------------------------------------------------------------
# _run_epss_trend tests
# ---------------------------------------------------------------------------


class TestRunEpssTrend:
    """Tests for _run_epss_trend function."""

    def _run(self, argv):
        from manus_agent.cli import _run_epss_trend

        return _run_epss_trend(argv)

    def _mock_fetch_and_analyse(self):
        """Return standard mocks for _fetch_epss_time_series and _analyse_series."""
        raw_response = {
            "data": [
                {
                    "cve": "CVE-2024-3094",
                    "date": "2025-01-15",
                    "epss": "0.95",
                    "percentile": "0.99",
                    "time-series": [
                        {"date": "2025-01-14", "epss": "0.90", "percentile": "0.98"},
                        {"date": "2025-01-13", "epss": "0.85", "percentile": "0.97"},
                    ],
                }
            ]
        }
        analysis = {
            "spike_detected": True,
            "current_epss": 0.95,
            "current_percentile": 0.99,
            "oldest_epss": 0.85,
            "oldest_date": "2025-01-13",
            "latest_date": "2025-01-15",
            "trend": "rising",
            "max_7d_jump": 0.10,
            "max_7d_jump_end_date": "2025-01-15",
            "points": [
                {"date": "2025-01-13", "epss": 0.85, "percentile": 0.97},
                {"date": "2025-01-14", "epss": 0.90, "percentile": 0.98},
                {"date": "2025-01-15", "epss": 0.95, "percentile": 0.99},
            ],
        }
        return raw_response, analysis

    def test_import_failure_returns_1(self, capsys):
        with mock.patch(
            "builtins.__import__",
            side_effect=_selective_import_error("manus_agent.tools.get_epss_trend"),
        ):
            result = self._run(["CVE-2024-3094"])
            assert result == 1

    def test_fetch_failure_returns_1(self, capsys):
        with mock.patch(
            "manus_agent.tools.get_epss_trend._fetch_epss_time_series",
            side_effect=RuntimeError("API down"),
        ):
            result = self._run(["CVE-2024-3094"])
            assert result == 1
        captured = capsys.readouterr()
        assert "EPSS API request failed" in captured.err

    def test_empty_data_returns_1(self, capsys):
        with mock.patch(
            "manus_agent.tools.get_epss_trend._fetch_epss_time_series",
            return_value={"data": []},
        ):
            result = self._run(["CVE-2024-3094"])
            assert result == 1
        captured = capsys.readouterr()
        assert "No EPSS data found" in captured.err

    def test_text_output_with_spike(self, capsys):
        raw, analysis = self._mock_fetch_and_analyse()
        with (
            mock.patch(
                "manus_agent.tools.get_epss_trend._fetch_epss_time_series",
                return_value=raw,
            ),
            mock.patch(
                "manus_agent.tools.get_epss_trend._analyse_series",
                return_value=analysis,
            ),
        ):
            result = self._run(["CVE-2024-3094"])
            assert result == 0
        captured = capsys.readouterr()
        assert "SPIKE DETECTED" in captured.out
        assert "CVE-2024-3094" in captured.out

    def test_text_output_no_spike(self, capsys):
        raw, analysis = self._mock_fetch_and_analyse()
        analysis["spike_detected"] = False
        with (
            mock.patch(
                "manus_agent.tools.get_epss_trend._fetch_epss_time_series",
                return_value=raw,
            ),
            mock.patch(
                "manus_agent.tools.get_epss_trend._analyse_series",
                return_value=analysis,
            ),
        ):
            result = self._run(["CVE-2024-3094"])
            assert result == 0
        captured = capsys.readouterr()
        assert "No significant spike" in captured.out

    def test_json_output(self, capsys):
        raw, analysis = self._mock_fetch_and_analyse()
        with (
            mock.patch(
                "manus_agent.tools.get_epss_trend._fetch_epss_time_series",
                return_value=raw,
            ),
            mock.patch(
                "manus_agent.tools.get_epss_trend._analyse_series",
                return_value=analysis,
            ),
        ):
            result = self._run(["CVE-2024-3094", "--output", "json"])
            assert result == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["cve_id"] == "CVE-2024-3094"
        assert parsed["analysis"]["spike_detected"] is True

    def test_current_point_dedup(self, capsys):
        """Current data point should not duplicate an existing time-series entry."""
        raw = {
            "data": [
                {
                    "cve": "CVE-2024-3094",
                    "date": "2025-01-15",
                    "epss": "0.95",
                    "percentile": "0.99",
                    "time-series": [
                        {"date": "2025-01-15", "epss": "0.95", "percentile": "0.99"},
                    ],
                }
            ]
        }
        analysis = {
            "spike_detected": False,
            "current_epss": 0.95,
            "current_percentile": 0.99,
            "oldest_epss": 0.95,
            "oldest_date": "2025-01-15",
            "latest_date": "2025-01-15",
            "trend": "stable",
            "max_7d_jump": 0.0,
            "max_7d_jump_end_date": None,
            "points": [{"date": "2025-01-15", "epss": 0.95, "percentile": 0.99}],
        }
        with (
            mock.patch(
                "manus_agent.tools.get_epss_trend._fetch_epss_time_series",
                return_value=raw,
            ),
            mock.patch(
                "manus_agent.tools.get_epss_trend._analyse_series",
                return_value=analysis,
            ) as mock_analyse,
        ):
            result = self._run(["CVE-2024-3094"])
            assert result == 0
            # The time_series passed to _analyse_series should NOT duplicate the current point
            call_args = mock_analyse.call_args[0][0]
            dates = [p["date"] for p in call_args]
            assert dates.count("2025-01-15") == 1

    def test_days_flag_passed(self):
        raw = {
            "data": [
                {"cve": "CVE-2024-3094", "date": "2025-01-15", "epss": "0.5", "percentile": "0.5", "time-series": []}
            ]
        }
        analysis = {
            "spike_detected": False,
            "current_epss": 0.5,
            "current_percentile": 0.5,
            "oldest_epss": 0.5,
            "oldest_date": "2025-01-15",
            "latest_date": "2025-01-15",
            "trend": "stable",
            "max_7d_jump": 0.0,
            "max_7d_jump_end_date": None,
            "points": [{"date": "2025-01-15", "epss": 0.5, "percentile": 0.5}],
        }
        with (
            mock.patch(
                "manus_agent.tools.get_epss_trend._fetch_epss_time_series",
                return_value=raw,
            ) as mock_fetch,
            mock.patch(
                "manus_agent.tools.get_epss_trend._analyse_series",
                return_value=analysis,
            ),
        ):
            self._run(["CVE-2024-3094", "--days", "90"])
            mock_fetch.assert_called_once_with("CVE-2024-3094", 90)

    def test_empty_points_text_output(self, capsys):
        """Text output with empty points list should still succeed."""
        raw, analysis = self._mock_fetch_and_analyse()
        analysis["points"] = []
        with (
            mock.patch(
                "manus_agent.tools.get_epss_trend._fetch_epss_time_series",
                return_value=raw,
            ),
            mock.patch(
                "manus_agent.tools.get_epss_trend._analyse_series",
                return_value=analysis,
            ),
        ):
            result = self._run(["CVE-2024-3094"])
            assert result == 0


# ---------------------------------------------------------------------------
# _run_patch_diff tests
# ---------------------------------------------------------------------------


class TestRunPatchDiff:
    """Tests for _run_patch_diff function."""

    def _run(self, argv):
        from manus_agent.cli import _run_patch_diff

        return _run_patch_diff(argv)

    def test_import_failure_returns_1(self, capsys):
        with mock.patch(
            "builtins.__import__",
            side_effect=_selective_import_error("manus_agent.tools.get_patch_diff"),
        ):
            result = self._run(["CVE-2024-3094"])
            assert result == 1

    def test_text_output_not_found(self, capsys):
        payload = {
            "message": "No commits found for CVE-2024-3094",
            "not_found": True,
            "commit_summaries": [],
        }
        with mock.patch(
            "manus_agent.tools.get_patch_diff.fetch_and_summarise",
            return_value=payload,
        ):
            result = self._run(["CVE-2024-3094"])
            assert result == 0
        captured = capsys.readouterr()
        assert "No commits found" in captured.out

    def test_text_output_with_commits(self, capsys):
        payload = {
            "message": "Found 1 commit for CVE-2024-3094",
            "not_found": False,
            "commit_summaries": [
                {
                    "commit_url": "https://github.com/example/commit/abc123",
                    "files_changed": ["src/main.c", "src/utils.c"],
                    "functions_touched": ["parse_input", "validate"],
                    "added_lines": 15,
                    "removed_lines": 8,
                    "primary_bug_class": "buffer-overflow",
                    "matched_bug_classes": ["buffer-overflow", "memory-safety"],
                    "reproduction_condition_hints": ["Send oversized input", "Use special chars"],
                },
            ],
        }
        with mock.patch(
            "manus_agent.tools.get_patch_diff.fetch_and_summarise",
            return_value=payload,
        ):
            result = self._run(["CVE-2024-3094"])
            assert result == 0
        captured = capsys.readouterr()
        assert "src/main.c" in captured.out
        assert "buffer-overflow" in captured.out
        assert "Send oversized input" in captured.out
        assert "memory-safety" in captured.out

    def test_json_output(self, capsys):
        payload = {
            "message": "Found 1 commit",
            "not_found": False,
            "commit_summaries": [],
        }
        with mock.patch(
            "manus_agent.tools.get_patch_diff.fetch_and_summarise",
            return_value=payload,
        ):
            result = self._run(["CVE-2024-3094", "--output", "json"])
            assert result == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["not_found"] is False

    def test_single_bug_class_no_all_line(self, capsys):
        """When matched_bug_classes has only one entry, 'All bug classes' line should not appear."""
        payload = {
            "message": "Found 1 commit",
            "not_found": False,
            "commit_summaries": [
                {
                    "commit_url": "https://github.com/example/commit/abc",
                    "files_changed": ["a.c"],
                    "functions_touched": [],
                    "added_lines": 1,
                    "removed_lines": 1,
                    "primary_bug_class": "xss",
                    "matched_bug_classes": ["xss"],
                    "reproduction_condition_hints": [],
                },
            ],
        }
        with mock.patch(
            "manus_agent.tools.get_patch_diff.fetch_and_summarise",
            return_value=payload,
        ):
            result = self._run(["CVE-2024-3094"])
            assert result == 0
        captured = capsys.readouterr()
        assert "All bug classes" not in captured.out


# ---------------------------------------------------------------------------
# _run_compare tests
# ---------------------------------------------------------------------------


class TestRunCompare:
    """Tests for _run_compare function."""

    def _run(self, argv):
        from manus_agent.cli import _run_compare

        return _run_compare(argv)

    def test_invalid_cve_id_returns_1(self, capsys):
        result = self._run(["NOT-A-CVE", "CVE-2021-44228"])
        assert result == 1
        captured = capsys.readouterr()
        assert "Invalid CVE ID" in captured.err

    def test_second_invalid_cve_id_returns_1(self, capsys):
        result = self._run(["CVE-2024-3094", "BAD-ID"])
        assert result == 1
        captured = capsys.readouterr()
        assert "Invalid CVE ID" in captured.err

    def test_text_output_success(self, capsys):
        with (
            mock.patch(
                "manus_agent.tools.compare_cves._build_cve_profile",
                return_value={"cve_id": "CVE-2024-3094", "cvss": 9.8},
            ),
            mock.patch(
                "manus_agent.tools.compare_cves._fetch_kev",
                return_value={"in_kev": False},
            ),
            mock.patch(
                "manus_agent.tools.compare_cves._build_comparison",
                return_value={"winner": "CVE-2024-3094"},
            ),
            mock.patch(
                "manus_agent.tools.compare_cves._render_text",
                return_value="CVE-2024-3094 is higher priority",
            ),
        ):
            result = self._run(["CVE-2024-3094", "CVE-2021-44228"])
            assert result == 0
        captured = capsys.readouterr()
        assert "CVE-2024-3094 is higher priority" in captured.out

    def test_json_output_success(self, capsys):
        comparison = {"winner": "CVE-2024-3094", "reason": "Higher CVSS"}
        with (
            mock.patch(
                "manus_agent.tools.compare_cves._build_cve_profile",
                return_value={"cve_id": "CVE-2024-3094"},
            ),
            mock.patch(
                "manus_agent.tools.compare_cves._fetch_kev",
                return_value={"in_kev": False},
            ),
            mock.patch(
                "manus_agent.tools.compare_cves._build_comparison",
                return_value=comparison,
            ),
            mock.patch(
                "manus_agent.tools.compare_cves._render_text",
                return_value="text",
            ),
        ):
            result = self._run(["CVE-2024-3094", "CVE-2021-44228", "--output", "json"])
            assert result == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["winner"] == "CVE-2024-3094"


# ---------------------------------------------------------------------------
# _run_exploit_complexity tests
# ---------------------------------------------------------------------------


class TestRunExploitComplexity:
    """Tests for _run_exploit_complexity function."""

    def _run(self, argv):
        from manus_agent.cli import _run_exploit_complexity

        return _run_exploit_complexity(argv)

    def test_invalid_cve_id_exits(self):
        with pytest.raises(SystemExit):
            self._run(["NOT-A-CVE"])

    def test_text_output_success(self, capsys):
        result_data = {"cve_id": "CVE-2024-3094", "score": 2, "label": "easy"}
        with (
            mock.patch(
                "manus_agent.tools.score_exploit_complexity._run_scoring",
                return_value=result_data,
            ),
            mock.patch(
                "manus_agent.tools.score_exploit_complexity._render_text",
                return_value="CVE-2024-3094: easy (2/5)",
            ),
        ):
            result = self._run(["CVE-2024-3094"])
            assert result == 0
        captured = capsys.readouterr()
        assert "easy" in captured.out

    def test_json_output_success(self, capsys):
        result_data = {"cve_id": "CVE-2024-3094", "score": 2, "label": "easy"}
        with (
            mock.patch(
                "manus_agent.tools.score_exploit_complexity._run_scoring",
                return_value=result_data,
            ),
            mock.patch(
                "manus_agent.tools.score_exploit_complexity._render_text",
                return_value="text",
            ),
        ):
            result = self._run(["CVE-2024-3094", "--output", "json"])
            assert result == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["score"] == 2


# ---------------------------------------------------------------------------
# _run_poc_search tests
# ---------------------------------------------------------------------------


class TestRunPocSearch:
    """Tests for _run_poc_search function."""

    def _run(self, argv):
        from manus_agent.cli import _run_poc_search

        return _run_poc_search(argv)

    def test_invalid_cve_id_exits(self):
        with pytest.raises(SystemExit):
            self._run(["NOT-A-CVE"])

    def test_json_output_success(self, capsys):
        mock_result = {
            "total_found": 2,
            "exploited_in_wild": False,
            "recent_activity": False,
            "sources_checked": ["github", "nvd"],
            "sources_failed": [],
            "results": [
                {"source": "github", "title": "PoC 1", "url": "https://example.com/poc1"},
            ],
        }
        with mock.patch(
            "manus_agent.tools.search_poc_sources.aggregate_poc_results",
            return_value=mock_result,
        ):
            result = self._run(["CVE-2024-3094", "--output", "json"])
            assert result == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["total_found"] == 2

    def test_text_output_no_results(self, capsys):
        mock_result = {
            "total_found": 0,
            "exploited_in_wild": False,
            "recent_activity": False,
            "sources_checked": ["github"],
            "sources_failed": [],
            "results": [],
        }
        with mock.patch(
            "manus_agent.tools.search_poc_sources.aggregate_poc_results",
            return_value=mock_result,
        ):
            result = self._run(["CVE-2024-3094"])
            assert result == 0
        captured = capsys.readouterr()
        assert "No PoC results found" in captured.out

    def test_text_output_with_results(self, capsys):
        mock_result = {
            "total_found": 1,
            "exploited_in_wild": False,
            "recent_activity": True,
            "sources_checked": ["github", "nvd"],
            "sources_failed": ["exploitdb"],
            "results": [
                {
                    "source": "github",
                    "exploited_in_wild": False,
                    "title": "PoC for CVE-2024-3094",
                    "published": "2025-01-15",
                    "url": "https://github.com/example/poc",
                },
            ],
        }
        with mock.patch(
            "manus_agent.tools.search_poc_sources.aggregate_poc_results",
            return_value=mock_result,
        ):
            result = self._run(["CVE-2024-3094"])
            assert result == 0
        captured = capsys.readouterr()
        assert "Results found" in captured.out
        assert "github" in captured.out
        assert "Recent activity" in captured.out
        assert "exploitdb" in captured.out  # failed source

    def test_text_output_exploited_in_wild(self, capsys):
        mock_result = {
            "total_found": 1,
            "exploited_in_wild": True,
            "recent_activity": False,
            "sources_checked": ["vulncheck_kev"],
            "sources_failed": [],
            "results": [
                {
                    "source": "vulncheck_kev",
                    "exploited_in_wild": True,
                    "title": "KEV entry",
                    "published": "2025-01-15",
                    "url": "https://vulncheck.com/kev/CVE-2024-3094",
                },
            ],
        }
        with mock.patch(
            "manus_agent.tools.search_poc_sources.aggregate_poc_results",
            return_value=mock_result,
        ):
            result = self._run(["CVE-2024-3094"])
            assert result == 0
        captured = capsys.readouterr()
        assert "EXPLOITED IN WILD" in captured.out

    def test_sources_filter_passed(self):
        mock_result = {
            "total_found": 0,
            "exploited_in_wild": False,
            "recent_activity": False,
            "sources_checked": ["github"],
            "sources_failed": [],
            "results": [],
        }
        with mock.patch(
            "manus_agent.tools.search_poc_sources.aggregate_poc_results",
            return_value=mock_result,
        ) as mock_agg:
            self._run(["CVE-2024-3094", "--sources", "github,nvd"])
            mock_agg.assert_called_once_with("CVE-2024-3094", ["github", "nvd"])

    def test_empty_sources_passes_none(self):
        mock_result = {
            "total_found": 0,
            "exploited_in_wild": False,
            "recent_activity": False,
            "sources_checked": [],
            "sources_failed": [],
            "results": [],
        }
        with mock.patch(
            "manus_agent.tools.search_poc_sources.aggregate_poc_results",
            return_value=mock_result,
        ) as mock_agg:
            self._run(["CVE-2024-3094"])
            mock_agg.assert_called_once_with("CVE-2024-3094", None)


# ---------------------------------------------------------------------------
# _run_blast_radius tests
# ---------------------------------------------------------------------------


class TestRunBlastRadius:
    """Tests for _run_blast_radius function."""

    def _run(self, argv):
        from manus_agent.cli import _run_blast_radius

        return _run_blast_radius(argv)

    def test_invalid_spec_returns_1(self, capsys):
        with mock.patch(
            "manus_agent.tools.get_dependency_blast_radius._parse_input",
            side_effect=ValueError("bad spec"),
        ):
            result = self._run(["@@@invalid"])
            assert result == 1
        captured = capsys.readouterr()
        assert "bad spec" in captured.err

    def test_cve_no_packages_found(self, capsys):
        with (
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._parse_input",
                return_value={"kind": "cve", "cve_id": "CVE-2024-9999"},
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_nvd_affected",
                return_value=[],
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_osv_affected",
                return_value=[],
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_ghsa_affected",
                return_value=[],
            ),
        ):
            result = self._run(["CVE-2024-9999"])
            assert result == 1
        captured = capsys.readouterr()
        assert "No affected package records" in captured.out

    def test_cve_json_output(self, capsys):
        packages = [
            {"name": "requests", "ecosystem": "pypi", "version_range": "<2.32.0", "source": "osv"},
        ]
        enriched_stats = {
            "package_name": "requests",
            "ecosystem": "pypi",
            "weekly_downloads": 50000000,
            "monthly_downloads": 200000000,
            "dependent_packages_count": 150000,
            "latest_version": "2.32.3",
            "description": "HTTP library",
            "full_id": None,
        }
        with (
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._parse_input",
                return_value={"kind": "cve", "cve_id": "CVE-2024-3094"},
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_nvd_affected",
                return_value=[],
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_osv_affected",
                return_value=packages,
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_ghsa_affected",
                return_value=[],
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._enrich_package",
                return_value=enriched_stats,
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._blast_score",
                return_value="CRITICAL",
            ),
        ):
            result = self._run(["CVE-2024-3094", "--output", "json"])
            assert result == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["cve_id"] == "CVE-2024-3094"
        assert parsed["summary"]["total_packages"] == 1
        assert parsed["packages"][0]["blast_radius"] == "CRITICAL"

    def test_cve_text_output(self, capsys):
        packages = [
            {"name": "requests", "ecosystem": "pypi", "version_range": "<2.32.0", "source": "osv"},
        ]
        enriched_stats = {
            "package_name": "requests",
            "name": "requests",
            "ecosystem": "pypi",
            "weekly_downloads": 50000000,
            "monthly_downloads": 200000000,
            "dependent_packages_count": 150000,
            "latest_version": "2.32.3",
            "description": "HTTP library for Python",
            "full_id": None,
        }
        with (
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._parse_input",
                return_value={"kind": "cve", "cve_id": "CVE-2024-3094"},
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_nvd_affected",
                return_value=[],
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_osv_affected",
                return_value=packages,
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_ghsa_affected",
                return_value=[],
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._enrich_package",
                return_value=enriched_stats,
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._blast_score",
                return_value="CRITICAL",
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._ECOSYSTEM_LABEL",
                {"pypi": "PyPI"},
            ),
        ):
            result = self._run(["CVE-2024-3094"])
            assert result == 0
        captured = capsys.readouterr()
        assert "Dependency Blast Radius" in captured.out
        assert "requests" in captured.out
        assert "CRITICAL" in captured.out

    def test_direct_package_spec(self, capsys):
        enriched_stats = {
            "package_name": "lodash",
            "name": "lodash",
            "ecosystem": "npm",
            "weekly_downloads": 40000000,
            "monthly_downloads": None,
            "dependent_packages_count": 200000,
            "latest_version": "4.17.21",
            "description": "Lodash modular utilities",
            "full_id": None,
        }
        with (
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._parse_input",
                return_value={"kind": "package", "name": "lodash", "ecosystem": "npm", "version": "4.17.20"},
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._enrich_package",
                return_value=enriched_stats,
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._blast_score",
                return_value="HIGH",
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._ECOSYSTEM_LABEL",
                {"npm": "npm"},
            ),
        ):
            result = self._run(["npm:lodash@4.17.20", "--output", "json"])
            assert result == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["cve_id"] is None
        assert parsed["packages"][0]["blast_radius"] == "HIGH"

    def test_dedup_across_sources(self, capsys):
        """Packages from multiple sources with the same name+ecosystem should be deduped."""
        osv_pkgs = [
            {"name": "requests", "ecosystem": "pypi", "version_range": "<2.32.0", "source": "osv"},
        ]
        ghsa_pkgs = [
            {"name": "requests", "ecosystem": "pypi", "version_range": "<2.32.0", "source": "ghsa"},
        ]
        enriched_stats = {
            "package_name": "requests",
            "name": "requests",
            "ecosystem": "pypi",
            "weekly_downloads": 50000000,
            "monthly_downloads": None,
            "dependent_packages_count": 150000,
            "latest_version": "2.32.3",
            "description": "HTTP library",
            "full_id": None,
        }
        with (
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._parse_input",
                return_value={"kind": "cve", "cve_id": "CVE-2024-3094"},
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_nvd_affected",
                return_value=[],
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_osv_affected",
                return_value=osv_pkgs,
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._fetch_ghsa_affected",
                return_value=ghsa_pkgs,
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._enrich_package",
                return_value=enriched_stats,
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._blast_score",
                return_value="CRITICAL",
            ),
        ):
            result = self._run(["CVE-2024-3094", "--output", "json"])
            assert result == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        # Should be deduped to 1 package
        assert parsed["summary"]["total_packages"] == 1

    def test_maven_full_id_shown_in_text(self, capsys):
        enriched_stats = {
            "package_name": "log4j-core",
            "name": "log4j-core",
            "ecosystem": "maven",
            "weekly_downloads": None,
            "monthly_downloads": None,
            "dependent_packages_count": None,
            "latest_version": "2.23.1",
            "description": "Apache Log4j Core",
            "full_id": "org.apache.logging.log4j:log4j-core",
        }
        with (
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._parse_input",
                return_value={"kind": "package", "name": "log4j-core", "ecosystem": "maven", "version": "2.14.0"},
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._enrich_package",
                return_value=enriched_stats,
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._blast_score",
                return_value="CRITICAL",
            ),
            mock.patch(
                "manus_agent.tools.get_dependency_blast_radius._ECOSYSTEM_LABEL",
                {"maven": "Maven Central"},
            ),
        ):
            result = self._run(["maven:log4j-core@2.14.0"])
            assert result == 0
        captured = capsys.readouterr()
        assert "org.apache.logging.log4j:log4j-core" in captured.out


# ---------------------------------------------------------------------------
# main() dispatch tests — verify subcommands route correctly
# ---------------------------------------------------------------------------


class TestMainDispatch:
    """Tests that main() dispatches to the correct subcommand handlers."""

    def test_analyze_dispatch(self):
        with (
            mock.patch("manus_agent.cli._build_analyze_parser") as mock_parser,
            mock.patch("manus_agent.cli._run_analyze", return_value=0),
            mock.patch("manus_agent.cli.Config") as mock_config_cls,
        ):
            mock_args = mock.MagicMock()
            mock_args.cve_id = "CVE-2024-3094"
            mock_args.verify = False
            mock_args.output = "text"
            mock_args.config = None
            mock_parser.return_value.parse_args.return_value = mock_args
            mock_config_cls.from_file.return_value = mock.MagicMock()

            with mock.patch("sys.argv", ["manus-agent", "analyze", "CVE-2024-3094"]):
                with pytest.raises(SystemExit) as exc_info:
                    from manus_agent.cli import main

                    main()
                assert exc_info.value.code == 0

    def test_discover_dispatch(self):
        with (
            mock.patch("manus_agent.cli._build_discover_parser") as mock_parser,
            mock.patch("manus_agent.cli._run_discover", return_value=0),
            mock.patch("manus_agent.cli.Config") as mock_config_cls,
        ):
            mock_args = mock.MagicMock()
            mock_args.since = None
            mock_args.min_epss = 0.7
            mock_args.output = "text"
            mock_args.dry_run = False
            mock_args.config = None
            mock_parser.return_value.parse_args.return_value = mock_args
            mock_config_cls.from_file.return_value = mock.MagicMock()

            with mock.patch("sys.argv", ["manus-agent", "discover"]):
                with pytest.raises(SystemExit) as exc_info:
                    from manus_agent.cli import main

                    main()
                assert exc_info.value.code == 0

    def test_remediate_dispatch(self):
        with (
            mock.patch("manus_agent.cli._build_remediate_parser") as mock_parser,
            mock.patch("manus_agent.cli._run_remediate", return_value=0),
            mock.patch("manus_agent.cli.Config") as mock_config_cls,
        ):
            mock_args = mock.MagicMock()
            mock_args.cve_id = "CVE-2024-3094"
            mock_args.output = "text"
            mock_args.config = None
            mock_parser.return_value.parse_args.return_value = mock_args
            mock_config_cls.from_file.return_value = mock.MagicMock()

            with mock.patch("sys.argv", ["manus-agent", "remediate", "CVE-2024-3094"]):
                with pytest.raises(SystemExit) as exc_info:
                    from manus_agent.cli import main

                    main()
                assert exc_info.value.code == 0

    def test_variants_dispatch(self):
        with mock.patch("manus_agent.cli._run_variants", return_value=0) as mock_run:
            with mock.patch("sys.argv", ["manus-agent", "variants", "CVE-2024-3094"]):
                with pytest.raises(SystemExit) as exc_info:
                    from manus_agent.cli import main

                    main()
                assert exc_info.value.code == 0
            mock_run.assert_called_once_with(["CVE-2024-3094"])

    def test_epss_trend_dispatch(self):
        with mock.patch("manus_agent.cli._run_epss_trend", return_value=0) as mock_run:
            with mock.patch("sys.argv", ["manus-agent", "epss-trend", "CVE-2024-3094"]):
                with pytest.raises(SystemExit) as exc_info:
                    from manus_agent.cli import main

                    main()
                assert exc_info.value.code == 0
            mock_run.assert_called_once_with(["CVE-2024-3094"])

    def test_patch_diff_dispatch(self):
        with mock.patch("manus_agent.cli._run_patch_diff", return_value=0) as mock_run:
            with mock.patch("sys.argv", ["manus-agent", "patch-diff", "CVE-2024-3094"]):
                with pytest.raises(SystemExit) as exc_info:
                    from manus_agent.cli import main

                    main()
                assert exc_info.value.code == 0
            mock_run.assert_called_once_with(["CVE-2024-3094"])

    def test_compare_dispatch(self):
        with mock.patch("manus_agent.cli._run_compare", return_value=0) as mock_run:
            with mock.patch("sys.argv", ["manus-agent", "compare", "CVE-2024-3094", "CVE-2021-44228"]):
                with pytest.raises(SystemExit) as exc_info:
                    from manus_agent.cli import main

                    main()
                assert exc_info.value.code == 0
            mock_run.assert_called_once_with(["CVE-2024-3094", "CVE-2021-44228"])

    def test_exploit_complexity_dispatch(self):
        with mock.patch("manus_agent.cli._run_exploit_complexity", return_value=0) as mock_run:
            with mock.patch("sys.argv", ["manus-agent", "exploit-complexity", "CVE-2024-3094"]):
                with pytest.raises(SystemExit) as exc_info:
                    from manus_agent.cli import main

                    main()
                assert exc_info.value.code == 0
            mock_run.assert_called_once_with(["CVE-2024-3094"])

    def test_poc_search_dispatch(self):
        with mock.patch("manus_agent.cli._run_poc_search", return_value=0) as mock_run:
            with mock.patch("sys.argv", ["manus-agent", "poc-search", "CVE-2024-3094"]):
                with pytest.raises(SystemExit) as exc_info:
                    from manus_agent.cli import main

                    main()
                assert exc_info.value.code == 0
            mock_run.assert_called_once_with(["CVE-2024-3094"])

    def test_blast_radius_dispatch(self):
        with mock.patch("manus_agent.cli._run_blast_radius", return_value=0) as mock_run:
            with mock.patch("sys.argv", ["manus-agent", "blast-radius", "requests@2.28.0"]):
                with pytest.raises(SystemExit) as exc_info:
                    from manus_agent.cli import main

                    main()
                assert exc_info.value.code == 0
            mock_run.assert_called_once_with(["requests@2.28.0"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REAL_IMPORT = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__


def _selective_import_error(blocked_module: str):
    """Return an __import__ side-effect that blocks one specific module."""

    def _import(name, *args, **kwargs):
        if name == blocked_module or name.startswith(blocked_module + "."):
            raise ImportError(f"Mocked import failure for {name}")
        return _REAL_IMPORT(name, *args, **kwargs)

    return _import
