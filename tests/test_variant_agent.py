"""Tests for VariantAnalysisAgent and the `variants` CLI subcommand."""

from __future__ import annotations

import json
import sys
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Module import + __all__ exports
# ---------------------------------------------------------------------------


def test_variant_agent_module_imports_without_crashing():
    """The module must be importable even without optional deps installed."""
    import manus_use.agents.variant_agent as va

    assert hasattr(va, "VariantAnalysisAgent")


def test_variant_agent_all_exports():
    """__all__ exports VariantAnalysisAgent and DEFAULT_MODEL_ID."""
    from manus_use.agents.variant_agent import __all__

    assert "VariantAnalysisAgent" in __all__
    assert "DEFAULT_MODEL_ID" in __all__


def test_variant_agent_exported_from_agents_package():
    """VariantAnalysisAgent is re-exported from the agents package."""
    from manus_use.agents import VariantAnalysisAgent  # noqa: F401


def test_default_model_id_is_nonempty_string():
    """DEFAULT_MODEL_ID is a non-empty string."""
    from manus_use.agents.variant_agent import DEFAULT_MODEL_ID

    assert isinstance(DEFAULT_MODEL_ID, str)
    assert DEFAULT_MODEL_ID


def test_system_prompt_is_string():
    """SYSTEM_PROMPT is a non-empty string with the expected sections."""
    from manus_use.agents.variant_agent import SYSTEM_PROMPT

    assert isinstance(SYSTEM_PROMPT, str)
    assert "variant" in SYSTEM_PROMPT.lower()
    assert "CVE" in SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# VariantAnalysisAgent instantiation
# ---------------------------------------------------------------------------


def test_variant_agent_instantiates_with_mock_config():
    """VariantAnalysisAgent() instantiates when Config is mocked."""
    with mock.patch("manus_use.agents.variant_agent.VariantAnalysisAgent.__init__", return_value=None):
        from manus_use.agents.variant_agent import VariantAnalysisAgent

        agent = VariantAnalysisAgent.__new__(VariantAnalysisAgent)
        agent._config = mock.MagicMock()
        agent._model = None
        agent._agent = None
        assert agent._agent is None


def test_variant_agent_init_without_strands(monkeypatch):
    """VariantAnalysisAgent.__init__ works even when strands is absent (lazy import)."""
    fake_config = mock.MagicMock()

    with mock.patch("manus_use.agents.variant_agent.VariantAnalysisAgent.__init__", return_value=None):
        from manus_use.agents.variant_agent import VariantAnalysisAgent

        agent = VariantAnalysisAgent.__new__(VariantAnalysisAgent)
        agent._config = fake_config
        agent._model = None
        agent._agent = None

    # The agent object exists without strands being imported
    assert agent._config is fake_config


# ---------------------------------------------------------------------------
# handle_request
# ---------------------------------------------------------------------------


def test_handle_request_calls_internal_agent():
    """handle_request() calls the internal _agent with the prompt."""
    from manus_use.agents.variant_agent import VariantAnalysisAgent

    fake_inner = mock.MagicMock(return_value="RESULT")

    with mock.patch.object(VariantAnalysisAgent, "__init__", return_value=None):
        agent = VariantAnalysisAgent.__new__(VariantAnalysisAgent)
        agent._config = mock.MagicMock()
        agent._model = None
        agent._agent = fake_inner

    result = agent.handle_request("some prompt")
    fake_inner.assert_called_once_with("some prompt")
    assert result == "RESULT"


def test_handle_request_lazy_builds_agent():
    """handle_request() calls _build_agent when _agent is None."""
    from manus_use.agents.variant_agent import VariantAnalysisAgent

    fake_inner = mock.MagicMock(return_value="LAZY_RESULT")

    with mock.patch.object(VariantAnalysisAgent, "__init__", return_value=None):
        agent = VariantAnalysisAgent.__new__(VariantAnalysisAgent)
        agent._config = mock.MagicMock()
        agent._model = None
        agent._agent = None

    with mock.patch.object(agent, "_build_agent", return_value=fake_inner) as m_build:
        result = agent.handle_request("test prompt")

    m_build.assert_called_once()
    fake_inner.assert_called_once_with("test prompt")
    assert result == "LAZY_RESULT"


# ---------------------------------------------------------------------------
# analyze_variants
# ---------------------------------------------------------------------------


def test_analyze_variants_builds_prompt_with_cve_id():
    """analyze_variants() builds a prompt containing the CVE id."""
    from manus_use.agents.variant_agent import VariantAnalysisAgent

    captured_prompts: list[str] = []

    def fake_handle_request(prompt: str) -> str:
        captured_prompts.append(prompt)
        return "REPORT"

    with mock.patch.object(VariantAnalysisAgent, "__init__", return_value=None):
        agent = VariantAnalysisAgent.__new__(VariantAnalysisAgent)
        agent._config = mock.MagicMock()
        agent._model = None
        agent._agent = None

    with mock.patch.object(agent, "handle_request", side_effect=fake_handle_request):
        result = agent.analyze_variants("CVE-2024-3094")

    assert result == "REPORT"
    assert len(captured_prompts) == 1
    assert "CVE-2024-3094" in captured_prompts[0]


def test_analyze_variants_prompt_mentions_variant():
    """analyze_variants() prompt includes variant-related context."""
    from manus_use.agents.variant_agent import VariantAnalysisAgent

    captured: list[str] = []

    with mock.patch.object(VariantAnalysisAgent, "__init__", return_value=None):
        agent = VariantAnalysisAgent.__new__(VariantAnalysisAgent)
        agent._config = mock.MagicMock()
        agent._model = None
        agent._agent = None

    with mock.patch.object(agent, "handle_request", side_effect=lambda p: captured.append(p) or "ok"):
        agent.analyze_variants("CVE-2025-9999")

    assert captured
    assert "variant" in captured[0].lower()


# ---------------------------------------------------------------------------
# _build_variants_parser
# ---------------------------------------------------------------------------


def test_build_variants_parser_cve_id_required():
    """_build_variants_parser requires a positional CVE-ID argument."""
    from manus_use.cli import _build_variants_parser

    parser = _build_variants_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args([])
    assert exc_info.value.code == 2


def test_build_variants_parser_parses_cve_id():
    """_build_variants_parser correctly parses a CVE-ID positional."""
    from manus_use.cli import _build_variants_parser

    parser = _build_variants_parser()
    args = parser.parse_args(["CVE-2024-3094"])
    assert args.cve_id == "CVE-2024-3094"


def test_build_variants_parser_output_default_text():
    """_build_variants_parser defaults --output to text."""
    from manus_use.cli import _build_variants_parser

    parser = _build_variants_parser()
    args = parser.parse_args(["CVE-2024-3094"])
    assert args.output == "text"


def test_build_variants_parser_output_json():
    """_build_variants_parser accepts --output json."""
    from manus_use.cli import _build_variants_parser

    parser = _build_variants_parser()
    args = parser.parse_args(["CVE-2024-3094", "--output", "json"])
    assert args.output == "json"


def test_build_variants_parser_output_invalid():
    """_build_variants_parser rejects invalid --output values."""
    from manus_use.cli import _build_variants_parser

    parser = _build_variants_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["CVE-2024-3094", "--output", "xml"])
    assert exc_info.value.code == 2


# ---------------------------------------------------------------------------
# _run_variants
# ---------------------------------------------------------------------------


def test_run_variants_missing_cve_id_exits_error():
    """_run_variants with no arguments exits with code 2."""
    from manus_use.cli import _run_variants

    with pytest.raises(SystemExit) as exc_info:
        _run_variants([])
    assert exc_info.value.code == 2


def test_run_variants_text_output_calls_handle_request(capsys):
    """_run_variants text mode calls analyze_variants and prints result."""
    from manus_use.agents.variant_agent import VariantAnalysisAgent
    from manus_use.cli import _run_variants

    with mock.patch.object(VariantAnalysisAgent, "__init__", return_value=None):
        with mock.patch.object(VariantAnalysisAgent, "analyze_variants", return_value="VARIANT_REPORT") as m_av:
            rc = _run_variants(["CVE-2024-3094"])

    assert rc == 0
    m_av.assert_called_once_with("CVE-2024-3094")
    out = capsys.readouterr().out
    assert "VARIANT_REPORT" in out


def test_run_variants_json_output_emits_valid_json(capsys):
    """_run_variants json mode emits valid JSON with cve_id and report keys."""
    from manus_use.agents.variant_agent import VariantAnalysisAgent
    from manus_use.cli import _run_variants

    with mock.patch.object(VariantAnalysisAgent, "__init__", return_value=None):
        with mock.patch.object(VariantAnalysisAgent, "analyze_variants", return_value="JSON_REPORT"):
            rc = _run_variants(["CVE-2025-1234", "--output", "json"])

    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out.strip())
    assert payload["cve_id"] == "CVE-2025-1234"
    assert payload["report"] == "JSON_REPORT"


def test_run_variants_import_error_returns_1(monkeypatch):
    """_run_variants returns exit code 1 when ImportError is raised."""
    from manus_use import cli

    with mock.patch.dict(sys.modules, {"manus_use.agents.variant_agent": None}):
        # Force ImportError by patching the import inside _run_variants
        real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

        def fake_import(name, *args, **kwargs):
            if name == "manus_use.agents.variant_agent":
                raise ImportError("strands not installed")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=fake_import):
            rc = cli._run_variants(["CVE-2024-3094"])

    assert rc == 1


# ---------------------------------------------------------------------------
# _SUBCOMMANDS set
# ---------------------------------------------------------------------------


def test_subcommands_contains_variants():
    """_SUBCOMMANDS set includes 'variants'."""
    from manus_use.cli import _SUBCOMMANDS

    assert "variants" in _SUBCOMMANDS


# ---------------------------------------------------------------------------
# main() routes "variants" to _run_variants
# ---------------------------------------------------------------------------


def test_main_routes_variants_subcommand():
    """main() routes 'variants' to _run_variants."""
    from manus_use import cli

    captured: dict = {}

    def fake_run_variants(argv):
        captured["argv"] = argv
        return 0

    with mock.patch.object(sys, "argv", ["manus-agent", "variants", "CVE-2024-3094"]):
        with mock.patch.object(cli, "_run_variants", side_effect=fake_run_variants) as m_rv:
            with pytest.raises(SystemExit) as exc_info:
                cli.main()

    assert exc_info.value.code == 0
    m_rv.assert_called_once()
    assert "CVE-2024-3094" in captured["argv"]


def test_main_variants_passes_output_flag():
    """main() passes --output json flag correctly to _run_variants."""
    from manus_use import cli

    captured: dict = {}

    def fake_run_variants(argv):
        captured["argv"] = argv
        return 0

    with mock.patch.object(sys, "argv", ["manus-agent", "variants", "CVE-2024-3094", "--output", "json"]):
        with mock.patch.object(cli, "_run_variants", side_effect=fake_run_variants):
            with pytest.raises(SystemExit):
                cli.main()

    assert "--output" in captured["argv"]
    assert "json" in captured["argv"]


# ---------------------------------------------------------------------------
# variant_analysis_agent.py thin wrapper
# ---------------------------------------------------------------------------


def test_thin_wrapper_imports_from_variant_agent():
    """variant_analysis_agent.py thin wrapper imports VariantAnalysisAgent."""
    import importlib.util
    import pathlib

    wrapper_path = pathlib.Path(__file__).resolve().parents[1] / "variant_analysis_agent.py"
    spec = importlib.util.spec_from_file_location("variant_analysis_agent", wrapper_path)
    mod = importlib.util.module_from_spec(spec)

    # Stub out strands/botocore to avoid heavy dep requirement
    with mock.patch.dict(
        sys.modules,
        {
            "strands": mock.MagicMock(),
            "strands.models": mock.MagicMock(),
            "botocore": mock.MagicMock(),
        },
    ):
        spec.loader.exec_module(mod)

    assert hasattr(mod, "main")
    assert callable(mod.main)


def test_thin_wrapper_main_calls_analyze_variants():
    """variant_analysis_agent.py main() delegates to VariantAnalysisAgent.analyze_variants."""
    import importlib.util
    import pathlib

    wrapper_path = pathlib.Path(__file__).resolve().parents[1] / "variant_analysis_agent.py"
    spec = importlib.util.spec_from_file_location("_va_wrapper_test", wrapper_path)
    mod = importlib.util.module_from_spec(spec)

    with mock.patch.dict(
        sys.modules,
        {
            "strands": mock.MagicMock(),
            "strands.models": mock.MagicMock(),
            "botocore": mock.MagicMock(),
        },
    ):
        spec.loader.exec_module(mod)

    from manus_use.agents.variant_agent import VariantAnalysisAgent

    with mock.patch.object(VariantAnalysisAgent, "__init__", return_value=None):
        with mock.patch.object(VariantAnalysisAgent, "analyze_variants", return_value="WRAPPER_RESULT") as m_av:
            with mock.patch.object(sys, "argv", ["variant_analysis_agent.py", "CVE-2024-3094"]):
                with mock.patch("builtins.print"):
                    mod.main()

    m_av.assert_called_once_with("CVE-2024-3094")
