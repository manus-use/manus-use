"""Tests for AgentConfig model_id/aws_region fields and VariantAnalysisAgent config wiring.

This test suite verifies:
1. AgentConfig has the new model_id and aws_region fields with correct defaults.
2. Config.from_file() correctly parses [agent] sections including the new fields.
3. VariantAnalysisAgent._build_agent() uses the config fields (not getattr fallbacks).
4. Dead CLI modules (cli_v2, cli_enhanced) have been removed.
"""

from __future__ import annotations

import sys
from unittest import mock

# ---------------------------------------------------------------------------
# AgentConfig field defaults
# ---------------------------------------------------------------------------


def test_agent_config_model_id_default_is_none():
    """AgentConfig.model_id defaults to None when not specified."""
    from manus_agent.config import AgentConfig

    cfg = AgentConfig()
    assert cfg.model_id is None


def test_agent_config_aws_region_default_is_none():
    """AgentConfig.aws_region defaults to None when not specified."""
    from manus_agent.config import AgentConfig

    cfg = AgentConfig()
    assert cfg.aws_region is None


def test_agent_config_context_manager_default():
    """AgentConfig.context_manager defaults to 'auto'."""
    from manus_agent.config import AgentConfig

    cfg = AgentConfig()
    assert cfg.context_manager == "auto"


def test_agent_config_accepts_model_id():
    """AgentConfig accepts an explicit model_id."""
    from manus_agent.config import AgentConfig

    cfg = AgentConfig(model_id="us.anthropic.claude-opus-4-20250514-v1:0")
    assert cfg.model_id == "us.anthropic.claude-opus-4-20250514-v1:0"


def test_agent_config_accepts_aws_region():
    """AgentConfig accepts an explicit aws_region."""
    from manus_agent.config import AgentConfig

    cfg = AgentConfig(aws_region="eu-west-1")
    assert cfg.aws_region == "eu-west-1"


def test_agent_config_all_fields_together():
    """AgentConfig accepts all three fields simultaneously."""
    from manus_agent.config import AgentConfig

    cfg = AgentConfig(
        context_manager="agentic",
        model_id="us.anthropic.claude-3-5-sonnet-20241022-v2:0",
        aws_region="ap-southeast-1",
    )
    assert cfg.context_manager == "agentic"
    assert cfg.model_id == "us.anthropic.claude-3-5-sonnet-20241022-v2:0"
    assert cfg.aws_region == "ap-southeast-1"


# ---------------------------------------------------------------------------
# Config.from_file() with [agent] section in TOML
# ---------------------------------------------------------------------------


def test_config_from_file_agent_model_id(tmp_path):
    """Config.from_file() reads [agent].model_id from a TOML config file."""
    config_file = tmp_path / "config.toml"
    config_file.write_text('[agent]\nmodel_id = "us.anthropic.claude-opus-4-20250514-v1:0"\n')
    from manus_agent.config import Config

    cfg = Config.from_file(config_file)
    assert cfg.agent.model_id == "us.anthropic.claude-opus-4-20250514-v1:0"


def test_config_from_file_agent_aws_region(tmp_path):
    """Config.from_file() reads [agent].aws_region from a TOML config file."""
    config_file = tmp_path / "config.toml"
    config_file.write_text('[agent]\naws_region = "eu-central-1"\n')
    from manus_agent.config import Config

    cfg = Config.from_file(config_file)
    assert cfg.agent.aws_region == "eu-central-1"


def test_config_from_file_agent_full_section(tmp_path):
    """Config.from_file() reads all [agent] fields together."""
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        "[agent]\n"
        'context_manager = "agentic"\n'
        'model_id = "us.anthropic.claude-3-5-haiku-20241022-v1:0"\n'
        'aws_region = "us-west-2"\n'
    )
    from manus_agent.config import Config

    cfg = Config.from_file(config_file)
    assert cfg.agent.context_manager == "agentic"
    assert cfg.agent.model_id == "us.anthropic.claude-3-5-haiku-20241022-v1:0"
    assert cfg.agent.aws_region == "us-west-2"


def test_config_from_file_agent_defaults_when_absent(tmp_path):
    """Config.from_file() uses AgentConfig defaults when [agent] section is absent."""
    config_file = tmp_path / "config.toml"
    config_file.write_text('[llm]\nprovider = "openai"\n')
    from manus_agent.config import Config

    cfg = Config.from_file(config_file)
    assert cfg.agent.model_id is None
    assert cfg.agent.aws_region is None
    assert cfg.agent.context_manager == "auto"


def test_config_from_file_agent_partial_section(tmp_path):
    """Config.from_file() handles partial [agent] sections (only one field set)."""
    config_file = tmp_path / "config.toml"
    config_file.write_text('[agent]\naws_region = "ap-northeast-1"\n')
    from manus_agent.config import Config

    cfg = Config.from_file(config_file)
    assert cfg.agent.aws_region == "ap-northeast-1"
    assert cfg.agent.model_id is None  # absent → default None
    assert cfg.agent.context_manager == "auto"  # absent → default "auto"


# ---------------------------------------------------------------------------
# Helpers for VariantAnalysisAgent tests
# BedrockModel is imported inside a deferred function, so we patch via sys.modules.
# ---------------------------------------------------------------------------


def _make_fake_strands_models(captured: dict):
    """Build a fake strands.models module whose BedrockModel records call args."""
    fake_instance = mock.MagicMock()

    def fake_bedrock_model(model_id, region_name, max_tokens):
        captured["model_id"] = model_id
        captured["region_name"] = region_name
        return fake_instance

    fake_mod = mock.MagicMock()
    fake_mod.BedrockModel = fake_bedrock_model
    return fake_mod


def _make_fake_strands_agent():
    """Build a fake strands module whose Agent records its constructor kwargs."""
    call_kw: dict = {}

    class FakeAgent:
        def __init__(self, **kwargs):
            call_kw.update(kwargs)

    fake_strands = mock.MagicMock()
    fake_strands.Agent = FakeAgent
    return fake_strands, call_kw


def _reload_variant_agent():
    """Force a fresh import of variant_agent from the current sys.modules."""
    for key in list(sys.modules):
        if "manus_agent.agents.variant_agent" in key:
            del sys.modules[key]
    from manus_agent.agents.variant_agent import VariantAnalysisAgent

    return VariantAnalysisAgent


# ---------------------------------------------------------------------------
# VariantAnalysisAgent uses AgentConfig fields (not getattr fallbacks)
# ---------------------------------------------------------------------------


def test_variant_agent_uses_config_model_id():
    """VariantAnalysisAgent._build_agent() picks up model_id from config.agent."""
    from manus_agent.config import AgentConfig, Config

    cfg = Config()
    cfg.agent = AgentConfig(model_id="test-model-override", aws_region="eu-west-1")

    captured: dict = {}
    fake_models = _make_fake_strands_models(captured)
    fake_strands, _ = _make_fake_strands_agent()

    with mock.patch.dict(
        sys.modules,
        {
            "botocore": mock.MagicMock(),
            "strands": fake_strands,
            "strands.models": fake_models,
        },
    ):
        agent_cls = _reload_variant_agent()
        agent = agent_cls(config=cfg)
        agent._build_agent()

    assert captured.get("model_id") == "test-model-override"
    assert captured.get("region_name") == "eu-west-1"


def test_variant_agent_falls_back_to_default_model_id_when_not_set():
    """VariantAnalysisAgent._build_agent() uses DEFAULT_MODEL_ID when config.agent.model_id is None."""
    from manus_agent.config import AgentConfig, Config

    cfg = Config()
    cfg.agent = AgentConfig()  # model_id=None, aws_region=None

    captured: dict = {}
    fake_models = _make_fake_strands_models(captured)
    fake_strands, _ = _make_fake_strands_agent()

    with mock.patch.dict(
        sys.modules,
        {
            "botocore": mock.MagicMock(),
            "strands": fake_strands,
            "strands.models": fake_models,
        },
    ):
        agent_cls = _reload_variant_agent()
        from manus_agent.agents.variant_agent import DEFAULT_MODEL_ID

        agent = agent_cls(config=cfg)
        agent._build_agent()

    assert captured.get("model_id") == DEFAULT_MODEL_ID
    assert captured.get("region_name") == "us-east-1"


def test_variant_agent_falls_back_to_default_region_when_not_set():
    """VariantAnalysisAgent falls back to us-east-1 when config.agent.aws_region is None."""
    from manus_agent.config import AgentConfig, Config

    cfg = Config()
    cfg.agent = AgentConfig(model_id="some-model", aws_region=None)

    captured: dict = {}
    fake_models = _make_fake_strands_models(captured)
    fake_strands, _ = _make_fake_strands_agent()

    with mock.patch.dict(
        sys.modules,
        {
            "botocore": mock.MagicMock(),
            "strands": fake_strands,
            "strands.models": fake_models,
        },
    ):
        agent_cls = _reload_variant_agent()
        agent = agent_cls(config=cfg)
        agent._build_agent()

    assert captured.get("region_name") == "us-east-1"


def test_variant_agent_injected_model_skips_bedrock_resolution():
    """VariantAnalysisAgent skips BedrockModel when a model is injected directly."""
    injected_model = mock.MagicMock()

    captured: dict = {}
    fake_models = _make_fake_strands_models(captured)
    fake_strands, call_kw = _make_fake_strands_agent()

    with mock.patch.dict(
        sys.modules,
        {
            "botocore": mock.MagicMock(),
            "strands": fake_strands,
            "strands.models": fake_models,
        },
    ):
        agent_cls = _reload_variant_agent()
        agent = agent_cls(model=injected_model)
        agent._build_agent()

    # BedrockModel was never called when a model is injected
    assert "model_id" not in captured, "BedrockModel should not have been called with an injected model"
    # The injected model was passed to Agent
    assert call_kw.get("model") is injected_model


# ---------------------------------------------------------------------------
# Dead CLI modules are gone
# ---------------------------------------------------------------------------


def test_cli_v2_removed():
    """manus_agent.cli_v2 must not exist — it was dead code."""
    import pathlib

    src_root = pathlib.Path(__file__).resolve().parents[1] / "src" / "manus_agent"
    cli_v2_path = src_root / "cli_v2.py"
    assert not cli_v2_path.exists(), f"cli_v2.py still exists at {cli_v2_path}"


def test_cli_enhanced_removed():
    """manus_agent.cli_enhanced must not exist — it was dead code."""
    import pathlib

    src_root = pathlib.Path(__file__).resolve().parents[1] / "src" / "manus_agent"
    cli_enhanced_path = src_root / "cli_enhanced.py"
    assert not cli_enhanced_path.exists(), f"cli_enhanced.py still exists at {cli_enhanced_path}"


def test_pyproject_no_dead_entry_points():
    """pyproject.toml must not expose manus-use-v2 or manus-use-enhanced entry points."""
    import pathlib

    pyproject_path = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"
    text = pyproject_path.read_text(encoding="utf-8")
    assert "manus-use-v2" not in text, "manus-use-v2 entry point should have been removed"
    assert "manus-use-enhanced" not in text, "manus-use-enhanced entry point should have been removed"
    assert "cli_v2" not in text, "cli_v2 reference should have been removed from pyproject.toml"
    assert "cli_enhanced" not in text, "cli_enhanced reference should have been removed from pyproject.toml"
