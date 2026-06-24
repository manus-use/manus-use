"""Tests for configuration module."""

import pytest

from manus_use.config import Config, LLMConfig


def test_default_config():
    """Test default configuration."""
    config = Config()

    assert config.llm.provider == "openai"
    assert config.llm.model == "gpt-4o"
    assert config.llm.temperature == 0.0
    assert config.llm.max_tokens == 4096

    assert config.sandbox.enabled is True
    assert config.sandbox.docker_image == "python:3.12-slim"

    assert "file_operations" in config.tools.enabled


def test_llm_config_model_kwargs():
    """Test LLM config model kwargs generation."""
    # OpenAI
    config = LLMConfig(provider="openai", model="gpt-4", api_key="test-key", temperature=0.5)
    kwargs = config.model_kwargs
    assert kwargs["model_id"] == "gpt-4"
    assert kwargs["api_key"] == "test-key"
    assert kwargs["temperature"] == 0.5

    # Bedrock
    config = LLMConfig(provider="bedrock", model="claude-3")
    kwargs = config.model_kwargs
    assert kwargs["model_id"] == "claude-3"
    assert "region" in kwargs


def test_config_from_file(tmp_path):
    """Test loading configuration from file."""
    # Create test config file
    config_file = tmp_path / "config.toml"
    config_file.write_text("""
[llm]
provider = "anthropic"
model = "claude-3"
temperature = 0.7

[sandbox]
enabled = false

[tools]
enabled = ["web_search"]
    """)

    # Load config
    config = Config.from_file(config_file)

    assert config.llm.provider == "anthropic"
    assert config.llm.model == "claude-3"
    assert config.llm.temperature == 0.7
    assert config.sandbox.enabled is False
    assert config.tools.enabled == ["web_search"]


def test_get_model():
    """Test model instance creation raises ImportError when provider package is absent."""
    import sys
    import unittest.mock as mock

    config = Config(llm=LLMConfig(provider="openai", model="gpt-4"))

    with mock.patch.dict(sys.modules, {"strands.models.openai": None}):
        with pytest.raises(ImportError, match="OpenAI model support"):
            config.get_model()


def test_get_model_anthropic_missing_import():
    """get_model() with provider='anthropic' raises ImportError when package absent."""
    import sys
    import unittest.mock as mock

    config = Config(llm=LLMConfig(provider="anthropic", model="claude-3-5-sonnet-20241022"))

    with mock.patch.dict(sys.modules, {"strands.models.anthropic": None}):
        with pytest.raises(ImportError, match="Anthropic model support"):
            config.get_model()


def test_get_model_ollama_missing_import():
    """get_model() with provider='ollama' raises ImportError when package absent."""
    import sys
    import unittest.mock as mock

    config = Config(llm=LLMConfig(provider="ollama", model="llama3"))

    with mock.patch.dict(sys.modules, {"strands.models.ollama": None}):
        with pytest.raises(ImportError, match="Ollama model support"):
            config.get_model()


def test_get_model_unknown_provider():
    """get_model() raises a descriptive ValueError for unrecognised providers."""
    config = Config(llm=LLMConfig(provider="unsupported", model="some-model"))

    with pytest.raises(ValueError, match="Supported values are"):
        config.get_model()


def test_llm_config_model_kwargs_anthropic():
    """model_kwargs includes the right keys for the Anthropic provider."""
    config = LLMConfig(provider="anthropic", model="claude-3-5-sonnet-20241022", api_key="sk-test")
    kwargs = config.model_kwargs
    assert kwargs["model_id"] == "claude-3-5-sonnet-20241022"
    assert kwargs["api_key"] == "sk-test"
    assert "host" not in kwargs


def test_llm_config_model_kwargs_ollama():
    """model_kwargs includes the right keys for the Ollama provider."""
    config = LLMConfig(provider="ollama", model="llama3", base_url="http://localhost:11434")
    kwargs = config.model_kwargs
    assert kwargs["model_id"] == "llama3"
    assert kwargs["host"] == "http://localhost:11434"


def test_llm_config_model_kwargs_ollama_default_host():
    """Ollama model_kwargs uses the default localhost host when base_url is unset."""
    config = LLMConfig(provider="ollama", model="llama3")
    kwargs = config.model_kwargs
    assert kwargs["host"] == "http://localhost:11434"
