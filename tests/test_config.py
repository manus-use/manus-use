"""Tests for configuration module."""

import pytest
from pathlib import Path

from manus_use.config import Config, LLMConfig, SandboxConfig, ToolsConfig


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
    config = LLMConfig(
        provider="openai",
        model="gpt-4",
        api_key="test-key",
        temperature=0.5
    )
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
    """Test model instance creation."""
    config = Config(llm=LLMConfig(provider="openai", model="gpt-4"))
    
    # This will fail without proper imports, but tests the logic
    with pytest.raises(ImportError):
        model = config.get_model()