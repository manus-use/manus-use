"""Tests for .env / environment-variable config loading."""

import os
from unittest import mock

import pytest

from manus_agent.config import Config, _load_dotenv

# ---------------------------------------------------------------------------
# _load_dotenv helper
# ---------------------------------------------------------------------------


class TestLoadDotenv:
    def test_no_dotenv_installed_is_silent(self, tmp_path, monkeypatch):
        """_load_dotenv is a no-op when python-dotenv is not importable."""
        monkeypatch.chdir(tmp_path)
        with mock.patch.dict("sys.modules", {"dotenv": None}):
            _load_dotenv()  # must not raise

    def test_loads_dot_env_in_cwd(self, tmp_path, monkeypatch):
        """_load_dotenv reads .env from the current working directory."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("MANUS_TEST_SENTINEL=loaded_from_cwd\n")
        monkeypatch.delenv("MANUS_TEST_SENTINEL", raising=False)

        _load_dotenv()

        assert os.environ.get("MANUS_TEST_SENTINEL") == "loaded_from_cwd"
        monkeypatch.delenv("MANUS_TEST_SENTINEL", raising=False)

    def test_cwd_env_takes_priority_over_subdirs(self, tmp_path, monkeypatch):
        """First found .env wins; config/.env is not loaded when .env exists in cwd."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("MANUS_PRIORITY_TEST=cwd\n")
        (tmp_path / "config").mkdir()
        (tmp_path / "config" / ".env").write_text("MANUS_PRIORITY_TEST=config_subdir\n")
        monkeypatch.delenv("MANUS_PRIORITY_TEST", raising=False)

        _load_dotenv()

        assert os.environ.get("MANUS_PRIORITY_TEST") == "cwd"
        monkeypatch.delenv("MANUS_PRIORITY_TEST", raising=False)

    def test_does_not_overwrite_existing_shell_env(self, tmp_path, monkeypatch):
        """Shell env vars are not overwritten by .env (override=False)."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("MANUS_SHELL_PRIORITY=from_file\n")
        monkeypatch.setenv("MANUS_SHELL_PRIORITY", "from_shell")

        _load_dotenv()

        assert os.environ["MANUS_SHELL_PRIORITY"] == "from_shell"


# ---------------------------------------------------------------------------
# LLM env overrides
# ---------------------------------------------------------------------------


class TestLLMEnvOverrides:
    def test_manus_llm_provider_overrides_default(self, monkeypatch):
        monkeypatch.setenv("MANUS_LLM_PROVIDER", "anthropic")
        cfg = Config()
        assert cfg.llm.provider == "anthropic"

    def test_manus_llm_model_overrides_default(self, monkeypatch):
        monkeypatch.setenv("MANUS_LLM_MODEL", "claude-3-5-sonnet-20241022")
        cfg = Config()
        assert cfg.llm.model == "claude-3-5-sonnet-20241022"

    def test_manus_llm_base_url(self, monkeypatch):
        monkeypatch.setenv("MANUS_LLM_BASE_URL", "http://localhost:8000/v1")
        cfg = Config()
        assert cfg.llm.base_url == "http://localhost:8000/v1"

    def test_manus_llm_temperature(self, monkeypatch):
        monkeypatch.setenv("MANUS_LLM_TEMPERATURE", "0.7")
        cfg = Config()
        assert cfg.llm.temperature == pytest.approx(0.7)

    def test_manus_llm_max_tokens(self, monkeypatch):
        monkeypatch.setenv("MANUS_LLM_MAX_TOKENS", "8192")
        cfg = Config()
        assert cfg.llm.max_tokens == 8192

    def test_openai_api_key_backfill(self, monkeypatch):
        monkeypatch.setenv("MANUS_LLM_PROVIDER", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        cfg = Config()
        assert cfg.llm.api_key == "sk-test"

    def test_anthropic_api_key_backfill(self, monkeypatch):
        monkeypatch.setenv("MANUS_LLM_PROVIDER", "anthropic")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        cfg = Config()
        assert cfg.llm.api_key == "sk-ant-test"

    def test_openai_key_not_used_for_anthropic_provider(self, monkeypatch):
        monkeypatch.setenv("MANUS_LLM_PROVIDER", "anthropic")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-wrong")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        cfg = Config()
        assert cfg.llm.api_key is None

    def test_api_key_in_toml_not_overwritten_by_env(self, tmp_path, monkeypatch):
        """config.toml api_key takes priority over env var."""
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text("[llm]\nprovider = 'openai'\napi_key = 'toml-key'\n")
        monkeypatch.setenv("OPENAI_API_KEY", "env-key")
        cfg = Config.from_file(cfg_file)
        assert cfg.llm.api_key == "toml-key"

    def test_aws_region_from_manus_env(self, monkeypatch):
        monkeypatch.setenv("MANUS_AWS_REGION", "eu-west-1")
        monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
        monkeypatch.delenv("AWS_REGION", raising=False)
        cfg = Config()
        assert cfg.llm.aws_region == "eu-west-1"

    def test_aws_region_from_conventional_env(self, monkeypatch):
        monkeypatch.delenv("MANUS_AWS_REGION", raising=False)
        monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-southeast-1")
        monkeypatch.delenv("AWS_REGION", raising=False)
        cfg = Config()
        assert cfg.llm.aws_region == "ap-southeast-1"

    def test_aws_region_manus_wins_over_conventional(self, monkeypatch):
        monkeypatch.setenv("MANUS_AWS_REGION", "us-east-1")
        monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
        cfg = Config()
        assert cfg.llm.aws_region == "us-east-1"


# ---------------------------------------------------------------------------
# Integration env overrides
# ---------------------------------------------------------------------------


class TestIntegrationEnvOverrides:
    def test_otx_api_key(self, monkeypatch):
        monkeypatch.setenv("MANUS_OTX_API_KEY", "otx-key-123")
        cfg = Config()
        assert cfg.otx.api_key == "otx-key-123"

    def test_github_token_manus_prefix(self, monkeypatch):
        monkeypatch.setenv("MANUS_GITHUB_TOKEN", "ghp_manus")
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        cfg = Config()
        assert cfg.github.api_token == "ghp_manus"

    def test_github_token_conventional(self, monkeypatch):
        monkeypatch.delenv("MANUS_GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_conventional")
        cfg = Config()
        assert cfg.github.api_token == "ghp_conventional"

    def test_github_manus_token_wins_over_conventional(self, monkeypatch):
        monkeypatch.setenv("MANUS_GITHUB_TOKEN", "ghp_manus")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_conventional")
        cfg = Config()
        assert cfg.github.api_token == "ghp_manus"

    def test_lark_api_token(self, monkeypatch):
        monkeypatch.setenv("MANUS_LARK_API_TOKEN", "lark-tok")
        monkeypatch.delenv("LARK_API_TOKEN", raising=False)
        cfg = Config()
        assert cfg.lark.api_token == "lark-tok"

    def test_lark_api_token_conventional(self, monkeypatch):
        monkeypatch.delenv("MANUS_LARK_API_TOKEN", raising=False)
        monkeypatch.setenv("LARK_API_TOKEN", "lark-conventional")
        cfg = Config()
        assert cfg.lark.api_token == "lark-conventional"

    def test_lark_document_url(self, monkeypatch):
        monkeypatch.setenv("MANUS_LARK_DOCUMENT_URL", "https://lark.example.com/doc/xxx")
        monkeypatch.delenv("LARK_DOCUMENT_URL", raising=False)
        cfg = Config()
        assert cfg.lark.document_url == "https://lark.example.com/doc/xxx"

    def test_lark_document_url_conventional(self, monkeypatch):
        monkeypatch.delenv("MANUS_LARK_DOCUMENT_URL", raising=False)
        monkeypatch.setenv("LARK_DOCUMENT_URL", "https://lark.example.com/doc/yyy")
        cfg = Config()
        assert cfg.lark.document_url == "https://lark.example.com/doc/yyy"

    def test_webhook_cve_submit_url(self, monkeypatch):
        monkeypatch.setenv("MANUS_WEBHOOK_CVE_SUBMIT_URL", "https://hook.example.com/cve")
        cfg = Config()
        assert cfg.webhooks.cve_submit_url == "https://hook.example.com/cve"

    def test_mcp_server_url(self, monkeypatch):
        monkeypatch.setenv("MANUS_MCP_SERVER_URL", "http://mcp.example.com:8080")
        cfg = Config()
        assert cfg.mcp.server_url == "http://mcp.example.com:8080"


# ---------------------------------------------------------------------------
# from_file with .env
# ---------------------------------------------------------------------------


class TestFromFileWithDotenv:
    def test_env_file_loaded_by_from_file(self, tmp_path, monkeypatch):
        """from_file loads a .env in cwd and applies values."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("MANUS_LLM_PROVIDER=anthropic\nANTHROPIC_API_KEY=sk-ant-from-env\n")
        monkeypatch.delenv("MANUS_LLM_PROVIDER", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        cfg = Config.from_file()

        assert cfg.llm.provider == "anthropic"
        assert cfg.llm.api_key == "sk-ant-from-env"

    def test_env_file_does_not_override_toml(self, tmp_path, monkeypatch):
        """config.toml explicit values win over .env."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("MANUS_LLM_PROVIDER=openai\n")
        (tmp_path / "config.toml").write_text("[llm]\nprovider = 'bedrock'\n")
        monkeypatch.delenv("MANUS_LLM_PROVIDER", raising=False)

        cfg = Config.from_file()

        # MANUS_LLM_PROVIDER always overrides (allows full env-only config)
        assert cfg.llm.provider == "openai"

    def test_env_file_fills_missing_toml_values(self, tmp_path, monkeypatch):
        """Env vars fill fields absent from config.toml."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("MANUS_GITHUB_TOKEN=ghp_from_env\n")
        (tmp_path / "config.toml").write_text("[llm]\nprovider = 'bedrock'\n")
        monkeypatch.delenv("MANUS_GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)

        cfg = Config.from_file()

        assert cfg.github.api_token == "ghp_from_env"

    def test_no_env_no_toml_returns_defaults(self, tmp_path, monkeypatch):
        """No .env and no config.toml → pure defaults."""
        monkeypatch.chdir(tmp_path)
        # Clear all MANUS_ vars to avoid interference from the test runner's env
        for k in list(os.environ):
            if k.startswith("MANUS_"):
                monkeypatch.delenv(k, raising=False)

        cfg = Config.from_file()

        assert cfg.llm.provider == "openai"
        assert cfg.llm.model == "gpt-4o"
        assert cfg.otx.api_key is None
