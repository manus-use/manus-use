"""Configuration management for ManusUse.

Config resolution order (highest priority first):

1. Environment variables / .env file  — ``MANUS_*`` prefixed or well-known names
2. config.toml                         — explicit file path or auto-discovered
3. Pydantic model defaults

Supported env-var names::

    # LLM
    MANUS_LLM_PROVIDER        bedrock | openai | anthropic | ollama
    MANUS_LLM_MODEL           model id / name
    MANUS_LLM_BASE_URL        base URL for openai-compatible endpoints
    MANUS_LLM_TEMPERATURE     float  (default 0.0)
    MANUS_LLM_MAX_TOKENS      int    (default 4096)
    OPENAI_API_KEY            OpenAI key  (conventional name)
    ANTHROPIC_API_KEY         Anthropic key  (conventional name)
    AWS_DEFAULT_REGION        AWS region  (conventional name)
    MANUS_AWS_REGION          alias for AWS_DEFAULT_REGION

    # Integrations
    MANUS_OTX_API_KEY
    MANUS_GITHUB_TOKEN        (also accepts GITHUB_TOKEN)
    MANUS_LARK_API_TOKEN      (also accepts LARK_API_TOKEN)
    MANUS_LARK_DOCUMENT_URL   (also accepts LARK_DOCUMENT_URL)
    MANUS_WEBHOOK_CVE_SUBMIT_URL
    MANUS_MCP_SERVER_URL
"""

import os
from pathlib import Path
from typing import Any

import toml
from pydantic import BaseModel, Field, model_validator

# ---------------------------------------------------------------------------
# .env loader (optional dependency — graceful no-op when python-dotenv absent)
# ---------------------------------------------------------------------------


def _load_dotenv() -> None:
    """Load the first .env file found; silently skips if dotenv is not installed."""
    try:
        from dotenv import load_dotenv as _load
    except ImportError:
        return

    search_paths = [
        Path(".env"),
        Path("config/.env"),
        Path.home() / ".manus-use" / ".env",
    ]
    for p in search_paths:
        if p.exists():
            _load(p, override=False)  # env vars already set in shell take priority
            break


# ---------------------------------------------------------------------------
# Config models
# ---------------------------------------------------------------------------


class LLMConfig(BaseModel):
    """LLM configuration."""

    provider: str = "openai"
    model: str = "gpt-4o"
    api_key: str | None = None
    base_url: str | None = None
    aws_region: str | None = None
    temperature: float = 0.0
    max_tokens: int = 4096

    @property
    def model_kwargs(self) -> dict[str, Any]:
        """Get model initialization kwargs based on provider."""
        kwargs = {
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

        if self.provider == "openai":
            if self.api_key:
                kwargs["api_key"] = self.api_key
            if self.base_url:
                kwargs["base_url"] = self.base_url
            kwargs["model_id"] = self.model
        elif self.provider == "anthropic":
            if self.api_key:
                kwargs["api_key"] = self.api_key
            kwargs["model_id"] = self.model
        elif self.provider == "bedrock":
            kwargs["model_id"] = self.model
            region = os.getenv("AWS_DEFAULT_REGION", self.aws_region or "us-west-2")
            # Keep both keys for compatibility across callers/tests.
            kwargs["region"] = region
            kwargs["region_name"] = region
        elif self.provider == "ollama":
            kwargs["model_id"] = self.model
            kwargs["host"] = self.base_url or "http://localhost:11434"

        return kwargs


class SandboxConfig(BaseModel):
    """Sandbox configuration."""

    enabled: bool = True
    docker_image: str = "python:3.12-slim"
    timeout: int = 300
    memory_limit: str = "512m"
    cpu_limit: float = 1.0


class ToolsConfig(BaseModel):
    """Tools configuration."""

    enabled: list[str] = Field(default_factory=lambda: ["file_operations", "code_execute", "web_search"])
    browser_headless: bool = True
    search_engine: str = "duckduckgo"
    max_search_results: int = 5


class BrowserUseConfig(BaseModel):
    """Browser-use specific configuration."""

    # LLM settings for browser-use (can override main LLM config)
    provider: str | None = None  # "bedrock", "openai", etc. If None, uses main LLM config
    model: str | None = None  # Model ID. If None, uses main LLM config
    api_key: str | None = None  # API key. If None, uses main LLM config or env vars
    temperature: float = 0.0
    max_tokens: int = 4096

    # Browser settings
    headless: bool = True
    keep_alive: bool = False  # Keep browser open between tasks
    disable_security: bool = False  # Disable browser security features (use with caution)
    extra_chromium_args: list[str] = Field(default_factory=list)  # Additional Chrome/Chromium args

    # Agent settings
    max_steps: int = 100  # Maximum steps per task
    max_actions_per_step: int = 10  # Maximum actions in a single step
    use_vision: bool = True  # Use vision capabilities
    save_conversation_path: str | None = None  # Path to save conversation history
    max_error_length: int = 400  # Maximum error message length
    tool_calling_method: str = "auto"  # "auto", "function_calling", "json_mode", etc.

    # Memory and context
    enable_memory: bool = False  # Enable conversation memory between tasks
    memory_window: int = 10  # Number of previous messages to keep in memory

    # Performance settings
    timeout: int = 300  # Task timeout in seconds
    retry_count: int = 3  # Number of retries on failure

    # Debugging
    debug: bool = False  # Enable debug logging
    save_screenshots: bool = False  # Save screenshots during execution
    screenshot_path: str | None = None  # Path to save screenshots


class OTXConfig(BaseModel):
    """OTX configuration."""

    api_key: str | None = None


class GitHubConfig(BaseModel):
    """GitHub API configuration."""

    api_token: str | None = None


class MCPConfig(BaseModel):
    """MCP server configuration."""

    server_url: str | None = None


class WebhooksConfig(BaseModel):
    """Webhooks configuration."""

    cve_submit_url: str | None = None


class LarkConfig(BaseModel):
    """Lark document API configuration."""

    document_url: str | None = None
    api_token: str | None = None


class AgentConfig(BaseModel):
    """Agent behaviour configuration."""

    context_manager: str = Field(
        default="auto",
        description=(
            "Strands context manager mode for general agents. "
            "'auto' composes SummarizingConversationManager + ContextOffloader. "
            "'agentic' lets the model manage context via tool calls. "
            "VulnerabilityIntelligenceAgent always uses 'agentic'."
        ),
    )
    model_id: str | None = Field(
        default=None,
        description=(
            "Override Bedrock model ID for security agents (VariantAnalysisAgent). "
            "Defaults to the agent's built-in default when not set."
        ),
    )
    aws_region: str | None = Field(
        default=None,
        description=("AWS region for Bedrock-backed security agents. Defaults to 'us-east-1' when not set."),
    )


class Config(BaseModel):
    """Main configuration."""

    llm: LLMConfig = Field(default_factory=LLMConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    browser_use: BrowserUseConfig = Field(default_factory=BrowserUseConfig)
    otx: OTXConfig = Field(default_factory=OTXConfig)
    github: GitHubConfig = Field(default_factory=GitHubConfig)
    mcp: MCPConfig = Field(default_factory=MCPConfig)
    webhooks: WebhooksConfig = Field(default_factory=WebhooksConfig)
    lark: LarkConfig = Field(default_factory=LarkConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)

    @model_validator(mode="after")
    def _apply_env_overrides(self) -> "Config":
        """Backfill unset fields from environment variables.

        MANUS_* env vars and well-known conventional names (OPENAI_API_KEY,
        GITHUB_TOKEN, etc.) are applied after the model is constructed.
        Only None / default values are overwritten — explicit values from
        config.toml always take priority over env vars for non-secret settings.
        MANUS_LLM_PROVIDER/MODEL/BASE_URL always override to allow full
        env-only configuration.
        """
        e = os.environ

        # --- LLM (always override — allows full env-only config) ---
        if e.get("MANUS_LLM_PROVIDER"):
            self.llm.provider = e["MANUS_LLM_PROVIDER"]
        if e.get("MANUS_LLM_MODEL"):
            self.llm.model = e["MANUS_LLM_MODEL"]
        if e.get("MANUS_LLM_BASE_URL"):
            self.llm.base_url = e["MANUS_LLM_BASE_URL"]
        if e.get("MANUS_LLM_TEMPERATURE"):
            self.llm.temperature = float(e["MANUS_LLM_TEMPERATURE"])
        if e.get("MANUS_LLM_MAX_TOKENS"):
            self.llm.max_tokens = int(e["MANUS_LLM_MAX_TOKENS"])

        # API keys — only fill when not already set in config.toml
        if self.llm.api_key is None:
            provider = (self.llm.provider or "").lower()
            if provider == "openai":
                self.llm.api_key = e.get("OPENAI_API_KEY")
            elif provider == "anthropic":
                self.llm.api_key = e.get("ANTHROPIC_API_KEY")

        # AWS region — conventional names; MANUS_AWS_REGION alias
        if self.llm.aws_region is None:
            self.llm.aws_region = (
                e.get("MANUS_AWS_REGION") or e.get("AWS_DEFAULT_REGION") or e.get("AWS_REGION")
            ) or None

        # --- Integrations ---
        if self.otx.api_key is None:
            self.otx.api_key = e.get("MANUS_OTX_API_KEY") or None

        if self.github.api_token is None:
            self.github.api_token = e.get("MANUS_GITHUB_TOKEN") or e.get("GITHUB_TOKEN") or None

        if self.lark.api_token is None:
            self.lark.api_token = e.get("MANUS_LARK_API_TOKEN") or e.get("LARK_API_TOKEN") or None
        if self.lark.document_url is None:
            self.lark.document_url = e.get("MANUS_LARK_DOCUMENT_URL") or e.get("LARK_DOCUMENT_URL") or None

        if self.webhooks.cve_submit_url is None:
            self.webhooks.cve_submit_url = e.get("MANUS_WEBHOOK_CVE_SUBMIT_URL") or None

        if self.mcp.server_url is None:
            self.mcp.server_url = e.get("MANUS_MCP_SERVER_URL") or None

        return self

    @classmethod
    def from_file(cls, path: Path | None = None) -> "Config":
        """Load configuration from a TOML file, with .env auto-loading.

        Resolution order:

        1. Environment variables (including values loaded from .env)
        2. config.toml values
        3. Pydantic field defaults

        .env search order (first found wins)::

            .env              (current working directory)
            config/.env
            ~/.manus-use/.env
        """
        # Load .env into os.environ (does not overwrite vars already set in shell)
        _load_dotenv()

        if path is None:
            # Look for config in standard locations
            search_paths = [
                Path("config.toml"),
                Path("config/config.toml"),
                Path.home() / ".manus-use" / "config.toml",
            ]
            for p in search_paths:
                if p.exists():
                    path = p
                    break

        if path and path.exists():
            data = toml.load(path)
            return cls(**data)

        # Return default config if no file found (env-var overrides still apply)
        return cls()

    def get_model(self):
        """Get configured model instance."""
        provider = (self.llm.provider or "").lower()

        if provider == "bedrock":
            from strands.models import BedrockModel

            return BedrockModel(**self.llm.model_kwargs)

        if provider == "openai":
            try:
                from strands.models.openai import OpenAIModel
            except ImportError as exc:
                raise ImportError(
                    "OpenAI model support is not available. Install required dependencies (e.g. `openai`)."
                ) from exc

            client_args: dict[str, Any] = {}
            if self.llm.api_key:
                client_args["api_key"] = self.llm.api_key
            if self.llm.base_url:
                client_args["base_url"] = self.llm.base_url

            # Strands OpenAIModel uses `model_id` and `client_args`.
            return OpenAIModel(
                client_args=client_args,
                model_id=self.llm.model,
                max_tokens=self.llm.max_tokens,
            )

        if provider == "anthropic":
            try:
                from strands.models.anthropic import AnthropicModel
            except ImportError as exc:
                raise ImportError(
                    "Anthropic model support is not available. Install required dependencies (e.g. `anthropic`)."
                ) from exc

            kwargs: dict[str, Any] = {
                "model_id": self.llm.model,
                "max_tokens": self.llm.max_tokens,
            }
            if self.llm.api_key:
                kwargs["api_key"] = self.llm.api_key
            return AnthropicModel(**kwargs)

        if provider == "ollama":
            try:
                from strands.models.ollama import OllamaModel
            except ImportError as exc:
                raise ImportError(
                    "Ollama model support is not available. Install required dependencies (e.g. `ollama`)."
                ) from exc

            return OllamaModel(
                model_id=self.llm.model,
                host=self.llm.base_url or "http://localhost:11434",
            )

        raise ValueError(
            f"Unknown provider: {self.llm.provider!r}. "
            "Supported values are: 'openai', 'anthropic', 'bedrock', 'ollama'."
        )
