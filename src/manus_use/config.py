"""Configuration management for ManusUse."""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import toml
from pydantic import BaseModel, Field


class LLMConfig(BaseModel):
    """LLM configuration."""
    
    provider: str = "openai"
    model: str = "gpt-4o"
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    aws_region: Optional[str] = None
    temperature: float = 0.0
    max_tokens: int = 4096
    
    @property
    def model_kwargs(self) -> Dict[str, Any]:
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
    
    enabled: list[str] = Field(
        default_factory=lambda: ["file_operations", "code_execute", "web_search"]
    )
    browser_headless: bool = True
    search_engine: str = "duckduckgo"
    max_search_results: int = 5


class BrowserUseConfig(BaseModel):
    """Browser-use specific configuration."""
    
    # LLM settings for browser-use (can override main LLM config)
    provider: Optional[str] = None  # "bedrock", "openai", etc. If None, uses main LLM config
    model: Optional[str] = None  # Model ID. If None, uses main LLM config
    api_key: Optional[str] = None  # API key. If None, uses main LLM config or env vars
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
    save_conversation_path: Optional[str] = None  # Path to save conversation history
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
    screenshot_path: Optional[str] = None  # Path to save screenshots


class OTXConfig(BaseModel):
    """OTX configuration."""
    api_key: Optional[str] = None


class GitHubConfig(BaseModel):
    """GitHub API configuration."""
    api_token: Optional[str] = None


class MCPConfig(BaseModel):
    """MCP server configuration."""
    server_url: Optional[str] = None


class WebhooksConfig(BaseModel):
    """Webhooks configuration."""
    cve_submit_url: Optional[str] = None


class LarkConfig(BaseModel):
    """Lark document API configuration."""
    document_url: Optional[str] = None
    api_token: Optional[str] = None


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
    
    @classmethod
    def from_file(cls, path: Optional[Path] = None) -> "Config":
        """Load configuration from file."""
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
            #print(data)
            return cls(**data)
        
        # Return default config if no file found
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

            client_args: Dict[str, Any] = {}
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

        raise ValueError(f"Unknown provider: {self.llm.provider}")
