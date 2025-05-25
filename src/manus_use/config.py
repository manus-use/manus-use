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
            kwargs["region_name"] = os.getenv("AWS_DEFAULT_REGION", "us-west-2")
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


class Config(BaseModel):
    """Main configuration."""
    
    llm: LLMConfig = Field(default_factory=LLMConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    
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
            return cls(**data)
        
        # Return default config if no file found
        return cls()
    
    def get_model(self):
        """Get configured model instance."""
        from strands.models import BedrockModel
        
        # For now, only Bedrock is available in the installed version
        # TODO: Add other models when available
        provider_map = {
            "bedrock": BedrockModel,
        }
        
        model_class = provider_map.get(self.llm.provider)
        if not model_class:
            raise ValueError(f"Unknown provider: {self.llm.provider}")
            
        return model_class(**self.llm.model_kwargs)