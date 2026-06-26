"""VariantAnalysisAgent — CVE variant analysis and vulnerability hunting."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_MODEL_ID = "us.anthropic.claude-opus-4-6-v1"

SYSTEM_PROMPT = """You are an expert vulnerability researcher specializing in variant analysis.
Given a CVE identifier, you will:
1. Research the original vulnerability deeply (root cause, affected code patterns, CWE)
2. Identify similar code patterns and architectural weaknesses in related projects
3. Search for variants — similar bugs that may exist in related codebases
4. Assess exploitability and severity of any variants found
5. Provide actionable remediation guidance for each finding

Structure your report with sections:
## Original Vulnerability Analysis
## Variant Search Strategy
## Variants Found
## Risk Assessment
## Remediation Recommendations
"""


class VariantAnalysisAgent:
    """Agent that performs CVE variant analysis using available tools."""

    def __init__(self, *, config=None, model: Any | None = None):
        from manus_use.config import Config

        self._config = config or Config.from_file()
        self._model = model  # allow injection for tests
        self._agent = None  # lazy init

    def _build_agent(self):
        try:
            from strands import Agent  # noqa: F401

            from manus_use.tools.get_github_advisory import get_github_advisory
            from manus_use.tools.get_nvd_data import get_nvd_data
            from manus_use.tools.python_repl import python_repl
            from manus_use.tools.search_for_exploits import search_for_exploits
        except ImportError as exc:
            raise ImportError(f"strands and manus_use tools required: {exc}") from exc

        from strands import Agent

        model = self._model
        if model is None:
            try:
                import botocore  # noqa: F401
                from strands.models import BedrockModel

                model_id = self._config.agent.model_id or DEFAULT_MODEL_ID
                region = self._config.agent.aws_region or "us-east-1"
                model = BedrockModel(model_id=model_id, region_name=region, max_tokens=8192)
            except Exception:
                model = None

        return Agent(
            model=model,
            system_prompt=SYSTEM_PROMPT,
            tools=[get_nvd_data, get_github_advisory, search_for_exploits, python_repl],
        )

    def handle_request(self, prompt: str) -> str:
        if self._agent is None:
            self._agent = self._build_agent()
        result = self._agent(prompt)
        return str(result)

    def analyze_variants(self, cve_id: str) -> str:
        return self.handle_request(
            f"Perform a comprehensive variant analysis for {cve_id}. "
            "Research the original vulnerability, then systematically search for similar bugs in related projects."
        )


__all__ = ["VariantAnalysisAgent", "DEFAULT_MODEL_ID"]
