#!/usr/bin/env python3
"""
Variant Analysis Agent — demonstrates AgentSkills plugin with real skills.

Skills loaded from skills/ directory:
  - variant-analysis: CVE variant analysis and vulnerability hunting
  - oss-contributor: OSS patch writing, PR, and GHSA submission
  - test-skill: simple CVE summaries (demo)

Usage:
  python variant_analysis_agent.py [CVE-ID]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from strands import Agent, AgentSkills
from strands.models import BedrockModel


def main():
    cve_id = sys.argv[1] if len(sys.argv) > 1 else "CVE-2024-3094"

    model = BedrockModel(
        model_id="us.anthropic.claude-opus-4-6-v1",
        region_name="us-east-1",
        max_tokens=4096,
    )

    skills_dir = Path(__file__).parent / "skills"
    plugin = AgentSkills(skills=str(skills_dir))

    agent = Agent(
        model=model,
        plugins=[plugin],
        system_prompt=(
            "You are a vulnerability analyst assistant. "
            "You have these skills available:\n"
            "  - variant-analysis: for CVE variant analysis and vulnerability hunting\n"
            "  - oss-contributor: for writing fix patches and submitting PRs/GHSAs\n"
            "  - test-skill: for simple CVE summaries\n"
            "Activate the most relevant skill before answering. "
            "After activating, follow the skill instructions exactly."
        ),
    )

    print(f"=== Variant Analysis Agent (AgentSkills test) ===")
    print(f"Query: {cve_id}\n")

    result = agent(f"Analyze {cve_id}")
    print(result)


if __name__ == "__main__":
    main()
