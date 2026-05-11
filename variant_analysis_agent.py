#!/usr/bin/env python3
"""
Variant Analysis Agent — minimal test of the Strands AgentSkills plugin.

Demonstrates:
  - AgentSkills plugin with a filesystem-based skill
  - Progressive disclosure (skill metadata in system prompt, full instructions loaded on demand)
  - Agent activating a skill via tool call during execution

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
        model_id="us.anthropic.claude-sonnet-4-20250514-v1:0",
        region_name="us-west-2",
        max_tokens=4096,
    )

    skills_dir = Path(__file__).parent / "skills"
    plugin = AgentSkills(skills=str(skills_dir))

    agent = Agent(
        model=model,
        plugins=[plugin],
        system_prompt=(
            "You are a vulnerability analyst assistant. "
            "You have skills available — activate the relevant skill before answering. "
            "After activating, follow the skill instructions exactly."
        ),
        tools=["manus_use.tools.python_repl"],
    )

    print(f"=== Variant Analysis Agent (AgentSkills test) ===")
    print(f"Query: {cve_id}\n")

    result = agent(f"Analyze {cve_id}")
    print(result)


if __name__ == "__main__":
    main()
