#!/usr/bin/env python3
"""Demo: AgentSkills (single skill) — Strands remediation with a test skill.

Shows how to load a single skill directory into a Strands Agent rather than
the full skill library.

Usage::

    python examples/agent_skills_remediation_demo.py [CVE-ID]
    python examples/agent_skills_remediation_demo.py CVE-2024-3094
"""

import sys
from pathlib import Path

from strands import Agent, AgentSkills
from strands.models import BedrockModel

SKILL_PATH = Path(__file__).resolve().parents[1] / "skills" / "test-skill"


def main() -> None:
    cve_id = sys.argv[1] if len(sys.argv) > 1 else "CVE-2024-3094"

    model = BedrockModel(
        model_id="us.anthropic.claude-sonnet-4-20250514-v1:0",
        region_name="us-west-2",
        max_tokens=4096,
    )

    plugin = AgentSkills(skills=[str(SKILL_PATH)])

    agent = Agent(
        model=model,
        plugins=[plugin],
        system_prompt=(
            "You are a remediation assistant. "
            "Activate the available skill before answering, "
            "then follow its instructions exactly."
        ),
    )

    print("=== AgentSkills Remediation Demo ===")
    print(f"Skill path: {SKILL_PATH}")
    print(f"Query: {cve_id}\n")

    result = agent(f"Analyze {cve_id}")
    print(result)


if __name__ == "__main__":
    main()
