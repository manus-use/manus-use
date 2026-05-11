#!/usr/bin/env python3
"""
Remediation Agent — uses only the test-skill to demonstrate
loading a single skill rather than a full directory.

Usage:
  python remediation_agent.py [CVE-ID]
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

    skill_path = str(Path(__file__).parent / "skills" / "test-skill")
    plugin = AgentSkills(skills=[skill_path])

    agent = Agent(
        model=model,
        plugins=[plugin],
        system_prompt=(
            "You are a remediation assistant. "
            "Activate the available skill before answering, "
            "then follow its instructions exactly."
        ),
    )

    print(f"=== Remediation Agent (single skill test) ===")
    print(f"Query: {cve_id}\n")

    result = agent(f"Analyze {cve_id}")
    print(result)


if __name__ == "__main__":
    main()
