#!/usr/bin/env python3
"""Vulnerability Intelligence agent entry point.

The :class:`VulnerabilityIntelligenceAgent` implementation now lives in the
importable module ``manus_use.agents.vi_agent``. This script remains a thin
command-line entry point so existing ``python vi_agent.py CVE-...`` workflows
keep working.
"""

import os
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
os.environ.setdefault("BYPASS_TOOL_CONSENT", "True")

# Add the src directory to Python path for in-tree execution.
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.agents.vi_agent import VulnerabilityIntelligenceAgent  # noqa: E402


def main() -> None:
    """Run a vulnerability intelligence analysis from the command line."""
    print("=== Vulnerability Intelligence Agent ===")

    cve_id = sys.argv[1] if len(sys.argv) > 1 else "CVE-2025-6554"
    if len(sys.argv) <= 1:
        print(f"No CVE provided. Using example: {cve_id}")

    try:
        from manus_use.config import Config

        config = Config.from_file()
    except Exception as exc:
        print(f"Could not load config ({exc}); using defaults.")
        config = None

    agent = VulnerabilityIntelligenceAgent(config=config)

    print(f"\n--- Sending analysis request to agent for: {cve_id} ---")
    result = agent.analyze(cve_id)
    print("\n--- Final Response from Agent ---")
    print(result)


if __name__ == "__main__":
    main()
