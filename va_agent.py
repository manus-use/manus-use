#!/usr/bin/env python3
"""Vulnerability Intelligence agent entry point (backwards-compat wrapper).

The :class:`VulnerabilityIntelligenceAgent` implementation lives in
``manus_use.agents.vi_agent``. This script is a thin command-line shim so
existing ``python va_agent.py CVE-... [--verify]`` and
``python vi_agent.py CVE-...`` workflows keep working without changes.

Prefer the CLI for new workflows::

    manus-use analyze CVE-2024-3094
    manus-use analyze CVE-2024-3094 --verify

The agent runs an 8-step analysis pipeline for each CVE:

1. NVD data + GitHub advisory
2. CISA KEV check + OTX threat intel
3. PoC hunt — trickest/cve index, PoC Week community digest,
   ExploitDB, Packetstorm, GitHub search
4. URL verification (browser fallback)
5. Deep PoC static code analysis
6. CWE analysis
7. Threat actor feed query
8. Lark document report
"""

import os
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
os.environ.setdefault("BYPASS_TOOL_CONSENT", "True")
os.environ["OPENCLAW"] = os.environ.get("OPENCLAW", "false")

# Add the src directory to Python path for in-tree execution.
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.agents.vi_agent import VulnerabilityIntelligenceAgent  # noqa: E402


def main() -> None:
    """Run a vulnerability intelligence analysis from the command line.

    Usage::

        python va_agent.py CVE-2024-3094            # analysis only
        python va_agent.py CVE-2024-3094 --verify   # analysis + exploit verification
    """
    print("=== Vulnerability Intelligence Assessment Agent ===")

    args = [a for a in sys.argv[1:] if a != "--verify"]
    verify = "--verify" in sys.argv[1:]

    cve_id = args[0] if args else "CVE-2025-6554"
    if not args:
        print(f"No CVE provided. Using example: {cve_id}")

    try:
        from manus_use.config import Config

        config = Config.from_file()
    except Exception as exc:
        print(f"Could not load config ({exc}); using defaults.")
        config = None

    agent = VulnerabilityIntelligenceAgent(config=config)

    if verify:
        print("Exploit verification: ENABLED")

    print(f"\n--- Sending analysis request to agent for: {cve_id} ---")
    result = agent.analyze(cve_id, verify=verify)
    print("\n--- Final Response from Agent ---")
    print(result)


if __name__ == "__main__":
    main()
