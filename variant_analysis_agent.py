#!/usr/bin/env python3
"""CLI entry-point for the Variant Analysis Agent (backwards compat wrapper).

The actual implementation lives in :mod:`manus_use.agents.variant_agent`.

Usage::
    python variant_analysis_agent.py CVE-2024-3094
Or via CLI::
    manus-use variants CVE-2024-3094
"""
import sys
import warnings

warnings.filterwarnings("ignore")


def main() -> None:
    from manus_use.agents.variant_agent import VariantAnalysisAgent

    cve_id = sys.argv[1] if len(sys.argv) > 1 else "CVE-2024-3094"
    agent = VariantAnalysisAgent()
    result = agent.analyze_variants(cve_id)
    print(result)


if __name__ == "__main__":
    main()
