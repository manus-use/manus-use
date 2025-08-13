#!/usr/bin/env python3
"""
Agent that discovers new vulnerabilities based on a set of criteria including
timeframe, CVSS severity, and EPSS score.
"""

import os
import sys
from pathlib import Path
import warnings
warnings.filterwarnings("ignore")
os.environ["BYPASS_TOOL_CONSENT"] = "True"

sys.path.insert(0, str(Path(__file__).parent / "src"))

from strands import Agent
from strands_tools import current_time, python_repl
import manus_use.tools.obtain_cves as obtain_cves

class VulnerabilityDiscoveryAgent:
    """Agent that discovers and reports on new, high-impact vulnerabilities."""

    def __init__(self, model_name: str):
        """Initialize the agent."""
        self.system_prompt = """
        You are an expert cybersecurity intelligence analyst. Your mission is to discover the latest high-impact vulnerabilities and report on them.

        **Primary Goal:** Identify and report on vulnerabilities that were disclosed **during specific date range**, have a **High or Critical CVSS score**, and meet the EPSS criteria (**score > 5% OR percentile > 50%**).
        ---

        **Your Step-by-Step Discovery Process:**

        **Step 1: Determine the Date Range**
        - Use the `current_time` tool to get today's date.
        - Use the `python_repl` tool with the `datetime` library to calculate the start and end datetimes for the last four months(before Jun 2025) in ISO 8601 format (%Y-%m-%dT%H:%M:%S.000Z).

        **Step 2: Obtain CVEs**
        - Use the `obtain_cves` with the date range from **Step 1** to obtain CVEs.
        """
        self.agent = Agent(
            model=model_name,
            system_prompt=self.system_prompt,
            tools=[
                current_time,
                obtain_cves,
                python_repl
            ]
        )

    def handle_request(self, request: str) -> str:
        """Handles a user request by invoking the agent."""
        print("INFO: Discovery Agent received request. It will now execute the discovery workflow...")
        response = self.agent(request)
        return response

# --- Main Execution Block ---
def main():
    """Example of using the VulnerabilityDiscoveryAgent."""
    print("=== Vulnerability Discovery Agent ===")

    try:
        from manus_use.config import Config
        config = Config.from_file()
        model_name = "us.anthropic.claude-sonnet-4-20250514-v1:0"
        print(f"Using configured model: {model_name}")
    except Exception as e:
        model_name = "us.anthropic.claude-sonnet-4-20250514-v1:0"
        print(f"Could not load config ({e}), using default model: {model_name}")

    discovery_agent = VulnerabilityDiscoveryAgent(model_name=model_name)

    analysis_request = """
    Please discover and report on new vulnerabilities according to your core workflow.
    """

    print("\n--- Sending request to Discovery Agent ---")
    result = discovery_agent.handle_request(analysis_request)
    print("\n--- Final Response from Agent ---")
    print(result)


if __name__ == "__main__":
    main()