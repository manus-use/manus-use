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
from strands_tools import http_request, python_repl, current_time

# Import the tools needed for discovery and enrichment
import manus_use.tools.get_nvd_data as get_nvd_data
import manus_use.tools.check_cisa_kev as check_cisa_kev
import manus_use.tools.get_otx_cve_details as get_otx_cve_details
import manus_use.tools.browser_agent_tool as browser_agent_tool
import manus_use.tools.get_github_advisory as get_github_advisory
import manus_use.tools.submit_cves as submit_cves

class VulnerabilityDiscoveryAgent:
    """Agent that discovers and reports on new, high-impact vulnerabilities."""

    def __init__(self, model_name: str):
        """Initialize the agent."""
        self.system_prompt = """
        You are an expert cybersecurity intelligence analyst. Your mission is to discover the latest high-impact vulnerabilities and report on them.

        **Primary Goal:** Identify and report on vulnerabilities that were disclosed **during specific date range**, have a **High or Critical CVSS score**, and meet the EPSS criteria (**score > 5% OR percentile > 50%**).

        **Core Workflow: Discover, Filter, Enrich, Report**

        --- 
        **General Instructions:**
        - **No Simulation:** You must not, under any circumstances, simulate or mock any part of this workflow. You must interact with the live, real-world APIs and tools for every step. Your job is to process real data, not to demonstrate a workflow with fake data.

        ---
        **Your Step-by-Step Discovery Process:**

        **Step 1: Determine the Date Range**
        - Use the `current_time` tool to get today's date.
        - Use the `python_repl` tool with the `datetime` library to calculate the start and end datetimes for the current month in ISO 8601 format (e.g., `2025-07-08T00:00:00.000Z`).

        **Step 2: Your Primary Task - A Mandatory Processing Loop**
        - Your main and most important task is to loop through every page of the NVD API results. You will be judged on your ability to complete this loop.
        - **A. Initial Call:** Make an initial request to the NVD API with the date range from **Step 1**, and set a reasonable page size (e.g., `resultsPerPage=50`). The URL format is `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={START_DATETIME}&pubEndDate={END_DATETIME}&cvssV3Severity=HIGH&cvssV3Severity=CRITICAL&cvssV4Severity=HIGH&cvssV4Severity=CRITICAL&resultsPerPage=50&startIndex=0`. Note the `totalResults` from this first call. This number is your target. You are not finished until you have processed this many vulnerabilities.
        - **B. The Loop:** You must now start a loop. In each iteration, you will fetch the next page of results using the `startIndex` parameter. This loop **must not** terminate until the number of processed vulnerabilities equals `totalResults`.
        - **C. Inside The Loop - Process Each Page:** For each page of results you fetch, you must perform the following sequence:
            - 1. **Filter All CVEs by EPSS:** Take the **entire list** of CVEs from that page and filter all of them using the EPSS API. Join them into a single, comma-separate string. Use this string to make a single batch call to the EPSS API using the format `https://api.first.org/data/v1/epss?cve={YOUR_COMMA_SEPARATED_STRING}`. Do not use a subset or sample.
            - 2. **Enrich** All CVEs from this page that passed the filter, prepare the final JSON payload. You must reuse the full NVD JSON object you already have for each CVE.
            - 3. **Submit** All enriched CVEs from this page using the `submit_cves` tool.
        - **Do not stop or ask for confirmation.** Continue this loop until the job is done.
        """
        self.agent = Agent(
            model=model_name,
            system_prompt=self.system_prompt,
            tools=[
                http_request,
                python_repl,
                current_time,
                submit_cves,
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