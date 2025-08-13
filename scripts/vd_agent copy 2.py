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
        **Your Step-by-Step Discovery Process:**

        **Step 1: Determine the Date Range**
        - Use the `current_time` tool to get today's date.
        - Use the `python_repl` tool with the `datetime` library to calculate the start and end datetimes for the current month in ISO 8601 format (e.g., `2025-07-08T00:00:00.000Z`).

        **Step 2: Discover, Enrich, and Submit in a Streaming Page-by-Page Workflow**
        - You will loop through the NVD API results page by page, creating a continuous, efficient workflow.
        - **Setup:** Use the `python_repl` tool to make an initial request to the NVD API. Use the date range from **Step 1** and severity filters in the URL, and set a reasonable page size (e.g., `resultsPerPage=50`). The URL format is `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={START_DATETIME}&pubEndDate={END_DATETIME}&cvssV3Severity=HIGH&cvssV3Severity=CRITICAL&cvssV4Severity=HIGH&cvssV4Severity=CRITICAL`. Note the `totalResults` from this first call.
        - **Looping:** You will loop, incrementing the `startIndex` parameter by the number of results per page, until you have processed all `totalResults`.
        - **For each page of results you fetch:**
            - **A. Filter by EPSS:** Take the list of CVEs from the current page and immediately filter them using the EPSS API.
            - **B. Enrich:** For the small list of CVEs from this page that passed the filter, gather the additional enrichment data from CISA, OTX, and GitHub. You can reuse the NVD data you already have.
            - **C. Submit:** Immediately take this fully enriched batch of CVEs and submit it using the `submit_cves` tool.
        - **This page-by-page loop is the core of your task.** You must continue until all results have been processed and submitted.
        """
        self.agent = Agent(
            model=model_name,
            system_prompt=self.system_prompt,
            tools=[
                python_repl,
                current_time,
                browser_agent_tool,
                get_nvd_data,
                check_cisa_kev,
                get_otx_cve_details,
                get_github_advisory,
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