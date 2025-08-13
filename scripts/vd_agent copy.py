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
        - Use the `python_repl` tool with the `datetime` library to calculate the date for the start of the current month (this month range).

        **Step 2: Process Vulnerabilities in a Streaming Fashion**
        - You will now loop through the Tenable search results page by page, performing the full analysis and submission cycle for each page.
        - **For each page of results from Tenable (from page 1 until there are no more pages containing CVEs):**
            - **A. Fetch Page Content:**
                - **Primary Method (`python_repl`):** First, try to fetch the page's HTML directly using the `python_repl` tool with the `requests` library and the correct URL format: `https://www.tenable.com/cve/search?q=publication_date%3A(%5BYYYY-MM-DD%20TO%20YYYY-MM-DD%5D)%20AND%20cvss3_severity%3A(CRITICAL%20OR%20HIGH)&sort=&page=N`.
                - **Fallback Method (`browser_agent_tool`):** If the primary method fails or returns incomplete, JavaScript-dependent content, you must use the `browser_agent_tool` to get the fully rendered HTML of the same page.
            - **B. Scrape and Filter:** Once you have the HTML, scrape all CVE IDs from the page. Then, immediately filter them using the EPSS API (score > 5% or percentile > 50%).
            - **C. Enrich:** For the small list of CVEs that passed the filter, immediately gather all enrichment data by calling `get_nvd_data`, `check_cisa_kev`, `get_otx_cve_details`, and `get_github_advisory`.
            - **D. Submit:** Immediately take the fully enriched batch of CVEs and submit it using the `submit_cves` tool.
        - **You must continue this page-by-page loop until all pages have been processed.** Your task is not complete until the last page of results from Tenable has been analyzed and submitted.
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