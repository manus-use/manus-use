#!/usr/bin/env python3
"""
Strands Agent that performs vulnerability analysis using a sequential, tool-based approach.
"""

import os
import sys
from pathlib import Path
import warnings
warnings.filterwarnings("ignore")
os.environ["BYPASS_TOOL_CONSENT"] = "True"


# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Import Strands SDK and required tools
from strands import Agent
from strands_tools import http_request, python_repl, current_time
# Import specific tool functions directly
import manus_use.tools.get_nvd_data as get_nvd_data
import manus_use.tools.search_for_exploits as search_for_exploits
import manus_use.tools.get_cwe_details as get_cwe_details
import manus_use.tools.search_exploit_db as search_exploit_db
import manus_use.tools.search_packetstorm as search_packetstorm
import manus_use.tools.create_lark_document as create_lark_document
import manus_use.tools.query_threat_intelligence_feeds as query_threat_intelligence_feeds
import manus_use.tools.get_github_advisory as get_github_advisory
import manus_use.tools.check_cisa_kev as check_cisa_kev
import manus_use.tools.get_otx_cve_details as get_otx_cve_details

class VulnerabilityIntelligenceAgent:
    """Agent that performs vulnerability analysis using a sequential, tool-based approach."""

    def __init__(self, model_name: str):
        """Initialize the agent."""
        self.system_prompt = """
        You are an expert cybersecurity analyst specializing in vulnerability intelligence and risk assessment. Your primary function is to provide comprehensive, actionable assessments of security vulnerabilities identified by CVE IDs, using a highly efficient, source-driven workflow.

        **Primary Goal:** Produce a detailed, accurate, and actionable vulnerability report.

        **Core Workflow: VulnCheck First**
        Your process is optimized for speed and accuracy. You will start with the most comprehensive data source, `search_vulncheck_xdb`, and then use other tools to fill in gaps or perform deeper analysis only when necessary.

        ---
        **Your Step-by-Step Analysis and Validation Process:**

        **Step 1: Comprehensive Initial Query with VulnCheck**
        - Identify the CVE from the user's request.
        - Immediately call the `search_vulncheck_xdb` tool. This is your primary data source and will provide a wealth of aggregated information, including description, CVSS score, exploit links, and CISA KEV status.

        **Step 2: Analyze VulnCheck Results and Determine Next Steps**
        - Carefully review the output from `search_vulncheck_xdb`.
        - **If the VulnCheck result is comprehensive (contains description, CVSS, and exploit links):**
            - You have a strong baseline. Proceed directly to **Step 4**, using the data from VulnCheck as the primary input.
        - **If the VulnCheck result is sparse or returns an error:**
            - Proceed to **Step 3** to gather data from more specific sources.

        **Step 3: Fallback Data Gathering (Only if Step 2 determines it's necessary)**
        - Call `get_nvd_data` to get foundational information from the NVD.
        - Call `get_github_advisory` to get advisory information from GitHub.
        - Call `check_cisa_kev` to check for active exploitation.
        - Use these tools to build the baseline information that VulnCheck would have provided.

        **Step 4: Gather and Analyze References & Exploits**
        - Consolidate all URLs found from your initial data gathering (either from `search_vulncheck_xdb` in Step 1 or the fallback tools in Step 3). This includes exploit PoCs, vendor advisories, and security articles.
        - **If the VulnCheck results did not provide a rich set of exploit PoCs and references:**
            - Call `search_for_exploits` (GitHub), `search_exploit_db`, and `search_packetstorm` to ensure complete coverage. Add any new PoCs found to your consolidated list.
        - For each unique and relevant URL:
            - Use `http_request` for straightforward fetches.
            - Use `python_repl` to analyze the fetched content for deeper technical details, context, or corroborating evidence.

        **Step 5: PoC and Exploit Quality Validation**
        - For each unique PoC found, perform the following validation:
        - **Source Credibility**: Prioritize PoCs from VulnCheck, Exploit-DB, reputable security researchers' GitHubs, and official vendor advisories.
        - **Code Analysis (Static)**: If PoC code is accessible, use `python_repl` to fetch and analyze it for functionality indicators (e.g., `socket`, `os.system`) and red flags (e.g., obfuscation).
        - **Documentation Review**: Assess if the PoC has clear setup instructions and expected outcomes.

        **Step 6: Analyze Weakness**
        - From the NVD or VulnCheck data, find the CWE ID and use the `get_cwe_details` tool to understand the software weakness.

        **Step 7: Final Threat Intelligence Check**
        - Use `get_otx_cve_details` to check for threat intelligence information from AlienVault OTX.
        - Use `query_threat_intelligence_feeds` to see if the CVE is being discussed by threat actors, which provides context beyond whether it is just "exploited".

        **Step 8: Final Quality Assurance and Report Generation**
        - **Data Completeness Check**: Verify all critical fields are populated.
        - **Information Consistency**: Ensure the technical description, CVSS vector, and exploitability analysis are consistent.
        - **Generate Report**: Once all checks pass, use the `create_lark_document` tool to synthesize all validated findings. The report must include a dedicated section on the **Exploitability Analysis** and a **Sources** section listing all URLs.
        """
        self.agent = Agent(
            model=model_name,
            system_prompt=self.system_prompt,
            tools=[
                http_request,
                python_repl,
                current_time,
                create_lark_document,
                get_nvd_data,
                search_for_exploits,
                get_cwe_details,
                search_exploit_db,
                search_packetstorm,
                check_cisa_kev,
                search_vulncheck_xdb,
                get_otx_cve_details,
                query_threat_intelligence_feeds,
                get_github_advisory,
            ]
        )

    def handle_request(self, request: str) -> str:
        """Handles a user request by invoking the agent."""
        print("INFO: Agent received request. It will now execute the analysis sequentially...")
        response = self.agent(request)
        return response

# --- Main Execution Block ---
def main():
    """Example of using the simplified VulnerabilityIntelligenceAgent."""
    print("=== Simplified Vulnerability Intelligence Agent ===")

    # Simplified and robust configuration handling
    try:
        from manus_use.config import Config
        config = Config.from_file()
        # Use a specific, powerful model suitable for orchestration
        model_name = "us.anthropic.claude-sonnet-4-20250514-v1:0"
        print(f"Using configured model: {model_name}")
    except Exception as e:
        model_name = "us.anthropic.claude-sonnet-4-20250514-v1:0"  # A sensible default
        print(f"Could not load config ({e}), using default model: {model_name}")

    # Create the agent
    vi_agent = VulnerabilityIntelligenceAgent(model_name=model_name)

    # Get CVE from command-line arguments or use an example for demonstration
    if len(sys.argv) > 1:
        cve_id = sys.argv[1]
    else:
        cve_id = "CVE-2025-6554"
        print(f"No CVE provided. Using example: {cve_id}")

    # The request is a high-level instruction to the agent.
    analysis_request = f"""
    Please perform a comprehensive vulnerability intelligence analysis for {cve_id}.
    Follow your sequential process and create a Lark document with the final report.
    """

    print(f"\n--- Sending analysis request to agent for: {cve_id} ---")
    result = vi_agent.handle_request(analysis_request)
    print("\n--- Final Response from Agent ---")
    print(result)


if __name__ == "__main__":
    main()
