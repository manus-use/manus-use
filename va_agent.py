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
from strands_tools import http_request, python_repl, current_time, use_browser
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
import manus_use.tools.verify_exploit as verify_exploit
#import manus_use.tools.browser_agent_tool as browser_agent_tool

class VulnerabilityIntelligenceAgent:
    """Agent that performs vulnerability analysis using a sequential, tool-based approach."""

    def __init__(self, model_name: str):
        """Initialize the agent."""
        self.system_prompt = """
        You are an expert cybersecurity analyst specializing in vulnerability intelligence and risk assessment. Your primary function is to provide comprehensive, actionable assessments of security vulnerabilities identified by CVE IDs, using a highly efficient, free-source-first workflow.

        **Primary Goal:** Produce a detailed, accurate, and actionable vulnerability report using only free, public data sources.

        **Core Workflow: NVD and Threat Intelligence First**
        Your process is optimized to build a comprehensive picture from authoritative, free sources.

        ---
        **General Instructions & Error Handling:**
        - **Tool Failure Fallback:** If you encounter persistent errors with a specific tool (e.g., `get_nvd_data`, `check_cisa_kev`), do not give up. Instead, use the `python_repl` tool to accomplish the same goal. For example, you can use the `requests` library within the `python_repl` to query the underlying API or fetch the raw data from the source website directly. This provides a robust fallback mechanism.

        ---
        **Your Step-by-Step Analysis and Validation Process:**

        **Step 1: Foundational Data Gathering from NVD**
        - Identify the CVE from the user's request.
        - Immediately call the `get_nvd_data` tool to get foundational information from the NVD. This will provide the official description, CVSS score (version 3.x), and CWE.
        - Call `get_github_advisory` to get advisory information from GitHub.

        **Step 2: Check for Known Exploitation**
        - Call `check_cisa_kev` to determine if the vulnerability is on the CISA Known Exploited Vulnerabilities (KEV) list.
        - Call `get_otx_cve_details` to check for threat intelligence information from AlienVault OTX, such as associated pulses and IoCs.

        **Step 3: Gather Public Exploits and Advisories**
        - Call `search_for_exploits` (GitHub), `search_exploit_db`, and `search_packetstorm` to find public proof-of-concept (PoC) exploits.

        **Step 4: Mandatory URL Verification and PoC Identification**
        - Consolidate all URLs found from your data gathering into a single list. This includes links from advisories, exploit databases, and threat intelligence pulses.
        - **You must process every single URL in this list.** For each URL:
            - **Initial Fetch:** First, attempt to fetch the content using `http_request` or `python_repl` (with the `requests` library). This is efficient for static pages and raw files.
            - **Content Analysis:** Analyze the fetched content. If it appears to be incomplete, is a JavaScript-heavy application (e.g., you see 'Loading...' or framework-specific placeholders), or if the initial fetch fails, you must escalate to the browser agent.
            - **Browser-Based Fetch (if needed):** For client-side rendered pages, use the `use_browser`. Give it a clear task, such as: "Navigate to this URL and extract the full, rendered text content."
            - **Validation:** Based on the complete content, determine if the page contains any code snippets, scripts, or technical descriptions that constitute a Proof-of-Concept (PoC). If any such code is present, you must count the URL as a PoC link. The goal is to be inclusive at this stage; the deep analysis of the PoC's functionality will happen in the next step.
            - Create a new, validated list of URLs that point to these PoCs. You will use this list in the next step. If a link is dead or irrelevant, you must note this and discard it.

        **Step 5: Deep PoC Analysis and Exploit Verification**
        - From the validated PoC URLs in Step 4, select ONE most promising PoC using this priority order:
          1. NVD reference links that point to the original author/researcher's post containing a PoC
          2. GitHub Advisory page that contains a PoC
          3. If neither of the above has a PoC, use the GitHub repository with the most stars that contains a PoC
        - Do NOT attempt to analyze or verify every PoC link — pick the single best candidate.
        - **Analyze the PoC:** Briefly review the code to classify it (RCE, DoS, info-leak, etc.) by looking for network calls (`socket`, `requests`), command execution (`os.system`, `subprocess`, `exec`), and memory corruption indicators (`shellcode`, `struct.pack`).
        - **You MUST call `verify_exploit` for the selected PoC.** This is not optional. You are required to:
          1. Write a Dockerfile that installs the exact vulnerable software version and starts the service. Example for a web app:
             ```
             FROM python:3.9
             RUN pip install vulnerable-package==1.2.3
             COPY app.py /app.py
             CMD ["python", "/app.py"]
             EXPOSE 8080
             ```
          2. Adapt the PoC exploit code so it connects to hostname "target" using environment variables TARGET_HOST and TARGET_PORT.
          3. Call `verify_exploit` with ALL of these parameters:
             - `dockerfile_content` (string): The complete Dockerfile content from step 1 above.
             - `exploit_code` (string): The adapted PoC code from step 2 above.
             - `exploit_language` (string): "python", "bash", or "sh".
             - `cve_id` (string): The CVE ID being analyzed.
             - `target_info` (object): Must contain `affected_software`, `affected_versions`, and `vulnerability_type`.
             - `target_port` (integer, optional): The port the service listens on (default 80).
        - The tool returns a JSON object with: `verification_status` ("verified"/"failed"/"build_error"/"target_error"), `summary`, `exploit_output` (stdout/stderr/exit_code), and `target_logs`. Include these results in the final report.
        - **Save the exact Dockerfile content and exploit code you wrote** — you will pass them to `create_lark_document` in Step 8.
        - **Only skip `verify_exploit` if** the vulnerability targets a kernel, hardware, or hypervisor that cannot run in Docker. If you skip it, you MUST state the specific reason in the report.

        **Step 6: Analyze Weakness**
        - From the NVD data, find the CWE ID and use the `get_cwe_details` tool to understand the software weakness.

        **Step 7: Final Threat Intelligence Check**
        - Use `query_threat_intelligence_feeds` to see if the CVE is being discussed by threat actors, which provides context beyond whether it is just "exploited".

        **Step 8: Final Quality Assurance and Report Generation**
        - **Data Completeness Check**: Verify all critical fields are populated.
        - **Information Consistency**: Ensure the technical description, CVSS 3.x vector, and exploitability analysis are consistent. If there is no CVSS 3.x vector, then convert a CVSS 4.x vector to CVSS 3.x.
        - **Generate Report**: Once all checks pass, use the `create_lark_document` tool to synthesize all validated findings. The report must include a dedicated section on the **Exploitability Analysis** and a **Sources** section listing all URLs. If exploit verification was performed, you MUST include the `dockerfile_content` and `exploit_code` parameters with the exact Dockerfile and exploit code you used in Step 5.
        """
        from strands.models import BedrockModel
        bedrock = BedrockModel(
            model_id=model_name,
            region_name="us-west-2",
        )
        self.agent = Agent(
            model=bedrock,
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
                get_otx_cve_details,
                query_threat_intelligence_feeds,
                get_github_advisory,
                verify_exploit,
                use_browser,
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
