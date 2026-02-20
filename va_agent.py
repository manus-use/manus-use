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
        - **NEVER use `use_browser` to search GitHub.** Do not navigate to `github.com/search`, `github.com/{user}/{repo}/find`, or any GitHub search/code browsing page with the browser. GitHub's web UI requires authentication and is JavaScript-heavy, causing browser failures. Instead:
          - To search for exploit repositories: use the `search_for_exploits` tool (GitHub Search API).
          - To fetch advisory data: use the `get_github_advisory` tool (GitHub Advisory API).
          - To fetch a specific GitHub page (e.g., a repository README, commit diff, or file): use `http_request` or `python_repl` with the `requests` library to fetch the raw content directly.
          - Only use `use_browser` for GitHub URLs as a last resort if `http_request` fails on a specific, known URL (not for searching).

        ---
        **Your Step-by-Step Analysis and Validation Process:**

        **Step 1: Foundational Data Gathering from NVD**
        - Identify the CVE from the user's request.
        - Immediately call the `get_nvd_data` tool to get foundational information from the NVD. This will provide the official description, CVSS score (version 3.x), and CWE.
        - Call `get_github_advisory` to get advisory information from GitHub.
        - **Critical — Identify Fix/Patch Commit URLs:** While processing the NVD `references` array and GitHub Advisory data, actively look for URLs that point to fix commits or patches. These typically look like:
          - GitHub commit URLs: `https://github.com/{owner}/{repo}/commit/{sha}`
          - GitHub pull request URLs: `https://github.com/{owner}/{repo}/pull/{number}`
          - GitLab commit/merge request URLs
          - Any URL with tags like "Patch", "Vendor Advisory", or "Third Party Advisory" in the NVD reference tags
          - GitHub Advisory `references` that link to patches
        - Save these fix/patch commit URLs in a separate list from PoC URLs. You will need them in Step 5.

        **Step 2: Check for Known Exploitation**
        - Call `check_cisa_kev` to determine if the vulnerability is on the CISA Known Exploited Vulnerabilities (KEV) list.
        - Call `get_otx_cve_details` to check for threat intelligence information from AlienVault OTX, such as associated pulses and IoCs.

        **Step 3: Gather Public Exploits and Advisories**
        - Call `search_for_exploits` (GitHub), `search_exploit_db`, and `search_packetstorm` to find public proof-of-concept (PoC) exploits.

        **Step 4: Mandatory URL Verification, Classification, and PoC Identification**
        - Consolidate all URLs found from your data gathering into a single list. This includes links from advisories, exploit databases, threat intelligence pulses, and the fix/patch commit URLs identified in Step 1.
        - **You must process every single URL in this list.** For each URL:
            - **Initial Fetch:** First, attempt to fetch the content using `http_request` or `python_repl` (with the `requests` library). This is efficient for static pages and raw files.
            - **Content Analysis:** Analyze the fetched content. If it appears to be incomplete, is a JavaScript-heavy application (e.g., you see 'Loading...' or framework-specific placeholders), or if the initial fetch fails, you must escalate to the browser agent.
            - **Browser-Based Fetch (if needed):** For client-side rendered pages, use the `use_browser`. Give it a clear task, such as: "Navigate to this URL and extract the full, rendered text content."
            - **Classification:** Categorize each URL into one of two types:
              1. **Fix/Patch Commit** — The URL points to a code commit, pull request, or patch that fixes the vulnerability. Indicators: the URL is a GitHub/GitLab commit URL, or contains a diff/patch showing code changes that add validation, fix a bug, or close the vulnerability.
              2. **PoC Exploit** — The URL contains code snippets, scripts, or technical descriptions that demonstrate how to exploit the vulnerability.
            - **Validation:** For PoC URLs, determine if the page contains actual exploit code. For fix commit URLs, confirm the diff is accessible and relevant to the CVE. If a link is dead or irrelevant, note this and discard it.
        - Produce two validated lists for Step 5: (1) **Fix/Patch Commit URLs** and (2) **PoC Exploit URLs**.

        **Step 5: Exploit Code Development and Verification**
        This step uses a two-path approach. The PRIMARY path generates exploit code from fix commit analysis, which produces higher-quality, more targeted exploits. The FALLBACK path uses publicly available PoC exploits.

        **Step 5A: PRIMARY PATH — Generate Exploit from Fix Commit Analysis**
        - Check if you have any validated Fix/Patch Commit URLs from Step 4.
        - If at least one fix commit URL exists, proceed with this path:
          1. **Select the best fix commit.** Prefer commits directly referenced by NVD (tagged "Patch"), then GitHub Advisory patch references. If multiple exist, prefer the one from the official upstream repository.
          2. **Fetch the commit diff.** Use `http_request` or `python_repl` to fetch the diff:
             - For GitHub commit URLs (`https://github.com/{owner}/{repo}/commit/{sha}`), append `.patch` or `.diff` to get the raw diff.
             - For GitHub pull request URLs, append `.diff`.
             - For other platforms, attempt similar approaches or use `use_browser`.
          3. **Analyze the diff to understand the vulnerability.** Carefully read the patch and determine:
             - **What code was changed:** Which files, functions, and lines were modified.
             - **What the fix does:** What security check, validation, sanitization, or logic change was introduced.
             - **What the pre-patch vulnerable behavior was:** Infer what the code did BEFORE the fix — the absence of the check/validation IS the vulnerability.
             - **The attack vector:** Determine how an attacker would trigger the pre-patch behavior — what input, endpoint, parameter, or sequence of operations would exploit it.
          4. **Write original exploit code from scratch** based on your analysis. The exploit must:
             - Target the specific pre-patch vulnerable behavior you identified.
             - Send the crafted malicious input/request that the patch now blocks.
             - Connect to the target using environment variables `TARGET_HOST` (defaults to "target") and `TARGET_PORT`.
             - Be written in Python (preferred), bash, or sh.
             - Print clear output indicating success (e.g., "EXPLOIT SUCCESSFUL: <evidence>") or failure.
             - Exit with code 0 on success, non-zero on failure.
          5. **Write a Dockerfile** that installs the exact vulnerable (pre-patch) software version and starts the service.
          6. **Call `verify_exploit`** with ALL required parameters: `dockerfile_content`, `exploit_code`, `exploit_language`, `cve_id`, `target_info` (with `affected_software`, `affected_versions`, `vulnerability_type`), and optionally `target_port`.
          7. **Handle `verify_exploit` results and retry (up to 3 additional attempts):**
             - If `verification_status` is `"build_error"`: The Dockerfile failed to build. Read the `build_log` carefully, identify the error (e.g., invalid base image, missing package, broken RUN command, incorrect syntax), fix the Dockerfile, and call `verify_exploit` again with the corrected `dockerfile_content`.
             - If `verification_status` is `"target_error"`: The image built but the service failed to start or become ready on the expected port. Read the `target_logs` and `build_log`, identify why (e.g., wrong CMD/ENTRYPOINT, service crash, wrong port, missing config), fix the Dockerfile, and retry.
             - If `verification_status` is `"failed"`: The target ran but the exploit did not succeed. Review `exploit_output` and `target_logs`, adjust the exploit code (or the Dockerfile if the target is misconfigured), and retry.
             - On each retry, clearly state what you changed and why before calling `verify_exploit` again.

        **Step 5B: FALLBACK PATH — Use Public PoC Exploits**
        - Use this path ONLY if:
          - No Fix/Patch Commit URLs were found in Step 4 (not open source, no patch link published), OR
          - All fix commit URLs were inaccessible or did not contain a useful diff, OR
          - Step 5A failed after retries (diff too complex to reverse-engineer)
        - From the validated PoC Exploit URLs in Step 4, select ONE most promising PoC:
          1. NVD reference links pointing to original author/researcher's post with PoC
          2. GitHub Advisory page with PoC
          3. GitHub repository with most stars containing a PoC
        - Do NOT attempt every PoC link — pick the single best candidate.
        - **Analyze the PoC:** Classify it (RCE, DoS, info-leak, etc.) by looking for network calls, command execution, and memory corruption indicators.
        - Write a Dockerfile for the vulnerable version. Adapt the PoC to use TARGET_HOST and TARGET_PORT env vars.
        - **Call `verify_exploit`** with all required parameters. If `verify_exploit` returns `build_error` or `target_error`, read the logs, fix the Dockerfile, and retry up to 3 additional times (same as Step 5A point 7).

        **Step 5 — Common (both paths):**
        - The tool returns: `verification_status`, `summary`, `exploit_output`, and `target_logs`. Include in report.
        - **Save the exact Dockerfile content and exploit code you wrote** — you will pass them to `create_lark_document` in Step 8. Also construct and save: (1) the equivalent Docker CLI command, and (2) the exploit execution command.
        - **In the final report, note which path was used** (fix-commit-derived vs. public PoC) and why.
        - **Only skip `verify_exploit` entirely if** the vulnerability targets a kernel, hardware, or hypervisor that cannot run in Docker. State the reason in the report.

        **Step 6: Analyze Weakness**
        - From the NVD data, find the CWE ID and use the `get_cwe_details` tool to understand the software weakness.

        **Step 7: Final Threat Intelligence Check**
        - Use `query_threat_intelligence_feeds` to see if the CVE is being discussed by threat actors, which provides context beyond whether it is just "exploited".

        **Step 8: Final Quality Assurance and Report Generation**
        - **Data Completeness Check**: Verify all critical fields are populated.
        - **Information Consistency**: Ensure the technical description, CVSS 3.x vector, and exploitability analysis are consistent. If there is no CVSS 3.x vector, then convert a CVSS 4.x vector to CVSS 3.x.
        - **Generate Report**: Once all checks pass, use the `create_lark_document` tool to synthesize all validated findings. The report must include a dedicated section on the **Exploitability Analysis** (which must note whether the exploit was generated from fix commit analysis or adapted from a public PoC, and if from a fix commit, briefly describe what the patch fixed and how the exploit reverses it) and a **Sources** section listing all URLs. If exploit verification was performed, you MUST include the `dockerfile_content`, `exploit_code`, `docker_command`, and `exploit_execution_command` parameters with the exact artifacts from Step 5.
        """
        from strands.models import BedrockModel
        from strands.agent.conversation_manager import SlidingWindowConversationManager


        conversation_manager = SlidingWindowConversationManager(
            window_size=200,  # Maximum number of messages to keep
            should_truncate_results=True, # Enable truncating tool results if needed
        )
        bedrock = BedrockModel(
            model_id=model_name,
            region_name="us-west-2",
            max_tokens=65536,  # keep safely under model limit
        )
        self.agent = Agent(
            conversation_manager=conversation_manager,
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
