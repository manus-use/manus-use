#!/usr/bin/env python3
"""
Master agent that uses the workflow tool to discover vulnerabilities.
"""

import os
import sys
from pathlib import Path
import warnings
warnings.filterwarnings("ignore")
os.environ["BYPASS_TOOL_CONSENT"] = "True"

sys.path.insert(0, str(Path(__file__).parent / "src"))

from strands import Agent
from strands_tools import workflow, python_repl, current_time
import manus_use.tools.obtain_cves as obtain_cves
import manus_use.tools.submit_cves as submit_cves

class VulnerabilityDiscoveryAgent:
    """An agent that orchestrates a vulnerability discovery workflow."""

    def __init__(self, model_name: str):
        self.system_prompt = """
        You are a master control agent. Your job is to define and execute a precise workflow to discover and submit vulnerabilities.

        **Workflow to Execute:**
        1.  **Calculate Date Ranges:** Use `python_repl` and `current_time` to get the date ranges for the last three months, sliced relative to today. The ranges must be inclusive. For example, if today is July 15th:
            - The first slice is from June 15th to July 15th (inclusive).
            - The second slice is from May 15th to June 14th.
            - The third slice is from April 15th to May 14th.
        2.  **Define the Workflow:** Construct a `workflow` with a sequence of steps for each of the three time slices. For each slice, you must first call `obtain_cves`.
        3.  **Submit CVEs:** After obtaining the CVEs, you must call `submit_cves` with the results. Before calling `submit_cves`, you must ensure that the `cve_list` from the `obtain_cves` step is not empty.
        4.  **Verify Submission:** After calling `submit_cves`, you must verify that the submission was successful by checking the output of the `submit_cves` tool. The output should indicate a successful submission.
        """
        self.agent = Agent(
            model=model_name,
            system_prompt=self.system_prompt,
            tools=[
                workflow,
                obtain_cves,
                submit_cves,
                python_repl,
                current_time
            ]
        )

    def handle_request(self, request: str) -> str:
        """Handles a user request by invoking the agent."""
        print("INFO: Discovery Agent received request. Defining and executing workflow...")
        return self.agent(request)

def main():
    """Main execution block."""
    print("=== Vulnerability Discovery Agent (Workflow Edition) ===")
    model_name = "us.anthropic.claude-sonnet-4-20250514-v1:0"
    discovery_agent = VulnerabilityDiscoveryAgent(model_name=model_name)
    analysis_request = "Please define and execute the vulnerability discovery workflow."
    result = discovery_agent.handle_request(analysis_request)
    print("\n--- Final Response from Agent ---")
    print(result)

if __name__ == "__main__":
    main()
