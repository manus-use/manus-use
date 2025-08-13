#!/usr/bin/env python3
"""
Master agent that uses a multi-agent approach to discover and submit vulnerabilities.
"""

import os
import sys
from pathlib import Path
import warnings

warnings.filterwarnings("ignore")
os.environ["BYPASS_TOOL_CONSENT"] = "True"

sys.path.insert(0, str(Path(__file__).parent / "src"))

from strands import Agent
from strands import tool
from strands_tools import python_repl, current_time
import manus_use.tools.obtain_cves as obtain_cves
import manus_use.tools.submit_cves as submit_cves

def get_bedrock_model(model_name, regoin_name):
    from botocore.config import Config as BotocoreConfig

    # Create a boto client config with custom settings
    boto_config = BotocoreConfig(
        retries={"max_attempts": 3, "mode": "standard"},
        connect_timeout=30,
        read_timeout=1000
    )
    #from boto3 import client
    #client = client(service_name='bedrock-runtime',
    #              config=boto_config)
    # Create a configured Bedrock model
    # eu-west-1
    from strands.models import BedrockModel
    bedrock_model = BedrockModel(
        model_id=model_name,
        region_name=regoin_name, #"eu-west-1",  # Specify a different region than the default
        temperature=0.3,
        top_p=0.8,
        #stop_sequences=["###", "END"],
        boto_client_config=boto_config,
        #client = client
    )
    return bedrock_model

@tool
def capture_cves(time_slices: list) -> str:
    """ Obtain and submite CVEs based on specific time slices
    Args:
        time_slices: A list of time slices, where each item is a dict containing 'start_date' and 'end_date', like: {'start_date': '2025-07-21', 'end_date': '2025-07-27'}.
    """
    system_prompt = "You are a cybersecurity intelligence expert to discover and submit vulnerabilities using the `obtain_cves` and `submit_cves` tools by first using obtain_cves then immediately submit the results using submit_cves. - The obtain_cves tool already filters for high EPSS scores - After obtaining CVEs and immediately submits them. - Make sure all CVEs be submitted"
    # If time_slices contain 'end_date', sort by 'end_date' descending before entering the loop
    if time_slices and time_slices and 'end_date' in time_slices[0]:
        time_slices = sorted(time_slices, key=lambda x: x['end_date'], reverse=True)
    #time_slices = sorted(time_slices, key=lambda x: x['end_date'], reverse=True)
    import concurrent.futures

    def process_time_slice(time_slice):
        print(time_slice)
        agent = Agent(
            model=get_bedrock_model("eu.anthropic.claude-sonnet-4-20250514-v1:0", "eu-west-1"),#us.anthropic.claude-3-7-sonnet-20250219-v1:0"),
            system_prompt=system_prompt,
            tools=[
                obtain_cves,
                submit_cves
            ]
        )
        result = agent(f"please obtain and submit CVEs in the time slice: {time_slice}")
        print(result)
        return result

    # Use a thread pool sized to the number of available CPUs, which is a best practice for I/O-bound tasks
    import os
    max_workers = min(32, (os.cpu_count() or 1) + 4)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_time_slice, time_slice) for time_slice in time_slices]
        results = []
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
        return results
    """
        for time_slice in time_slices:
        print(time_slice)
        result = agent(f"please obtain and submit CVEs in the time slice: {time_slice}")
        print(result)
    """

    return f"capturing CVEs for {time_slices} is done"

class VulnerabilityDiscoveryAgent:
    """An agent that orchestrates a vulnerability discovery workflow."""

    def __init__(self, model_name: str):
        self.system_prompt = """
        You are a master control agent. Your job is to calculate date ranges by a week to discover and submit vulnerabilities using the `capture_cves` tool.

        **Steps:**
        1. FIRST: Use python_repl and current_time to calculate time slices for the last three months, including the present date. Calculate separate time slices to present date, each referring to one week, with start_date and end_date for each. Store these exact dates, such as {'start_date': '2025-07-21', 'end_date': '2025-07-27'}.
        2. THEN: Capture CVEs with the following tasks, using the EXACT time slices calculated in step 1:
           - Task 1: Capture CVEs for EXACT time slices - use the list of EXACT time slices contain start date and end date from FIRST step's output with the tool `capture_cves`
           - Task 2: Verify all submissions were successful by checking the results from Tasks 1
        
        IMPORTANT: 
        - Calculate the time slices in STEP 1 BEFORE using the tool `capture_cves`
        """
        # or "us.anthropic.claude-sonnet-4-20250514-v1:0"
 
        self.agent = Agent(
            model=get_bedrock_model(model_name, "us-west-2"),
            system_prompt=self.system_prompt,
            tools=[
                python_repl,
                current_time,
                capture_cves
            ]
        )

    def handle_request(self, request: str) -> str:
        """Handles a user request by invoking the agent."""
        print("INFO: Discovery Agent received request. Defining and executing workflow...")
        return self.agent(request)

def main():
    """Main execution block."""
    print("=== Vulnerability Discovery Agent (Multi-Agent Edition) ===")
    model_name = "us.anthropic.claude-sonnet-4-20250514-v1:0"
    discovery_agent = VulnerabilityDiscoveryAgent(model_name=model_name)
    analysis_request = "Please define and execute the vulnerability discovery workflow."
    result = discovery_agent.handle_request(analysis_request)
    print("\n--- Final Response from Agent ---")
    print(result)

if __name__ == "__main__":
    main()
