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
from strands_tools import python_repl, current_time, workflow
import manus_use.tools.obtain_cves as obtain_cves
import manus_use.tools.submit_cves as submit_cves

class VulnerabilityDiscoveryAgent:
    """An agent that orchestrates a vulnerability discovery workflow."""

    def __init__(self, model_name: str):
        self.system_prompt = """
        You are a master control agent. Your job is to orchestrate a workflow to discover and submit vulnerabilities using the workflow tool.

        **Workflow Steps:**
        1. FIRST: Use python_repl and current_time to calculate date ranges for the last three months. Calculate three separate time slices with start_date and end_date for each. Store these exact dates.
        
        2. THEN: Create a workflow with the following tasks, using the EXACT dates calculated in step 1:
           - Task 1: Obtain and submit CVEs for time slice 1 - use the EXACT start_date and end_date from FIRST step's slice 1 with obtain_cves, then immediately submit the results using submit_cves (tools: ["obtain_cves", "submit_cves"])
           - Task 2: Obtain and submit CVEs for time slice 2 - use the EXACT start_date and end_date from FIRST step's slice 2 with obtain_cves, then immediately submit the results using submit_cves (tools: ["obtain_cves", "submit_cves"])
           - Task 3: Obtain and submit CVEs for time slice 3 - use the EXACT start_date and end_date from FIRST step's slice 3 with obtain_cves, then immediately submit the results using submit_cves (tools: ["obtain_cves", "submit_cves"])
           - Task 4: Verify all submissions were successful by checking the results from Tasks 1-3 (depends on Tasks 1,2,3, tools: ["python_repl"])
        
        IMPORTANT: 
        - Calculate the date ranges in STEP 1 BEFORE creating the workflow
        - When creating each task, include the ACTUAL date values from step 1 in the task description (e.g., "start_date: 2024-04-26, end_date: 2024-05-26")
        - The obtain_cves tool already filters for high EPSS scores
        - Each task obtains CVEs and immediately submits them in the same task
        - Tasks 1-3 will run in parallel since they have no dependencies
        
        Use the workflow tool with action="create" to create the workflow, then action="start" to execute it.
        Each task should specify:
        - appropriate tools and dependencies
        - "model_provider": "bedrock"
        - "model_id": "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
        """
        # or "us.anthropic.claude-sonnet-4-20250514-v1:0"
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
        from strands.models import BedrockModel
        bedrock_model = BedrockModel(
            model_id=model_name,
            #region_name="us-east-1",  # Specify a different region than the default
            temperature=0.3,
            top_p=0.8,
            #stop_sequences=["###", "END"],
            boto_client_config=boto_config,
            #client = client
        )
        self.agent = Agent(
            model=bedrock_model,
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
    print("=== Vulnerability Discovery Agent (Multi-Agent Edition) ===")
    model_name = "us.anthropic.claude-sonnet-4-20250514-v1:0"
    discovery_agent = VulnerabilityDiscoveryAgent(model_name=model_name)
    analysis_request = "Please define and execute the vulnerability discovery workflow."
    result = discovery_agent.handle_request(analysis_request)
    print("\n--- Final Response from Agent ---")
    print(result)

if __name__ == "__main__":
    main()
