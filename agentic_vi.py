# CLAUDE MODEL SETUP
import boto3
from botocore.config import Config
from langchain_aws import BedrockLLM, ChatBedrock
from browser_use import Agent
from browser_use.browser.browser import Browser, BrowserConfig
from browser_use.controller.service import Controller
import asyncio

import os
from dotenv import load_dotenv
load_dotenv()

boto_config = Config(connect_timeout=500, read_timeout=500, retries={'max_attempts': 5})

bedrock_runtime = boto3.client(
    service_name="bedrock-runtime",
    region_name=os.getenv("AWS_REGION_NAME"),
    endpoint_url=os.getenv("AWS_ENDPOINT_URL"),
    config=boto_config
)

class_mapping = {
    "Bedrock": BedrockLLM,
    "BedrockChat": ChatBedrock,
}

def initialize_model():
    model_class = class_mapping["BedrockChat"]
    model_id = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
    model_kwargs = {
        "max_tokens": 128000,
        "temperature": 1,
        "top_k": 250,
        "top_p": 0.999,
        "stop_sequences": ["\n\nHuman:"]
    }
    return model_class(
        client=bedrock_runtime,
        model_id=model_id,
        model_kwargs=model_kwargs,
        config=boto_config
    )

task = """Please go to https://github.com/advisories to assess top 10 critical CVEs happened today with Exploitation Scenarios and Detection."""
# https://www.tenable.com/cve/search?q=cvss3_severity%5C%3A%28CRITICAL%29+AND+%28python+OR+golang+OR+java+OR+javascript+OR+chrome%29+AND+%22published%5C%3A%5B2025-04-01%22+TO+%222025-04-30%5D%22+AND+cvss3_severity%3A%28CRITICAL%29&sort=newest&page=1
llm = initialize_model()

browser = Browser(
    config=BrowserConfig(
        headless=False
    )
)

agent = Agent(
    task=task, llm=llm, controller=Controller(), browser=browser, validate_output=False,
)

async def main():
    await agent.run(max_steps=300)
    await browser.close()

asyncio.run(main())