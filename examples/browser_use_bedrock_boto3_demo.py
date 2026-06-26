#!/usr/bin/env python3
"""Demo: browser-use agent with AWS Bedrock (boto3/langchain_aws) — no headless.

Connects directly to Bedrock via boto3 rather than through the ManusUse
config system, which is useful for experimenting with raw browser-use behaviour.

Usage::

    export AWS_REGION_NAME=us-east-1   # or set in a .env file
    python examples/browser_use_bedrock_boto3_demo.py
"""

import asyncio
import os

import boto3
from botocore.config import Config as BotocoreConfig
from browser_use import Agent
from browser_use.browser.browser import Browser, BrowserConfig
from browser_use.controller.service import Controller
from dotenv import load_dotenv
from langchain_aws import ChatBedrock

load_dotenv()

boto_config = BotocoreConfig(
    connect_timeout=500,
    read_timeout=500,
    retries={"max_attempts": 5},
)

bedrock_runtime = boto3.client(
    service_name="bedrock-runtime",
    region_name=os.getenv("AWS_REGION_NAME", "us-east-1"),
    endpoint_url=os.getenv("AWS_ENDPOINT_URL"),
    config=boto_config,
)

llm = ChatBedrock(
    client=bedrock_runtime,
    model_id="us.anthropic.claude-3-7-sonnet-20250219-v1:0",
    model_kwargs={
        "max_tokens": 128000,
        "temperature": 1,
        "top_k": 250,
        "top_p": 0.999,
        "stop_sequences": ["\n\nHuman:"],
    },
    config=boto_config,
)

TASK = (
    "Go to https://github.com/advisories and assess the top 10 critical CVEs "
    "published today, including exploitation scenarios and detection guidance."
)

browser = Browser(config=BrowserConfig(headless=False))
agent = Agent(
    task=TASK,
    llm=llm,
    controller=Controller(),
    browser=browser,
    validate_output=False,
)


async def main() -> None:
    await agent.run(max_steps=300)
    await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
