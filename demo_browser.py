import os
import sys

from langchain_aws import ChatBedrock
import argparse
import asyncio

from browser_use import Agent
from browser_use.browser.browser import Browser, BrowserConfig
from browser_use.controller.service import Controller

def get_llm():
    return ChatBedrock(
        model_id= 'us.anthropic.claude-3-7-sonnet-20250219-v1:0',
        temperature=0.0,
        max_tokens=None,
    )
task = """Please assess 20 critical or high severity vulnerabilities happened in 2025 and related to python, golang, java, javascript or chrome, and get EPSS for them though https://api.first.org/data/v1/epss?cve=CVE-2025-32444&pretty=true."""
# https://www.tenable.com/cve/search?q=cvss3_severity%5C%3A%28CRITICAL%29+AND+%28python+OR+golang+OR+java+OR+javascript+OR+chrome%29+AND+%22published%5C%3A%5B2025-04-01%22+TO+%222025-04-30%5D%22+AND+cvss3_severity%3A%28CRITICAL%29&sort=newest&page=1
llm = get_llm()

browser = Browser(
    config=BrowserConfig(
        headless=False
    )
)

agent = Agent(
    task=task, llm=llm, controller=Controller(), browser=browser, validate_output=False,
)

async def main():
    await agent.run(max_steps=30)
    await browser.close()

asyncio.run(main())