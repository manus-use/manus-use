from browser_use.llm import ChatAnthropicBedrock

import boto3
from botocore.config import Config
from browser_use import Agent
from browser_use.browser.browser import Browser, BrowserConfig
from browser_use.controller.service import Controller
import asyncio

# Anthropic-specific class with Claude defaults
llm = ChatAnthropicBedrock(
    model="us.anthropic.claude-3-7-sonnet-20250219-v1:0",
    aws_region="us-west-2",
)

agent = Agent(
    task="Your task here",
    llm=llm
)

task = """Provide a comprehensive vulnerability intelligence summary for CVE-2025-24290. Include CVSS score, attack vector, exploit complexity, privileges required, user interaction, business impact, exploit availability (including proof-of-concept links), evidence of active exploitation, affected products, patch/remediation status, and any relevant vendor advisories. Ensure all data is up-to-date and cross-verified with official sources."""
# https://www.tenable.com/cve/search?q=cvss3_severity%5C%3A%28CRITICAL%29+AND+%28python+OR+golang+OR+java+OR+javascript+OR+chrome%29+AND+%22published%5C%3A%5B2025-04-01%22+TO+%222025-04-30%5D%22+AND+cvss3_severity%3A%28CRITICAL%29&sort=newest&page=1

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