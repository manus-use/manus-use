#!/usr/bin/env python3
"""Demo: minimal browser-use agent with ChatAnthropicBedrock.

A stripped-down example showing how to wire up browser-use directly
with the Anthropic Bedrock chat class (no ManusUse config layer).

Usage::

    python examples/browser_use_anthropic_bedrock_demo.py
"""

import asyncio

from browser_use import Agent
from browser_use.browser.browser import Browser, BrowserConfig
from browser_use.controller.service import Controller
from browser_use.llm import ChatAnthropicBedrock

llm = ChatAnthropicBedrock(
    model="us.anthropic.claude-3-7-sonnet-20250219-v1:0",
    aws_region="us-west-2",
)

TASK = (
    "Provide a comprehensive vulnerability intelligence summary for CVE-2025-24290. "
    "Include CVSS score, attack vector, exploit complexity, privileges required, "
    "user interaction, business impact, exploit availability (including PoC links), "
    "evidence of active exploitation, affected products, patch/remediation status, "
    "and any relevant vendor advisories."
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
