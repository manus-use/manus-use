#!/usr/bin/env python3
"""Demo: BrowserAgent — web automation tasks (headless mode).

Usage::

    python examples/browser_agent_demo.py
"""

import asyncio

from manus_use.agents.browser import BrowserAgent
from manus_use.config import Config


async def main() -> None:
    config = Config.from_file()

    agent = BrowserAgent(config=config, headless=True)

    tasks = [
        ("Web search", "Search for 'OpenAI GPT-4' and summarise what you find"),
        ("Extract content", "Navigate to https://example.com and extract the main heading and first paragraph"),
        ("Screenshot", "Take a screenshot of the current page and save it as 'example_screenshot.jpg'"),
        (
            "Form interaction",
            "Go to https://httpbin.org/forms/post, fill custname='Test User' and custtel='555-1234', "
            "then describe what you see",
        ),
        ("JavaScript", "Execute JavaScript to get the current page title and URL"),
    ]

    for label, prompt in tasks:
        print(f"\n--- {label} ---")
        result = await agent.run(prompt)
        print(result)

    print("\n✅ BrowserAgent demo complete.")


if __name__ == "__main__":
    asyncio.run(main())
