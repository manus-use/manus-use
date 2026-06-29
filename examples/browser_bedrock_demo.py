#!/usr/bin/env python3
"""Demo: BrowserAgent with AWS Bedrock — visible browser (headless=False).

Usage::

    export AWS_ACCESS_KEY_ID=...
    export AWS_SECRET_ACCESS_KEY=...
    python examples/browser_bedrock_demo.py
"""

import asyncio
import os
import sys

from manus_agent.agents.browser import BrowserAgent
from manus_agent.config import Config


async def main() -> None:
    if not os.environ.get("AWS_ACCESS_KEY_ID"):
        print("⚠️  AWS credentials not found. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.")
        sys.exit(1)

    config = Config.from_file()
    print(f"Model:      {config.model.model_id}")
    print(f"AWS region: {config.model.aws_region}")

    # headless=False lets you watch the browser during the demo
    agent = BrowserAgent(config=config, headless=False)

    tasks = [
        ("Navigate & inspect", "Navigate to https://example.com and list the elements on the page"),
        ("Search & extract", "Search for 'OpenAI GPT-4' and extract key info from the first result"),
        (
            "Form interaction",
            "Go to https://httpbin.org/forms/post, fill customer name='Test User' and phone='555-1234', "
            "then describe what you see",
        ),
        ("Screenshot", "Take a screenshot and save it as 'bedrock_demo_screenshot.jpg'"),
    ]

    for label, prompt in tasks:
        print(f"\n--- {label} ---")
        result = await agent.run(prompt)
        print(result)

    print("\n✅ Bedrock BrowserAgent demo complete.")


if __name__ == "__main__":
    asyncio.run(main())
