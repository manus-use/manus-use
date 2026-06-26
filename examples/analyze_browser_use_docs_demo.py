#!/usr/bin/env python3
"""Demo: analyze browser-use documentation with a browser agent and AWS Bedrock.

Navigates to the browser-use deepwiki page, extracts comprehensive
documentation, and saves a structured markdown report locally.

Usage::

    python examples/analyze_browser_use_docs_demo.py
"""

import asyncio
from pathlib import Path

from browser_use import Agent
from langchain_aws import ChatBedrock


async def analyze() -> None:
    print("=== Browser-Use Documentation Analyzer ===\n")

    llm = ChatBedrock(
        model_id="us.anthropic.claude-3-7-sonnet-20250219-v1:0",
        model_kwargs={"temperature": 0.0, "max_tokens": 4096},
        region_name="us-east-1",
    )

    task = """
    Navigate to https://deepwiki.com/browser-use/browser-use and extract:
    1. Overview and purpose
    2. Key features and capabilities
    3. Installation instructions
    4. Basic usage examples (with code)
    5. Advanced features and configuration
    6. Architecture overview
    7. Best practices
    8. Common use cases
    9. Limitations

    Capture ALL code examples and organise the output clearly.
    """

    agent = Agent(task=task, llm=llm, max_input_tokens=200_000)

    print("Starting browser agent (this may take a few minutes)…\n")
    result = await agent.run(max_steps=50)

    # Extract text from result
    if hasattr(result, "final_answer"):
        content = result.final_answer
    elif hasattr(result, "history") and result.history:
        last = result.history[-1]
        content = getattr(last, "extracted_content", str(last))
    else:
        content = str(result)

    output_file = Path("browser_use_analysis.md")
    output_file.write_text(content, encoding="utf-8")
    print(f"✅ Report saved to: {output_file}  ({output_file.stat().st_size} bytes)")


if __name__ == "__main__":
    asyncio.run(analyze())
