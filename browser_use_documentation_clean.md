# Browser-Use Documentation

**Generated on:** 2025-05-26 22:12:16

**Source:** https://deepwiki.com/browser-use/browser-use

---

## What is browser-use?

Browser-use is a framework that enables AI agents to automate web browsing tasks by providing a seamless interface between language models (LLMs) and browser automation technology. It allows AI to navigate websites, extract information, and perform complex web interactions just as a human user would.

## Key Features

- Integration with various language models through LangChain
- Browser automation using Playwright
- DOM extraction and processing for AI comprehension
- Action system for executing browser interactions
- Message management for LLM communication
- Vision capabilities for image processing
- Support for multiple browser contexts and sessions
- Custom action registration

## Installation

**Requirements:**
- Python 3.11 or higher
- Playwright

```bash
pip install browser-use
playwright install chromium
```

## Usage Example

```python
from langchain_openai import ChatOpenAI
from browser_use import Agent
import asyncio
from dotenv import load_dotenv
load_dotenv()

async def main():
    agent = Agent(
        task="Compare the price of gpt-4o and DeepSeek-V3",
        llm=ChatOpenAI(model="gpt-4o"),
    )
    await agent.run()

asyncio.run(main())
```

## System Architecture

The browser-use framework consists of several key components:

1. **Agent**: The central orchestrator that coordinates all system components
2. **Browser**: Provides an abstraction layer over Playwright for browser management and interaction
3. **Controller**: Manages the execution of browser actions
4. **DOM Service**: Extracts and processes DOM information from web pages
5. **MessageManager**: Handles communication between the Agent and language models
6. **ActionRegistry**: Stores and manages available browser actions
7. **Language Model**: Used for decision-making and task execution

### Data Flow
Task → Agent → LLM → Controller → Browser Action → Browser → DOM State → DomService → Element Tree → MessageManager → LLM → Repeat until task complete

## Supported Models

Browser-use works with various language models through LangChain integrations:

| Provider | Models | Vision Support | Notes |
| --- | --- | --- | --- |
| OpenAI | GPT-4o, GPT-4o-mini | Yes | Recommended for best performance (89% accuracy) |
| Anthropic | Claude 3.5 Sonnet | Yes | Good alternative to GPT-4o |
| Google | Gemini 2.0, Gemini 1.5 | Yes | Gemini 2.0-exp is currently free |
| DeepSeek | DeepSeek-V3, DeepSeek-R1 | Partial | 30x cheaper than GPT-4o |
| Azure OpenAI | GPT-4o, GPT-4o-mini | Yes | Enterprise-grade integration |
| Ollama | Qwen 2.5, etc. | Varies | Local models with no API key required |
| Novita AI | Various models | Varies | Alternative API provider |

## Common Use Cases

1. **E-commerce and Shopping**: Adding items to cart, filling checkout forms, comparing prices
2. **Data Collection**: Searching for specific information, extracting data from websites
3. **Job Applications**: Finding job listings, filtering by criteria, submitting applications
4. **Document Creation**: Creating and editing documents in web applications like Google Docs
5. **Research**: Finding information across multiple websites and compiling results
6. **CRM/Data Integration**: Transferring data between websites and other systems

## Documentation Structure

- Overview
- System Architecture
- Installation and Setup
- Core Components
- Browser Interaction
- Action System
- Language Model Integration
- Advanced Usage

---

*This documentation was automatically extracted using browser_tools.py from the manus-use project*