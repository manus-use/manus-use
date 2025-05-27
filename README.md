# manus-use

A powerful framework for building advanced AI agents with comprehensive tool support and orchestration capabilities.

manus-use provides a simple yet flexible framework for creating AI agents that can execute code, browse the web, analyze data, and coordinate complex multi-agent workflows. The framework now features enhanced multi-agent orchestration and browser-use integration for sophisticated web automation.

## Features

- 🤖 **Multiple Agent Types**: Manus-style agents, browser agents (powered by browser-use), data analysis agents, and more
- 🛠️ **Rich Tool Ecosystem**: File operations, advanced web browsing with browser-use, code execution, search, and visualization
- 🔒 **Secure Sandbox**: Docker-based isolated execution environment
- 🌐 **MCP Support**: Native Model Context Protocol integration
- 🔄 **Multi-Agent Orchestration**: Intelligent task planning and routing with specialized agents
- 🎯 **Model Agnostic**: Support for OpenAI, Anthropic, Bedrock, Ollama, and more
- 🌐 **Browser-Use Integration**: Powerful browser automation through natural language commands
- 🤝 **CLI with Multi-Agent Support**: Command-line interface that automatically detects and routes complex tasks

## Installation

```bash
pip install manus-use
```

Or install from source:

```bash
git clone https://github.com/manus-use/manus-use.git
cd manus-use
pip install -e .
```

For browser automation features:
```bash
pip install browser-use
playwright install chromium
```

## Quick Start

### Basic Agent Usage

```python
from manus_use import ManusAgent
from manus_use.tools import code_execute, file_read, file_write

# Create a Manus-style agent
agent = ManusAgent(
    tools=[code_execute, file_read, file_write],
    model="gpt-4o"  # or any supported model
)

# Use the agent
response = agent("Create a Python script that analyzes CSV data and generates a chart")
print(response)
```

### CLI Usage

```bash
# Simple task - single agent execution
manus "Create a hello world Python script"

# Complex task - automatic multi-agent orchestration
manus "Research the latest AI trends online and create a technical report with visualizations"

# Specify execution mode
manus --mode multi "Build a web scraper and analyze the collected data"
```

## Configuration

Create a `config.toml` file:

```toml
[llm]
provider = "openai"  # or "anthropic", "bedrock", "ollama"
model = "gpt-4o"
api_key = "your-api-key"

[sandbox]
enabled = true
docker_image = "python:3.12-slim"

[tools]
enabled = ["file_operations", "code_execute", "web_search", "browser"]
```

## Advanced Usage

### Browser Agent (Powered by browser-use)

```python
from manus_use.agents import BrowserUseAgent
from manus_use.tools import browser_do, browser_navigate, browser_extract_content

# Using BrowserUseAgent directly
agent = BrowserUseAgent()
result = agent("Search for AI agent frameworks and compare their features")

# Or using browser tools
result = await browser_do("Go to GitHub and find the top Python AI projects")

# Fine-grained browser control
await browser_navigate("https://example.com")
content = await browser_extract_content("Extract all pricing information")
```

### Data Analysis Agent

```python
from manus_use import DataAnalysisAgent

agent = DataAnalysisAgent()
result = agent("Analyze sales_data.csv and create a trend visualization")
```

### Multi-Agent Orchestration

```python
from manus_use.multi_agents import Orchestrator, PlanningAgent
from manus_use.agents import ManusAgent, BrowserUseAgent

# Create an orchestrator with multiple specialized agents
orchestrator = Orchestrator()

# Execute complex task - automatic task decomposition and routing
result = orchestrator.run("Research the latest AI trends and create a technical report with code examples")

# The orchestrator will:
# 1. Use PlanningAgent to decompose the task
# 2. Route web research to BrowserUseAgent
# 3. Use ManusAgent for report writing and code generation
# 4. Coordinate results from all agents
```

### Browser Tools

```python
from manus_use.tools import (
    browser_do,
    browser_navigate,
    browser_click_element,
    browser_extract_content,
    browser_scroll_down,
    browser_input_text,
    browser_search_google
)

# High-level browser automation
result = await browser_do("Fill out the contact form on example.com with test data")

# Low-level browser control
await browser_navigate("https://example.com")
await browser_input_text("John Doe", "name field")
await browser_click_element("submit button")
content = await browser_extract_content("confirmation message")
```

## Key Components

### Agents
- **ManusAgent**: General-purpose agent with file operations and code execution
- **BrowserUseAgent**: Web automation agent powered by browser-use framework
- **DataAnalysisAgent**: Specialized agent for data analysis and visualization
- **PlanningAgent**: Task decomposition and planning for multi-agent workflows
- **MCPAgent**: Model Context Protocol integration for extended tool capabilities

### Tools
- **File Operations**: Read, write, list, delete, and move files
- **Code Execution**: Run Python code in sandboxed or local environments
- **Web Search**: Search the web using various search engines
- **Browser Automation**: Complete set of browser tools powered by browser-use
- **Visualization**: Create charts and visualizations from data

### Orchestration
- **Intelligent Task Routing**: Automatically routes tasks to appropriate agents
- **Task Decomposition**: Breaks complex tasks into manageable subtasks
- **Parallel Execution**: Runs independent tasks concurrently
- **Result Aggregation**: Combines outputs from multiple agents

## Documentation

For detailed documentation, see [docs/](docs/).

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Strands SDK](https://github.com/strands-agents/sdk-python) - A powerful Python SDK for building AI agents
- Browser automation powered by [browser-use](https://github.com/browser-use/browser-use) - Framework for AI-driven web aut