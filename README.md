# manus-use

A powerful framework for building advanced AI agents with comprehensive tool support and orchestration capabilities.

manus-use provides a simple yet flexible framework for creating AI agents that can execute code, browse the web, analyze data, and coordinate complex multi-agent workflows.

## Features

- 🤖 **Multiple Agent Types**: Manus-style agents, browser agents, data analysis agents, and more
- 🛠️ **Rich Tool Ecosystem**: File operations, web browsing, code execution, search, and visualization
- 🔒 **Secure Sandbox**: Docker-based isolated execution environment
- 🌐 **MCP Support**: Native Model Context Protocol integration
- 🔄 **Multi-Agent Flows**: Orchestrate complex workflows with multiple specialized agents
- 🎯 **Model Agnostic**: Support for OpenAI, Anthropic, Bedrock, Ollama, and more

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

## Quick Start

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
enabled = ["file_ops", "code_execute", "web_search", "browser"]
```

## Advanced Usage

### Browser Agent

```python
from manus_use import BrowserAgent

agent = BrowserAgent()
result = agent("Search for AI agent frameworks and compare their features")
```

### Data Analysis Agent

```python
from manus_use import DataAnalysisAgent

agent = DataAnalysisAgent()
result = agent("Analyze sales_data.csv and create a trend visualization")
```

### Multi-Agent Flow

```python
from manus_use import FlowOrchestrator, PlanningAgent

# Create a flow with multiple agents
flow = FlowOrchestrator()
flow.add_agent("planner", PlanningAgent())
flow.add_agent("manus", ManusAgent())
flow.add_agent("browser", BrowserAgent())

# Execute complex task
result = flow.run("Research the latest AI trends and create a technical report with code examples")
```

## Documentation

For detailed documentation, see [docs/](docs/).

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

Built with [Strands SDK](https://github.com/strands-agents/sdk-python) - A powerful Python SDK for building AI agents.