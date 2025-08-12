# ManusUse

A powerful, extensible framework for building AI agents with comprehensive tool support, multi-agent orchestration, and advanced web automation capabilities.

## Overview

ManusUse empowers developers to create sophisticated AI agents that can:
- Execute code in secure Docker sandboxes
- Automate web browsing and data extraction
- Analyze data and generate visualizations
- Coordinate multiple specialized agents for complex tasks
- Integrate with various LLM providers seamlessly

Built on [Strands SDK](https://github.com/strands-agents/sdk-python) and integrated with [browser-use](https://github.com/browser-use/browser-use), ManusUse provides a production-ready foundation for AI agent development.

## Key Features

### 🤖 Multiple Agent Types
- **ManusAgent**: General-purpose agent for file operations and code execution
- **BrowserUseAgent**: Advanced web automation using natural language
- **DataAnalysisAgent**: Specialized for data processing and visualization
- **VulnerabilityIntelligenceAgent**: Deep CVE analysis with multi-source intelligence (`va_agent.py`)
- **VulnerabilityDiscoveryAgent**: Automated vulnerability discovery and submission (`vd_agent.py`)
- **MCPAgent**: Model Context Protocol integration for extended capabilities
- **WorkflowAgent**: Complex task orchestration with dependency management

### 🛠️ Rich Tool Ecosystem
- File operations (read, write, edit, delete)
- Code execution in Docker sandboxes
- Web search and content retrieval
- Browser automation (click, type, extract)
- Data visualization (charts, plots, reports)
- Security analysis tools (CVE checking, threat intelligence)

### 🔄 Multi-Agent Orchestration
- Automatic task decomposition and routing
- Parallel execution of independent tasks
- Intelligent agent selection based on task requirements
- Result aggregation and error handling

### 🔌 Flexible Integration
- Support for OpenAI, Anthropic, AWS Bedrock, Ollama
- Model Context Protocol (MCP) compatibility
- Extensible tool system
- Configuration-driven architecture

## Quick Start

### Installation

```bash
# Basic installation
pip install manus-use

# With browser automation support
pip install manus-use[browser]
playwright install chromium

# Full installation with all features
pip install manus-use[browser,search,visualization]
```

### Basic Usage

```python
from manus_use import ManusAgent

# Create an agent
agent = ManusAgent(model="gpt-4o")

# Execute a task
response = agent("Create a Python script that fetches weather data and saves it to a CSV file")
print(response)
```

### Browser Automation

```python
from manus_use.agents import BrowserUseAgent

# Create a browser agent
browser_agent = BrowserUseAgent()

# Automate web tasks
result = browser_agent("Go to GitHub and find the top 5 trending Python repositories today")
```

### Multi-Agent Workflows

```python
from manus_use.multi_agents import WorkflowAgent

# Create a workflow agent
workflow = WorkflowAgent()

# Execute a complex task with multiple agents
result = workflow.handle_request("""
    1. Search the web for recent AI research papers
    2. Analyze the trends and create visualizations
    3. Generate a comprehensive report with insights
""")
```

## Configuration

Create a `config/config.toml` file:

```toml
[llm]
provider = "openai"  # or "anthropic", "bedrock", "ollama"
model = "gpt-4o"
api_key = "your-api-key"  # or use environment variable

[sandbox]
enabled = true
docker_image = "python:3.12-slim"

[tools]
enabled = ["file_ops", "code_execute", "web_search", "browser"]
```

See [config.example.toml](config/config.example.toml) for all available options.

## CLI Usage

ManusUse provides multiple CLI interfaces:

```bash
# Basic CLI
manus-use "Create a factorial function in Python"

# Enhanced CLI with rich UI
manus-use-enhanced

# Automatic multi-agent mode for complex tasks
manus-use "Research quantum computing applications and create a presentation"
```

## Development

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/manus-use/manus-use.git
cd manus-use

# Install in development mode
pip install -e ".[dev,browser,search,visualization]"

# Run tests
hatch run test

# Check code quality
hatch run lint
hatch run format
```

### Running Tests

```bash
# Run all tests
hatch run test

# Run with coverage
hatch run test-cov

# Run specific test
hatch run pytest tests/test_agents.py -v
```

## Examples

Explore the [examples/](examples/) directory for:
- [Basic agent usage](examples/basic_usage.py)
- [Browser automation](examples/browser_use_demo.py)
- [Multi-agent workflows](examples/multi_agent_flow.py)
- [Data analysis](examples/test_browser_agent.py)

## Documentation

- [Quick Start Guide](docs/quick-start.md)
- [Browser Agent Setup](docs/browser-agent-setup.md)
- [API Reference](docs/api-reference.md)

## Security and Vulnerability Intelligence

ManusUse includes sophisticated vulnerability intelligence capabilities through specialized agents:

### 🔍 Vulnerability Analysis Agent (`va_agent.py`)
A comprehensive CVE analysis tool that performs deep vulnerability research:

```bash
# Analyze a specific CVE
python va_agent.py CVE-2025-6554

# The agent will automatically:
# - Fetch data from NVD and GitHub advisories
# - Check CISA KEV and AlienVault OTX
# - Search for public exploits and PoCs
# - Perform deep PoC analysis and validation
# - Generate a comprehensive Lark document report
```

Features:
- Multi-source intelligence gathering (NVD, CISA KEV, OTX, GitHub)
- Automatic PoC discovery and validation
- Deep code analysis of exploits
- Threat intelligence correlation
- Automated report generation

### 🎯 Vulnerability Discovery Agent (`vd_agent.py`)
An automated vulnerability discovery and submission system:

```bash
# Run automated vulnerability discovery
python vd_agent.py

# The agent will:
# - Calculate time slices for the current two weeks
# - Discover CVEs with high EPSS scores
# - Submit vulnerabilities in batches
# - Provide detailed submission summaries
```

Features:
- Automated time-based CVE discovery
- EPSS score filtering for high-impact vulnerabilities
- Concurrent processing for efficiency
- Batch submission capabilities
- Multi-agent orchestration

### Usage Examples

```python
# Using the Vulnerability Analysis Agent programmatically
from va_agent import VulnerabilityIntelligenceAgent

agent = VulnerabilityIntelligenceAgent(model_name="us.anthropic.claude-sonnet-4-20250514-v1:0")
result = agent.handle_request("Analyze CVE-2025-6554 and create a comprehensive report")

# Using the Vulnerability Discovery Agent
from vd_agent import VulnerabilityDiscoveryAgent

discovery = VulnerabilityDiscoveryAgent(model_name="us.anthropic.claude-sonnet-4-20250514-v1:0")
result = discovery.handle_request("Execute vulnerability discovery workflow")
```

**Important**: These tools are designed for defensive security purposes only and should be used for legitimate security research, vulnerability management, and defense.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Built with [Strands SDK](https://github.com/strands-agents/sdk-python) - A powerful Python SDK for building AI agents
- Browser automation powered by [browser-use](https://github.com/browser-use/browser-use) - Framework for AI-driven web automation
- Inspired by Anthropic's computer use demonstrations

## Support

- 📖 [Documentation](https://github.com/manus-use/manus-use/wiki)
- 🐛 [Issue Tracker](https://github.com/manus-use/manus-use/issues)
- 💬 [Discussions](https://github.com/manus-use/manus-use/discussions)