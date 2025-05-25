# ManusUse Quick Start Guide

## Installation

1. **Install ManusUse**:
```bash
pip install -e .
```

Or with all optional dependencies:
```bash
pip install -e ".[browser,search,visualization]"
```

2. **Configure API Keys**:
```bash
cp config/config.example.toml config/config.toml
# Edit config/config.toml with your API keys
```

## Basic Usage

### Simple Agent

```python
from manus_use import ManusAgent

agent = ManusAgent()
response = agent("Create a Python function to calculate factorial")
print(response)
```

### With Custom Tools

```python
from manus_use import ManusAgent
from manus_use.tools import file_read, file_write, code_execute

agent = ManusAgent(tools=[file_read, file_write, code_execute])
response = agent("Read data.csv and create a summary report")
```

### Browser Agent

```python
from manus_use import BrowserAgent

agent = BrowserAgent()
response = agent("Search for the latest AI news and summarize top 3 stories")
```

### Data Analysis

```python
from manus_use import DataAnalysisAgent

agent = DataAnalysisAgent()
response = agent("Create a sample dataset and perform statistical analysis")
```

## Multi-Agent Workflows

```python
from manus_use import FlowOrchestrator

flow = FlowOrchestrator()
result = flow.run(
    "Research Python web frameworks, compare their features, "
    "and create a recommendation report"
)
```

## Configuration

### Environment Variables

You can use environment variables instead of config file:

```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="..."
```

### Docker Sandbox

To enable secure code execution, ensure Docker is installed and running:

```bash
docker pull python:3.12-slim
```

Then in your config:
```toml
[sandbox]
enabled = true
```

## CLI Usage

Run the interactive CLI:
```bash
manus-use
```

Or:
```bash
python -m manus_use.cli
```

## Next Steps

- Check out the [examples](../examples/) directory
- Read about [advanced features](advanced-features.md)
- Learn about [creating custom tools](custom-tools.md)