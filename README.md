# ManusUse

[![PyPI version](https://img.shields.io/pypi/v/manus-use.svg)](https://pypi.org/project/manus-use/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://github.com/manus-use/manus-use/actions/workflows/test.yml/badge.svg)](https://github.com/manus-use/manus-use/actions)

A powerful, extensible framework for building AI agents with comprehensive tool support, multi-agent orchestration, and advanced web automation capabilities.

## Overview

ManusUse empowers developers to create sophisticated AI agents that can:

- Execute code in secure Docker sandboxes
- Automate web browsing and data extraction
- Analyze data and generate visualizations
- Coordinate multiple specialized agents for complex tasks
- Integrate with various LLM providers seamlessly
- Perform deep vulnerability intelligence analysis

Built on [Strands SDK](https://github.com/strands-agents/sdk-python) and integrated with [browser-use](https://github.com/browser-use/browser-use), ManusUse provides a production-ready foundation for AI agent development.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Configuration](#configuration)
- [Python API](#python-api)
- [Security & Vulnerability Intelligence](#security--vulnerability-intelligence)
- [Development](#development)

---

## Installation

```bash
# Basic installation
pip install manus-use

# With browser automation support
pip install manus-use[browser]
playwright install chromium

# Full installation with all optional features
pip install manus-use[browser,search,visualization]
```

---

## Quick Start

### 1. Initialize your configuration

```bash
manus-use init
```

The interactive wizard creates `~/.manus-use/config.toml` with your LLM provider credentials.

### 2. Check your environment

```bash
manus-use doctor
```

Verifies installed packages, configuration, and API key accessibility.

### 3. Run your first task

```bash
# Single-shot (non-interactive)
manus-use "Write a Python script that fetches the current Bitcoin price"

# Interactive REPL
manus-use
```

---

## CLI Reference

ManusUse ships a single `manus-use` entry point with several subcommands.

### `manus-use [task]` — Run a task

```bash
# Single-shot task (prints result, then exits)
manus-use "Create a factorial function in Python"

# Use a specific agent type
manus-use --agent browser "Find the top 5 trending GitHub repos today"

# Force multi-agent orchestration
manus-use --mode multi "Research quantum computing and create a presentation"

# Save output to a file
manus-use --output result.txt "Summarise the latest AI news"

# JSON output for piping into other tools
manus-use --format json "List the first 10 prime numbers" | jq .result

# Interactive REPL (omit the task argument)
manus-use
manus-use --mode multi
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--mode {auto,single,multi}` | `auto` | Execution mode; `auto` detects task complexity |
| `--agent {manus,browser,data,mcp}` | `manus` | Agent type for single-agent execution |
| `--show-plan` | off | Print the multi-agent plan before running |
| `--output FILE` | — | Write result to FILE (single-shot only) |
| `--format {text,json}` | `text` | Output format; `json` is scriptable |
| `--no-history` | off | Skip recording this run in the history log |
| `--config FILE` | — | Override default config file search path |
| `--version` | — | Print version and exit |

### `manus-use init` — Configure credentials

```bash
manus-use init                       # write to ~/.manus-use/config.toml
manus-use init --output ./my.toml   # write to a custom location
manus-use init --force               # overwrite without prompting
```

### `manus-use doctor` — Diagnose your environment

```bash
manus-use doctor
manus-use doctor --config ./custom.toml
```

Checks Python packages, config file validity, and whether API keys are accessible.

### `manus-use analyze <CVE-ID>` — Vulnerability intelligence

```bash
# Deep CVE analysis (NVD · CISA KEV · OTX · PoC search · CWE · threat feeds)
manus-use analyze CVE-2025-6554

# With Docker-based exploit verification
manus-use analyze CVE-2024-3094 --verify

# Machine-readable output
manus-use analyze CVE-2025-6554 --output json

# Generate a Lark document report
manus-use analyze CVE-2025-6554 --output lark
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--verify` | off | Run exploit in a Docker sandbox to confirm exploitability |
| `--output {text,json,lark}` | `text` | Report format |
| `--config FILE` | — | Override config |

### `manus-use history` — Browse past runs

```bash
manus-use history                        # last 20 runs
manus-use history --limit 50             # last 50 runs
manus-use history --grep "bitcoin"       # filter by task text
manus-use history --format json | jq .   # all history as JSON
manus-use history --clear                # delete all history
```

History is stored at `~/.manus-use/history.jsonl`.

---

## Configuration

Create `~/.manus-use/config.toml` (or run `manus-use init`):

```toml
[llm]
provider = "bedrock"          # "openai" | "anthropic" | "bedrock" | "ollama"
model = "us.anthropic.claude-sonnet-4-20250514-v1:0"

[sandbox]
enabled = true
docker_image = "python:3.12-slim"

[tools]
enabled = ["file_ops", "code_execute", "web_search"]

[agent]
# "none" | "sliding_window" | "agentic" (model-managed, recommended for long tasks)
context_manager = "agentic"
```

See [config/config.example.toml](config/config.example.toml) for all available options.

### Provider-specific examples

**AWS Bedrock:**
```toml
[llm]
provider = "bedrock"
model = "us.anthropic.claude-sonnet-4-20250514-v1:0"
# Uses ~/.aws/credentials or IAM role automatically
```

**OpenAI:**
```toml
[llm]
provider = "openai"
model = "gpt-4o"
api_key = "sk-..."    # or set OPENAI_API_KEY env var
```

**Anthropic:**
```toml
[llm]
provider = "anthropic"
model = "claude-3-5-sonnet-20241022"
api_key = "sk-ant-..."    # or set ANTHROPIC_API_KEY env var
```

**Ollama (local):**
```toml
[llm]
provider = "ollama"
model = "llama3.2"
base_url = "http://localhost:11434"
```

---

## Python API

### Basic usage

```python
from manus_use import ManusAgent

agent = ManusAgent()

result = agent("Write a Python script that fetches weather data and saves it to CSV")
print(result)
```

### Browser automation

```python
from manus_use.agents import BrowserUseAgent

agent = BrowserUseAgent()
result = agent("Go to GitHub and find the top 5 trending Python repositories today")
print(result)
```

### Data analysis

```python
from manus_use.agents import DataAnalysisAgent

agent = DataAnalysisAgent()
result = agent("Load sales.csv, compute monthly revenue, and plot a bar chart")
print(result)
```

### Multi-agent orchestration

```python
from manus_use.multi_agents import WorkflowAgent

workflow = WorkflowAgent()
result = workflow.handle_request("""
    1. Search the web for recent AI research papers
    2. Analyse the trends and create visualizations
    3. Generate a comprehensive report with insights
""")
print(result)
```

### Vulnerability intelligence

```python
from manus_use.agents import VulnerabilityIntelligenceAgent
from manus_use.config import Config

config = Config.from_file()
agent = VulnerabilityIntelligenceAgent(config=config)

result = agent.handle_request("Analyse CVE-2025-6554 and create a comprehensive report")
print(result)
```

### Custom configuration

```python
from manus_use import ManusAgent
from manus_use.config import Config

config = Config.from_file("path/to/config.toml")
agent = ManusAgent(config=config)

result = agent("Create a factorial function")
print(result)
```

---

## Security & Vulnerability Intelligence

ManusUse includes a multi-source vulnerability intelligence pipeline accessible via the CLI or Python API.

### How it works

The `manus-use analyze` command runs an 8-step pipeline:

1. **NVD + GitHub Advisory** — official CVE metadata, CVSS, CWE
2. **CISA KEV** — known-exploited-vulnerabilities catalogue
3. **AlienVault OTX** — threat intelligence pulses and IoCs
4. **PoC discovery** — PoC Week trending digest, Trickest/CVE index, Exploit-DB, PacketStorm, GitHub
5. **URL verification** — every candidate URL is fetched and validated
6. **Static analysis** — code-level analysis of confirmed PoCs (network calls, payload patterns)
7. **CWE correlation** — weakness classification and remediation hints
8. **Report generation** — structured text, JSON, or Lark document output

### Examples

```bash
# Analyse a CVE and print a structured text report
manus-use analyze CVE-2024-3094

# Get JSON output and extract the CVSS score
manus-use analyze CVE-2024-3094 --output json | jq .cvss_score

# Verify exploitability in a Docker sandbox, then write a Lark report
manus-use analyze CVE-2025-6554 --verify --output lark
```

> **Important:** These tools are designed for defensive security purposes only. Use them for legitimate security research, vulnerability management, and defence.

---

## Key Features

### 🤖 Agent types

| Agent | Class | Best for |
|-------|-------|----------|
| General | `ManusAgent` | File ops, code execution, reasoning |
| Browser automation | `BrowserUseAgent` | JS-heavy sites, form filling, scraping |
| Lightweight browser | `BrowserAgent` | Static pages, simple navigation |
| Data analysis | `DataAnalysisAgent` | CSV/JSON processing, charts |
| MCP | `MCPAgent` | Model Context Protocol tool servers |
| Multi-agent | `WorkflowAgent` | Complex tasks needing multiple specialists |
| Vulnerability intel | `VulnerabilityIntelligenceAgent` | CVE analysis, threat intelligence |

### 🛠️ Built-in tools

- File operations (read, write, edit, delete)
- Code execution in Docker sandboxes
- Web search (DuckDuckGo, configurable)
- Browser automation (click, type, extract, screenshot)
- Data visualization (charts, plots, reports)
- Security tools (NVD, CISA KEV, OTX, Exploit-DB, Trickest, PoC Week)
- HTTP requests with content extraction
- Python REPL with persistent state

### 🔌 LLM providers

- **AWS Bedrock** (Claude, Titan, …)
- **OpenAI** (GPT-4o, GPT-4-turbo, …)
- **Anthropic** (Claude 3.5 Sonnet, Opus, …)
- **Ollama** (Llama, Mistral, … running locally)

---

## Development

### Set up a development environment

```bash
git clone https://github.com/manus-use/manus-use.git
cd manus-use
pip install -e ".[dev,browser,search,visualization]"
```

### Run tests

```bash
# All tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=manus_use --cov-report=html

# Or via hatch
hatch run test
hatch run test-cov
```

### Lint and format

```bash
ruff check src/ tests/
ruff format src/ tests/

# Or via hatch
hatch run lint
hatch run format
```

### Project layout

```
manus-use/
├── src/manus_use/
│   ├── agents/          # Agent implementations
│   │   ├── base.py      # BaseManusAgent (all agents inherit from this)
│   │   ├── manus.py     # ManusAgent (general purpose)
│   │   ├── browser.py   # BrowserAgent (lightweight)
│   │   ├── browser_use_agent.py  # BrowserUseAgent (full JS automation)
│   │   ├── data_analysis.py      # DataAnalysisAgent
│   │   ├── mcp.py       # MCPAgent
│   │   └── vi_agent.py  # VulnerabilityIntelligenceAgent
│   ├── multi_agents/    # Multi-agent orchestration
│   │   └── workflow_agent.py
│   ├── tools/           # Individual tool implementations
│   ├── cli.py           # manus-use CLI entry point
│   ├── config.py        # Config model (TOML-backed)
│   └── __init__.py
├── tests/               # pytest test suite (175+ tests)
├── config/
│   └── config.example.toml
├── examples/            # Runnable usage examples
└── pyproject.toml
```

### Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Examples

Explore the [examples/](examples/) directory for runnable scripts:

- [`basic_usage.py`](examples/basic_usage.py) — simple ManusAgent task
- [`browser_use_demo.py`](examples/browser_use_demo.py) — browser automation
- [`multi_agent_flow.py`](examples/multi_agent_flow.py) — multi-agent orchestration

---

## Support

- 📖 [Documentation](https://github.com/manus-use/manus-use/wiki)
- 🐛 [Issue Tracker](https://github.com/manus-use/manus-use/issues)
- 💬 [Discussions](https://github.com/manus-use/manus-use/discussions)

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## Acknowledgments

- Built with [Strands SDK](https://github.com/strands-agents/sdk-python) — a powerful Python SDK for building AI agents
- Browser automation powered by [browser-use](https://github.com/browser-use/browser-use) — framework for AI-driven web automation
- Inspired by Anthropic's computer use demonstrations
