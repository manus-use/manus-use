# ManusUse CLI Quick Start Guide

ManusUse provides a powerful command-line interface for interacting with AI agents. This guide will help you get started quickly.

## Installation

```bash
# Install ManusUse with CLI support
pip install manus-use[cli]

# Or install required dependencies
pip install click rich
```

## Basic Usage

### 1. Run a Single Command

```bash
# Simple calculation
python -m manus_use.cli_enhanced -p "Calculate 25 * 4"

# Code generation
python -m manus_use.cli_enhanced -p "Write a Python function to reverse a string"

# Complex task (auto-detects multi-agent need)
python -m manus_use.cli_enhanced -p "Analyze this data and create a visualization"
```

### 2. Interactive Mode

Start the interactive CLI:

```bash
python -m manus_use.cli_enhanced
```

In interactive mode:
- Type your tasks naturally
- Use `/mode` to switch between single/multi/browser modes
- Use `/history` to see previous commands
- Use `/clear` to clear the screen
- Use `/exit` to quit

### 3. Force Specific Mode

```bash
# Force single agent
python -m manus_use.cli_enhanced --mode single -p "Your task"

# Force multi-agent orchestration
python -m manus_use.cli_enhanced --mode multi -p "Complex multi-step task"

# Browser mode (requires browser-use)
python -m manus_use.cli_enhanced --mode browser -p "Search the web for information"
```

## Examples

### Simple Tasks

```bash
# Math calculation
python -m manus_use.cli_enhanced -p "What is the square root of 144?"

# Questions
python -m manus_use.cli_enhanced -p "Explain quantum computing in simple terms"

# Code generation
python -m manus_use.cli_enhanced -p "Create a Python class for a binary search tree"
```

### Complex Tasks (Multi-Agent)

```bash
# Sequential operations
python -m manus_use.cli_enhanced -p "First read data.csv, then analyze it and create a summary"

# Multiple steps
python -m manus_use.cli_enhanced -p "Calculate fibonacci numbers up to 100, then plot them"

# Research and implementation
python -m manus_use.cli_enhanced -p "Research sorting algorithms and implement quicksort"
```

### File Operations

```bash
# Create a file
python -m manus_use.cli_enhanced -p "Create a file called hello.py with a hello world function"

# Read and analyze
python -m manus_use.cli_enhanced -p "Read config.toml and explain its structure"
```

## Configuration

Create a configuration file at `config.toml`:

```toml
[llm]
provider = "bedrock"  # or "openai", "anthropic"
model = "anthropic.claude-3-5-sonnet-20241022-v2:0"
temperature = 0.0

[tools]
enabled = ["file_operations", "code_execute", "web_search"]

[browser_use]
headless = true
enable_memory = false
```

## Available Modes

- **auto**: Automatically detects task complexity and chooses the best approach
- **single**: Uses a single ManusAgent for the task
- **multi**: Uses multi-agent orchestration with task planning
- **browser**: Uses BrowserUseAgent for web-related tasks

## Command Line Options

```bash
python -m manus_use.cli_enhanced --help

Options:
  --mode [auto|single|multi|browser]  Execution mode
  --config PATH                       Path to config file
  -p, --prompt TEXT                   Run a single task
  --headless / --no-headless          Run browser in headless mode
  --debug                             Enable debug logging
  --version                           Show version
```

## Tips

1. **Be Specific**: The more specific your task description, the better the results
2. **Use Multi-Agent for Complex Tasks**: Tasks with multiple steps work best with `--mode multi`
3. **Check History**: Use `/history` in interactive mode to reuse previous commands
4. **Enable Debug**: Use `--debug` to see detailed execution information

## Troubleshooting

### Common Issues

1. **Import Errors**: Make sure all dependencies are installed
   ```bash
   pip install click rich
   ```

2. **LLM Errors**: Check your config.toml has valid credentials
   ```bash
   export AWS_DEFAULT_REGION=us-west-2  # For Bedrock
   ```

3. **Tool Warnings**: The "unrecognized tool specification" warnings are normal and don't affect functionality

## Quick Test

Test if everything is working:

```bash
# Simple test
python -m manus_use.cli_enhanced -p "What is 2 + 2?"

# Should output: 4
```

## Next Steps

- Explore more complex tasks with multi-agent orchestration
- Try browser automation with `--mode browser`
- Create custom tools for your specific needs
- Check the full documentation for advanced features