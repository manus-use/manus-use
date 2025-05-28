# ManusUse CLI Usage Guide

## Installation

First, ensure you have ManusUse installed with CLI dependencies:

```bash
pip install manus-use[cli]
# or if using from source:
pip install click rich textual
```

## Available CLI Commands

ManusUse provides three different CLI interfaces:

1. **manus-use** - Original simple CLI
2. **manus-use-enhanced** - Enhanced CLI with rich formatting and streaming
3. **manus-use-v2** - Full TUI (Terminal User Interface) with panels

## Using the Enhanced CLI

### 1. Basic Usage

```bash
# Show version
manus-use-enhanced --version

# Show help
manus-use-enhanced --help

# Run a single task
manus-use-enhanced -p "What is 2 + 2?"

# Start interactive mode
manus-use-enhanced
```

### 2. Execution Modes

The CLI supports different execution modes:

- **auto** (default): Automatically detects task complexity
- **single**: Uses a single ManusAgent
- **multi**: Uses multi-agent orchestration
- **browser**: Uses BrowserUseAgent for web tasks

```bash
# Force single agent mode
manus-use-enhanced --mode single -p "Calculate 15 * 23"

# Force multi-agent mode
manus-use-enhanced --mode multi -p "Analyze data and create a report"

# Browser mode
manus-use-enhanced --mode browser -p "Search for Python tutorials"

# Auto mode (detects complexity)
manus-use-enhanced -p "First analyze the data, then create a visualization"
```

### 3. Browser Options

When using browser mode:

```bash
# Run with visible browser (not headless)
manus-use-enhanced --no-headless -p "Browse to example.com"

# Enable streaming for real-time updates
manus-use-enhanced --stream -p "Search and extract data from web"
```

### 4. Configuration

```bash
# Use custom config file
manus-use-enhanced --config /path/to/config.toml

# Enable debug logging
manus-use-enhanced --debug
```

## Interactive Mode

Start interactive mode by running without arguments:

```bash
manus-use-enhanced
```

### Special Commands in Interactive Mode

- `/mode [auto|single|multi|browser]` - Switch execution mode
- `/history` - Show command history
- `/clear` - Clear the screen
- `/exit` - Exit the program

### Example Interactive Session

```
$ manus-use-enhanced

╭─────────────────────────────── Welcome ──────────────────────────────────╮
│ ManusUse Interactive Mode                                                │
│ Type your tasks below. Special commands:                                │
│   • /mode - Switch between auto/single/multi/browser modes             │
│   • /history - Show command history                                     │
│   • /clear - Clear screen                                               │
│   • /exit - Exit                                                       │
╰──────────────────────────────────────────────────────────────────────────╯

[auto] > What is the weather today?
[auto] > /mode browser
Mode switched to: browser
[browser] > Search for Python tutorials on the web
[browser] > /mode multi
Mode switched to: multi
[multi] > Analyze this data and create a report with visualizations
[multi] > /exit
Goodbye!
```

## Task Examples

### Simple Tasks (Single Agent)

```bash
# Calculations
manus-use-enhanced -p "Calculate the square root of 144"

# Questions
manus-use-enhanced -p "What is the capital of France?"

# Code generation
manus-use-enhanced -p "Write a Python function to sort a list"
```

### Complex Tasks (Multi-Agent)

```bash
# Sequential tasks
manus-use-enhanced -p "First analyze the current date, then create a report"

# Multiple operations
manus-use-enhanced -p "Read data.csv, analyze it, and create visualizations"

# Research and implementation
manus-use-enhanced -p "Research Python best practices and then implement a example"
```

### Browser Tasks

```bash
# Web search
manus-use-enhanced --mode browser -p "Search for the latest AI news"

# Data extraction
manus-use-enhanced --mode browser -p "Extract product prices from example.com"

# Web automation
manus-use-enhanced --mode browser --no-headless -p "Fill out a form on website.com"
```

## Output Formatting

The enhanced CLI provides rich output formatting:

- **Syntax highlighting** for code
- **Markdown rendering** for formatted text
- **Progress bars** for long-running tasks
- **Tables** for structured data
- **Colored panels** for results

## Configuration File

Create a config file at `~/.config/manus-use/config.toml`:

```toml
[llm]
provider = "anthropic"
model = "claude-3-5-sonnet-20241022"
temperature = 0.7

[tools]
enabled = ["file_operations", "web_search", "visualization"]

[browser_use]
headless = false
enable_memory = true
```

## Troubleshooting

### Common Issues

1. **Import errors**: Make sure all dependencies are installed
   ```bash
   pip install click rich textual
   ```

2. **Config not found**: Create a config.toml file or specify with --config

3. **Browser tasks fail**: Ensure browser-use is installed
   ```bash
   pip install browser-use
   ```

4. **Timeout errors**: Complex tasks may take time, be patient

### Debug Mode

Enable debug logging to see detailed information:

```bash
manus-use-enhanced --debug -p "Your task"
```

## Tips and Best Practices

1. **Use descriptive tasks**: Be specific about what you want
2. **Check mode**: Use `/mode` to see current execution mode
3. **Review history**: Use `/history` to see previous commands
4. **Start simple**: Test with simple tasks before complex ones
5. **Use streaming**: Enable `--stream` for browser tasks to see progress

## Advanced Usage

### Chaining Tasks

In interactive mode, you can chain related tasks:

```
[auto] > Read the file data.csv
[auto] > Now analyze the data you just read
[auto] > Create a visualization based on the analysis
```

### Saving Output

Redirect output to a file:

```bash
manus-use-enhanced -p "Generate a report" > report.md
```

### Batch Processing

Create a script with multiple tasks:

```bash
#!/bin/bash
manus-use-enhanced -p "Task 1"
manus-use-enhanced -p "Task 2"
manus-use-enhanced -p "Task 3"
```

## Next Steps

- Explore the [examples](examples/) directory for more use cases
- Check the [API documentation](docs/api.md) for programmatic usage
- Join the community for tips and support