# BrowserAgent Setup with browser-use and AWS Bedrock

This guide explains how to use the BrowserAgent with browser-use and AWS Bedrock in manus-use.

## Prerequisites

1. **AWS Credentials**: Set up your AWS credentials:
   ```bash
   export AWS_ACCESS_KEY_ID="your-access-key"
   export AWS_SECRET_ACCESS_KEY="your-secret-key"
   export AWS_DEFAULT_REGION="us-east-1"
   ```

2. **Install Dependencies**:
   ```bash
   pip install browser-use langchain-aws markdownify
   ```

3. **Install Playwright** (required by browser-use):
   ```bash
   playwright install chromium
   ```

## Configuration

Use the provided `config/config.bedrock.toml` configuration file, which is already set up for AWS Bedrock:

```toml
[llm]
provider = "bedrock"
model = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
temperature = 0.0
max_tokens = 4096

[tools]
browser_headless = false  # Set to true for headless mode
```

## Usage

### 1. Using BrowserAgent in Your Code

```python
from manus_use.agents.browser import BrowserAgent
from manus_use.config import Config

# Load config
config = Config.from_file("config/config.bedrock.toml")

# Create browser agent
browser_agent = BrowserAgent(config=config, headless=False)

# Run a task
result = await browser_agent.run(
    "Navigate to https://www.anthropic.com and tell me about their latest AI models"
)
```

### 2. Running the Test Scripts

**Basic Browser Test:**
```bash
python examples/test_browser_bedrock.py
```

**Direct browser-use Demo:**
```bash
python examples/browser_use_demo.py
```

**Demo Browser:**
```bash
python demo_browser.py
```

## How It Works

The BrowserAgent uses browser-use with AWS Bedrock as the LLM backend:

1. **Browser Control**: browser-use provides browser automation through indexed elements
2. **LLM Integration**: AWS Bedrock Claude models interpret tasks and control the browser
3. **Element Interaction**: Elements are referenced by index numbers [0], [1], [2], etc.

## Available Browser Tools

- `browser_navigate`: Navigate to URLs
- `browser_get_state`: Get current page state with clickable elements
- `browser_click`: Click elements by index
- `browser_type`: Type text into input fields by index
- `browser_extract`: Extract content based on goals
- `browser_screenshot`: Take screenshots
- `browser_scroll`: Scroll pages
- `browser_close`: Close browser session

## Tips

1. **Element Indices**: Always call `browser_get_state` first to see available elements
2. **Headless Mode**: Set `browser_headless = true` in config for background operation
3. **AWS Region**: Ensure your AWS_DEFAULT_REGION matches your Bedrock model region
4. **Model Selection**: Update the model ID in config to use different Claude models

## Troubleshooting

1. **AWS Credentials**: Ensure AWS credentials are properly configured
2. **Browser Issues**: Run `playwright install chromium` if browser fails to launch
3. **Model Access**: Verify you have access to the Bedrock model in your AWS account
4. **Dependencies**: Install all required packages: `pip install -r requirements.txt`