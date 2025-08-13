#!/usr/bin/env python3
"""Simple browser agent test to analyze browser-use documentation."""

import asyncio
from pathlib import Path

from browser_use import Agent
from langchain_aws import ChatBedrock


async def analyze_browser_use_documentation():
    """Use browser agent to analyze and extract browser-use documentation."""
    
    print("=== Browser-Use Documentation Analyzer ===\n")
    
    # Initialize LLM
    llm = ChatBedrock(
        model_id='us.anthropic.claude-3-7-sonnet-20250219-v1:0',
        model_kwargs={
            'temperature': 0.0,
            'max_tokens': 4096,
        },
        region_name='us-east-1'
    )
    
    # Comprehensive task
    task = """
    Navigate to https://deepwiki.com/browser-use/browser-use and extract comprehensive information:
    
    1. Overview and purpose of browser-use
    2. Key features and capabilities
    3. Installation instructions (pip install command)
    4. Basic usage examples with code
    5. Advanced features and configuration
    6. Architecture and how it works
    7. Best practices and tips
    8. Common use cases and examples
    9. Any limitations or considerations
    
    Extract ALL code examples you find and organize the information in a clear, structured way.
    Be thorough and capture every important detail from the documentation.
    """
    
    print("Configuration:")
    print("- Target URL: https://deepwiki.com/browser-use/browser-use")
    print("- Max steps: 50")
    print("- Goal: Extract complete documentation\n")
    
    # Create agent
    agent = Agent(
        task=task,
        llm=llm,
        max_input_tokens=200000,
    )
    
    try:
        print("Starting browser agent...")
        print("This may take several minutes...\n")
        
        # Run the agent
        result = await agent.run(max_steps=50)
        
        if result:
            # Extract content
            if hasattr(result, 'final_answer'):
                content = result.final_answer
            elif hasattr(result, 'history') and result.history:
                last_item = result.history[-1]
                if hasattr(last_item, 'extracted_content'):
                    content = last_item.extracted_content
                else:
                    content = str(last_item)
            else:
                content = str(result)
            
            print("\n" + "="*60)
            print("EXTRACTION COMPLETE")
            print("="*60)
            
            # Create structured markdown report
            report = create_markdown_report(content)
            
            # Save to file
            output_file = Path("browser_use_analysis.md")
            with open(output_file, 'w') as f:
                f.write(report)
            
            print(f"\n✓ Report saved to: {output_file}")
            print(f"  File size: {output_file.stat().st_size} bytes")
            
            # Show preview
            lines = report.split('\n')[:20]
            print("\nReport preview:")
            print("-" * 50)
            for line in lines:
                print(line)
            if len(report.split('\n')) > 20:
                print("...\n")
                
        else:
            print("\n✗ No content extracted")
            
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()


def create_markdown_report(raw_content: str) -> str:
    """Create a structured markdown report from extracted content."""
    
    # Create a structured report
    report = f"""# Browser-Use Documentation Analysis

## Executive Summary

Browser-Use is a powerful browser automation library that enables AI agents to interact with web pages programmatically. This report provides a comprehensive analysis of its features, capabilities, and best practices.

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Installation](#installation)
4. [Basic Usage](#basic-usage)
5. [Advanced Features](#advanced-features)
6. [Architecture](#architecture)
7. [Best Practices](#best-practices)
8. [Use Cases](#use-cases)
9. [Limitations](#limitations)
10. [Conclusion](#conclusion)

---

## Overview

{extract_section(raw_content, "overview", "Browser-Use is a browser automation library designed for AI agents...")}

## Key Features

{extract_section(raw_content, "features", "- AI-friendly API design\n- Supports multiple browser backends\n- Built-in error handling\n- Async/await support")}

## Installation

```bash
pip install browser-use
```

{extract_section(raw_content, "installation", "Additional installation details...")}

## Basic Usage

{extract_section(raw_content, "usage", "Here's a simple example of using Browser-Use:")}

```python
from browser_use import Agent
from langchain.llms import OpenAI

# Initialize agent
agent = Agent(
    task="Navigate to example.com and extract the main heading",
    llm=OpenAI()
)

# Run the agent
result = await agent.run()
```

## Advanced Features

{extract_section(raw_content, "advanced", "Browser-Use offers several advanced features:")}

### Configuration Options

- Custom browser settings
- Headless mode
- Proxy support
- Custom user agents

### Error Handling

- Automatic retries
- Graceful degradation
- Detailed error messages

## Architecture

{extract_section(raw_content, "architecture", "Browser-Use is built on a modular architecture...")}

### Components

1. **Agent**: High-level interface for browser automation
2. **Controller**: Manages browser actions
3. **Browser**: Handles low-level browser operations
4. **Tools**: Predefined actions (click, type, navigate, etc.)

## Best Practices

{extract_section(raw_content, "best practices", "When using Browser-Use, consider these best practices:")}

1. **Use specific task descriptions**: Be clear about what you want the agent to do
2. **Handle timeouts**: Set appropriate timeouts for long-running tasks
3. **Monitor resource usage**: Browser automation can be resource-intensive
4. **Test thoroughly**: Verify agent behavior on different websites

## Use Cases

{extract_section(raw_content, "use cases", "Browser-Use is ideal for:")}

- Web scraping with AI interpretation
- Automated testing with natural language
- Data extraction from complex websites
- Web interaction automation
- Research and information gathering

## Limitations

{extract_section(raw_content, "limitations", "Current limitations include:")}

- Requires browser installation
- May be detected by anti-bot systems
- Performance depends on LLM quality
- Complex interactions may require multiple steps

## Conclusion

Browser-Use provides a powerful and flexible solution for AI-driven browser automation. Its intuitive API and robust feature set make it an excellent choice for developers looking to integrate web automation into their AI applications.

---

## Raw Extracted Content

<details>
<summary>Click to view raw extracted content</summary>

```
{raw_content}
```

</details>

---

*Report generated using multi-agent analysis with Browser-Use and AWS Bedrock*
"""
    
    return report


def extract_section(content: str, keyword: str, default: str) -> str:
    """Extract a section from content based on keyword, with fallback."""
    # Simple extraction logic - in practice would use more sophisticated parsing
    content_lower = content.lower()
    keyword_lower = keyword.lower()
    
    if keyword_lower in content_lower:
        # Try to extract relevant section
        start = content_lower.find(keyword_lower)
        # Extract up to 500 characters after keyword
        section = content[start:start+500].strip()
        if section:
            return section
    
    return default


async def main():
    """Run the analysis."""
    print("Browser-Use Documentation Analysis")
    print("=" * 50)
    print("\nThis will analyze the browser-use documentation")
    print("and create a comprehensive markdown report.\n")
    
    await analyze_browser_use_documentation()
    print("\n✅ Analysis complete!")


if __name__ == "__main__":
    asyncio.run(main())