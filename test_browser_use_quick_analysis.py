#!/usr/bin/env python3
"""Quick multi-agent analysis of browser-use documentation."""

import asyncio
from pathlib import Path
from datetime import datetime

from src.manus_use.agents import BrowserAgent, ManusAgent
from src.manus_use.config import Config


async def quick_browser_use_analysis():
    """Perform a quick focused analysis of browser-use documentation."""
    
    print("=== Quick Browser-Use Documentation Analysis ===\n")
    
    # Load configuration
    config_path = Path(__file__).parent / "config" / "config.bedrock.toml"
    if not config_path.exists():
        print(f"Error: Configuration file not found at {config_path}")
        return
    
    config = Config.from_file(config_path)
    
    # Initialize agents
    browser_agent = BrowserAgent(config=config)
    manus_agent = ManusAgent(config=config)
    
    print("Phase 1: Extracting documentation content...")
    
    # Extract main documentation
    extraction_prompt = """
    Navigate to https://deepwiki.com/browser-use/browser-use and extract:
    1. Overview of browser-use (what it is, main purpose)
    2. Key features (bullet points)
    3. Installation instructions (pip install command)
    4. One basic usage example (code snippet)
    5. Main benefits and use cases
    
    Be concise but thorough. Extract the most important information.
    """
    
    try:
        extraction_result = browser_agent(extraction_prompt)
        # Convert AgentResult to string
        if hasattr(extraction_result, 'result'):
            extracted_content = str(extraction_result.result)
        else:
            extracted_content = str(extraction_result)
        print("✓ Content extracted successfully")
    except Exception as e:
        print(f"✗ Extraction failed: {e}")
        extracted_content = "Failed to extract content"
    
    print("\nPhase 2: Analyzing and structuring content...")
    
    # Analyze and structure the content
    analysis_prompt = f"""
    Based on this extracted content about browser-use:
    
    {extracted_content}
    
    Create a well-structured markdown report with the following sections:
    
    # Browser-Use Documentation Analysis
    
    ## Overview
    (Summarize what browser-use is in 2-3 sentences)
    
    ## Key Features
    (List the main features as bullet points)
    
    ## Installation
    (Provide the installation command and any prerequisites)
    
    ## Basic Usage Example
    (Include a simple code example with explanation)
    
    ## Use Cases
    (List 3-5 primary use cases)
    
    ## Advantages
    (List key benefits of using browser-use)
    
    ## Comparison with Alternatives
    (Brief comparison with Selenium/Playwright - 2-3 points)
    
    ## Conclusion
    (2-3 sentence summary and recommendation)
    
    Format everything properly in markdown.
    """
    
    try:
        report_result = manus_agent(analysis_prompt)
        # Convert AgentResult to string
        if hasattr(report_result, 'result'):
            report = str(report_result.result)
        else:
            report = str(report_result)
        print("✓ Analysis completed successfully")
    except Exception as e:
        print(f"✗ Analysis failed: {e}")
        report = f"# Browser-Use Analysis Report\n\nAnalysis failed: {e}"
    
    # Save the report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = Path(f"browser_use_quick_analysis_{timestamp}.md")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\n✓ Report saved to: {output_file}")
    print(f"  File size: {output_file.stat().st_size:,} bytes")
    
    # Display preview
    lines = report.split('\n')[:20]
    print("\nReport Preview:")
    print("-" * 50)
    for line in lines:
        print(line)
    if len(report.split('\n')) > 20:
        print("...")
    
    return output_file


async def main():
    """Run the quick analysis."""
    
    start_time = datetime.now()
    print(f"Starting at: {start_time.strftime('%H:%M:%S')}\n")
    
    try:
        output_file = await quick_browser_use_analysis()
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        print(f"\n✅ Analysis completed in {duration:.2f} seconds")
        
        if output_file and output_file.exists():
            print(f"\nYou can view the full report at: {output_file}")
            
    except KeyboardInterrupt:
        print("\n\n⚠️ Analysis interrupted by user")
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())