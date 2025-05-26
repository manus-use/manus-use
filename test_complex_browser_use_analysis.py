#!/usr/bin/env python3
"""Complex multi-agent test to analyze browser-use documentation comprehensively."""

import asyncio
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

from src.manus_use.multi_agents import FlowOrchestrator
from src.manus_use.multi_agents.task_planning_agent import PlanningAgent, TaskPlan
from src.manus_use.config import Config
from src.manus_use.agents import BrowserAgent, DataAnalysisAgent, ManusAgent


class BrowserUseDocumentationAnalyzer:
    """Complex analyzer for browser-use documentation using multiple agents."""
    
    def __init__(self, config: Config):
        self.config = config
        self.orchestrator = FlowOrchestrator(config)
        self.results = {}
        self.start_time = None
        self.end_time = None
    
    async def analyze_documentation(self) -> Dict[str, Any]:
        """Run comprehensive analysis of browser-use documentation."""
        
        self.start_time = datetime.now()
        print(f"[{self.start_time.strftime('%H:%M:%S')}] Starting comprehensive browser-use analysis...")
        
        # Phase 1: Planning
        print("\n=== Phase 1: Task Planning ===")
        plan = await self._create_analysis_plan()
        
        # Phase 2: Content Extraction
        print("\n=== Phase 2: Content Extraction ===")
        extraction_results = await self._extract_documentation_content()
        
        # Phase 3: Deep Analysis
        print("\n=== Phase 3: Deep Analysis ===")
        analysis_results = await self._analyze_extracted_content(extraction_results)
        
        # Phase 4: Report Generation
        print("\n=== Phase 4: Report Generation ===")
        report = await self._generate_comprehensive_report(extraction_results, analysis_results)
        
        # Phase 5: Save Results
        print("\n=== Phase 5: Saving Results ===")
        output_path = await self._save_results(report)
        
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()
        
        print(f"\n[{self.end_time.strftime('%H:%M:%S')}] Analysis completed in {duration:.2f} seconds")
        
        return {
            "success": True,
            "output_path": str(output_path),
            "duration": duration,
            "extraction_results": extraction_results,
            "analysis_results": analysis_results
        }
    
    async def _create_analysis_plan(self) -> List[TaskPlan]:
        """Create a detailed task plan for the analysis."""
        
        planner = PlanningAgent(config=self.config)
        
        planning_request = """
        Create a comprehensive plan to analyze the browser-use documentation at https://deepwiki.com/browser-use/browser-use.
        
        The plan should include:
        1. Navigate to the documentation page and extract all content
        2. Identify and extract all code examples
        3. Analyze the architecture and design patterns
        4. Compare features with similar tools
        5. Extract installation and setup instructions
        6. Identify best practices and recommendations
        7. Analyze use cases and limitations
        8. Generate a comprehensive markdown report
        
        Each task should be assigned to the appropriate agent type (browser, data_analysis, manus).
        """
        
        plan = planner.create_plan(planning_request)
        
        print(f"Created {len(plan)} tasks:")
        for i, task in enumerate(plan, 1):
            print(f"  {i}. [{task.agent_type}] {task.description[:60]}...")
        
        return plan
    
    async def _extract_documentation_content(self) -> Dict[str, Any]:
        """Extract all content from the browser-use documentation."""
        
        browser_agent = BrowserAgent(config=self.config)
        
        extraction_tasks = [
            {
                "name": "overview",
                "prompt": """Navigate to https://deepwiki.com/browser-use/browser-use and extract:
                - Main title and description
                - Overview of what browser-use is
                - Key features list
                - Main benefits
                Extract everything visible on the main page."""
            },
            {
                "name": "installation",
                "prompt": """On the browser-use documentation page, find and extract:
                - Complete installation instructions
                - System requirements
                - Dependencies
                - Configuration steps
                - Environment setup
                Include all code snippets and commands."""
            },
            {
                "name": "usage_examples",
                "prompt": """Find and extract all usage examples from the documentation:
                - Basic usage examples
                - Advanced examples
                - Code snippets
                - Configuration examples
                - Real-world use cases
                Capture all code blocks completely."""
            },
            {
                "name": "api_reference",
                "prompt": """Extract API reference information:
                - Main classes and methods
                - Parameters and options
                - Return values
                - Error handling
                - Available tools and actions"""
            },
            {
                "name": "architecture",
                "prompt": """Extract architecture and design information:
                - System architecture overview
                - Component descriptions
                - How it works internally
                - Integration points
                - Design patterns used"""
            }
        ]
        
        results = {}
        for task in extraction_tasks:
            print(f"\nExtracting {task['name']}...")
            try:
                result = browser_agent(task['prompt'])
                results[task['name']] = result
                print(f"  ✓ Extracted {len(str(result))} characters")
            except Exception as e:
                print(f"  ✗ Error: {e}")
                results[task['name']] = f"Error extracting {task['name']}: {str(e)}"
        
        return results
    
    async def _analyze_extracted_content(self, extraction_results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform deep analysis on extracted content."""
        
        data_agent = DataAnalysisAgent(config=self.config)
        manus_agent = ManusAgent(config=self.config)
        
        analysis_tasks = [
            {
                "name": "feature_comparison",
                "agent": data_agent,
                "prompt": f"""Based on this browser-use documentation:
                {extraction_results.get('overview', '')}
                {extraction_results.get('api_reference', '')}
                
                Create a detailed feature comparison with similar tools like:
                - Selenium
                - Playwright
                - Puppeteer
                - AutoGPT browser capabilities
                
                Include pros and cons for each."""
            },
            {
                "name": "code_quality_analysis",
                "agent": manus_agent,
                "prompt": f"""Analyze these code examples from browser-use:
                {extraction_results.get('usage_examples', '')}
                
                Evaluate:
                - Code quality and readability
                - Best practices followed
                - Potential improvements
                - Common patterns used
                - Error handling approaches"""
            },
            {
                "name": "architecture_analysis",
                "agent": data_agent,
                "prompt": f"""Analyze the browser-use architecture:
                {extraction_results.get('architecture', '')}
                
                Provide insights on:
                - Scalability
                - Maintainability
                - Performance characteristics
                - Security considerations
                - Extension points"""
            },
            {
                "name": "use_case_analysis",
                "agent": manus_agent,
                "prompt": f"""Based on the browser-use documentation:
                {extraction_results.get('overview', '')}
                {extraction_results.get('usage_examples', '')}
                
                Identify and analyze:
                - Top 5 use cases
                - Industry applications
                - Automation scenarios
                - Integration possibilities
                - ROI potential"""
            }
        ]
        
        results = {}
        for task in analysis_tasks:
            print(f"\nAnalyzing {task['name']}...")
            try:
                result = task['agent'](task['prompt'])
                results[task['name']] = result
                print(f"  ✓ Analysis completed")
            except Exception as e:
                print(f"  ✗ Error: {e}")
                results[task['name']] = f"Error in {task['name']}: {str(e)}"
        
        return results
    
    async def _generate_comprehensive_report(self, extraction_results: Dict[str, Any], 
                                           analysis_results: Dict[str, Any]) -> str:
        """Generate a comprehensive markdown report."""
        
        manus_agent = ManusAgent(config=self.config)
        
        # Create report structure
        report_sections = []
        
        # Title and metadata
        report_sections.append(f"""# Browser-Use: Comprehensive Documentation Analysis

**Analysis Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Documentation URL**: https://deepwiki.com/browser-use/browser-use  
**Analysis Method**: Multi-Agent Deep Analysis

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [What is Browser-Use?](#what-is-browser-use)
3. [Installation & Setup](#installation--setup)
4. [Core Features](#core-features)
5. [Architecture Analysis](#architecture-analysis)
6. [Code Examples](#code-examples)
7. [Feature Comparison](#feature-comparison)
8. [Use Cases](#use-cases)
9. [Best Practices](#best-practices)
10. [Limitations & Considerations](#limitations--considerations)
11. [Conclusion & Recommendations](#conclusion--recommendations)

---
""")
        
        # Executive Summary
        summary_prompt = f"""Create an executive summary based on this analysis:
        Overview: {extraction_results.get('overview', 'N/A')}
        Key Features: {analysis_results.get('feature_comparison', 'N/A')}
        
        Write a 2-3 paragraph executive summary highlighting the most important findings."""
        
        summary = manus_agent(summary_prompt)
        report_sections.append(f"## Executive Summary\n\n{summary}\n\n")
        
        # Main sections
        sections = [
            ("What is Browser-Use?", extraction_results.get('overview', 'Information not available')),
            ("Installation & Setup", extraction_results.get('installation', 'Information not available')),
            ("Core Features", extraction_results.get('api_reference', 'Information not available')),
            ("Architecture Analysis", analysis_results.get('architecture_analysis', 'Analysis not available')),
            ("Code Examples", extraction_results.get('usage_examples', 'Examples not available')),
            ("Feature Comparison", analysis_results.get('feature_comparison', 'Comparison not available')),
            ("Use Cases", analysis_results.get('use_case_analysis', 'Analysis not available')),
            ("Best Practices", analysis_results.get('code_quality_analysis', 'Analysis not available'))
        ]
        
        for title, content in sections:
            report_sections.append(f"## {title}\n\n{content}\n\n")
        
        # Limitations section
        limitations_prompt = """Based on the browser-use documentation analysis, identify:
        1. Current limitations
        2. Potential challenges
        3. Security considerations
        4. Performance implications
        5. Scalability concerns"""
        
        limitations = manus_agent(limitations_prompt)
        report_sections.append(f"## Limitations & Considerations\n\n{limitations}\n\n")
        
        # Conclusion
        conclusion_prompt = """Write a comprehensive conclusion with:
        1. Summary of key findings
        2. Recommendations for different use cases
        3. Future outlook
        4. Final verdict on browser-use as a tool"""
        
        conclusion = manus_agent(conclusion_prompt)
        report_sections.append(f"## Conclusion & Recommendations\n\n{conclusion}\n\n")
        
        # Appendix
        report_sections.append("""---

## Appendix

### Analysis Methodology

This report was generated using a multi-agent system that:
1. **Browser Agent**: Extracted content directly from the documentation
2. **Data Analysis Agent**: Performed comparative analysis and architecture review
3. **Manus Agent**: Generated insights and recommendations

### Raw Data

<details>
<summary>Click to view raw extraction data</summary>

```json
""")
        
        # Add raw data
        report_sections.append(json.dumps({
            "extraction_results": {k: str(v)[:500] + "..." if len(str(v)) > 500 else str(v) 
                                 for k, v in extraction_results.items()},
            "analysis_results": {k: str(v)[:500] + "..." if len(str(v)) > 500 else str(v) 
                               for k, v in analysis_results.items()}
        }, indent=2))
        
        report_sections.append("""
```

</details>

---

*This report was generated automatically using the Manus-Use Multi-Agent Framework*
""")
        
        return "\n".join(report_sections)
    
    async def _save_results(self, report: str) -> Path:
        """Save the analysis results to a markdown file."""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"browser_use_analysis_{timestamp}.md"
        output_path = Path(filename)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"✓ Report saved to: {output_path}")
        print(f"  File size: {output_path.stat().st_size:,} bytes")
        
        # Also save a summary version
        summary_path = Path(f"browser_use_summary_{timestamp}.md")
        summary = self._create_summary(report)
        
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write(summary)
        
        print(f"✓ Summary saved to: {summary_path}")
        
        return output_path
    
    def _create_summary(self, full_report: str) -> str:
        """Create a summary version of the report."""
        
        lines = full_report.split('\n')
        summary_lines = []
        
        # Extract key sections
        in_summary = False
        section_count = 0
        
        for line in lines:
            if line.startswith('# ') or line.startswith('## '):
                summary_lines.append(line)
                section_count = 0
                in_summary = line.startswith('## Executive Summary') or line.startswith('## Conclusion')
            elif in_summary and section_count < 10:
                summary_lines.append(line)
                section_count += 1
            elif line.startswith('1. ') or line.startswith('- '):
                summary_lines.append(line)
        
        return '\n'.join(summary_lines)


async def main():
    """Run the complex browser-use documentation analysis."""
    
    print("=" * 80)
    print("Browser-Use Documentation - Complex Multi-Agent Analysis")
    print("=" * 80)
    
    # Load configuration
    config_path = Path(__file__).parent / "config" / "config.bedrock.toml"
    
    if not config_path.exists():
        print(f"\n✗ Error: Configuration file not found at {config_path}")
        print("Please create config/config.bedrock.toml with your AWS credentials")
        return
    
    try:
        config = Config.from_file(config_path)
        print(f"\n✓ Configuration loaded from: {config_path}")
    except Exception as e:
        print(f"\n✗ Error loading configuration: {e}")
        return
    
    # Create analyzer
    analyzer = BrowserUseDocumentationAnalyzer(config)
    
    print("\nThis analysis will:")
    print("1. Create a comprehensive task plan")
    print("2. Extract documentation content using browser automation")
    print("3. Perform deep analysis using multiple agents")
    print("4. Generate a detailed markdown report")
    print("5. Save results with timestamps")
    
    print("\n" + "=" * 80)
    
    try:
        # Run analysis
        results = await analyzer.analyze_documentation()
        
        if results['success']:
            print("\n" + "=" * 80)
            print("✅ ANALYSIS COMPLETED SUCCESSFULLY")
            print("=" * 80)
            print(f"\nResults saved to: {results['output_path']}")
            print(f"Total duration: {results['duration']:.2f} seconds")
            
            # Show file preview
            with open(results['output_path'], 'r') as f:
                preview = f.read(1000)
                print("\nReport Preview:")
                print("-" * 40)
                print(preview)
                print("..." if len(f.read()) > 0 else "")
        else:
            print("\n✗ Analysis failed")
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user")
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())