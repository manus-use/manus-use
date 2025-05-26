"""Use browser_tools to access deepwiki.com and summarize to markdown."""

import asyncio
import sys
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.tools.browser_tools import browser_do, browser_extract_content, browser_cleanup


async def summarize_deepwiki():
    """Access deepwiki.com/browser-use and create a summary."""
    print("Accessing deepwiki.com/browser-use...")
    print("=" * 60)
    
    # Navigate to the page
    print("\n1. Navigating to the page...")
    nav_result = await browser_do(
        task="Navigate to https://deepwiki.com/browser-use/browser-us",
        headless=True
    )
    print(f"Navigation result: {nav_result.get('success')}")
    
    # Extract the main content
    print("\n2. Extracting page content...")
    content_result = await browser_extract_content(
        goal="Extract all content including headings, paragraphs, code examples, and any important information about browser-use",
        include_links=True
    )
    print(f"Content extraction: {content_result.get('success')}")
    
    # Get page title and structure
    print("\n3. Getting page structure...")
    structure_result = await browser_do(
        task="Analyze the page structure and identify all main sections, headings, and the overall organization of the content"
    )
    print(f"Structure analysis: {structure_result.get('success')}")
    
    # Create a comprehensive summary
    print("\n4. Creating comprehensive summary...")
    summary_result = await browser_do(
        task="""Create a detailed summary of the browser-use documentation including:
        1. What browser-use is and its purpose
        2. Key features and capabilities
        3. Installation instructions
        4. Basic usage examples
        5. API reference or important methods
        6. Any code examples found on the page
        7. Best practices or tips mentioned
        8. Any limitations or considerations
        Format the summary in markdown with proper headings and sections."""
    )
    print(f"Summary creation: {summary_result.get('success')}")
    
    # Cleanup
    await browser_cleanup()
    
    # Compile all results
    print("\n5. Compiling results...")
    
    # Create markdown content
    md_content = f"""# Browser-Use Documentation Summary

**Generated on:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

**Source:** https://deepwiki.com/browser-use/browser-us

---

## Page Content

{content_result.get('result', 'No content extracted')}

---

## Page Structure

{structure_result.get('result', 'No structure information')}

---

## Comprehensive Summary

{summary_result.get('result', 'No summary available')}

---

*This summary was automatically generated using browser_tools.py*
"""
    
    # Save to file
    output_file = "deepwiki_browser_use_summary.md"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(md_content)
    
    print(f"\n✅ Summary saved to: {output_file}")
    print("=" * 60)
    
    return output_file


if __name__ == "__main__":
    print("Starting deepwiki.com browser-use documentation extraction...")
    print("This will use browser automation to access and summarize the page.\n")
    
    try:
        output_file = asyncio.run(summarize_deepwiki())
        print(f"\nSuccess! Check the file: {output_file}")
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()