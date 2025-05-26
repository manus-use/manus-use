"""Extract browser-use documentation from a URL."""

import asyncio
import sys
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.tools.browser_tools import browser_do, browser_cleanup


async def extract_browser_use_docs():
    """Extract browser-use documentation."""
    print("Extracting browser-use documentation...")
    print("=" * 60)
    
    # Try the GitHub repository first
    print("\n1. Trying GitHub repository...")
    result = await browser_do(
        task="""Go to https://deepwiki.com/browser-use/browser-use and extract:
        1. The README content
        2. What browser-use is and its purpose
        3. Key features
        4. Installation instructions
        5. Usage examples
        6. Any important documentation
        Format everything in markdown.""",
        headless=False
    )
    
    # Cleanup
    await browser_cleanup()
    
    if result.get('success'):
        # Create markdown file
        md_content = f"""# Browser-Use Documentation

**Generated on:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

**Source:** https://github.com/browser-use/browser-use

---

{result.get('result', 'No content extracted')}

---

*This documentation was automatically extracted using browser_tools.py*
"""
        
        # Save to file
        output_file = "browser_use_documentation.md"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(md_content)
        
        print(f"\n✅ Documentation saved to: {output_file}")
        print("=" * 60)
        
        return output_file
    else:
        print(f"\n❌ Failed to extract documentation: {result.get('error')}")
        return None


if __name__ == "__main__":
    print("Starting browser-use documentation extraction...")
    print("This will use browser automation to extract documentation from GitHub.\n")
    
    try:
        output_file = asyncio.run(extract_browser_use_docs())
        if output_file:
            print(f"\nSuccess! Check the file: {output_file}")
        else:
            print("\nFailed to extract documentation.")
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()