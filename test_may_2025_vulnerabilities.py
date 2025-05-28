#!/usr/bin/env python3
"""Use browser_use_agent to assess the latest 2 vulnerabilities from May 2025."""

import asyncio
import sys
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.agents.browser_use_agent import BrowserUseAgent
from manus_use.config import Config


async def assess_may_2025_vulnerabilities():
    """Use browser to find and assess latest vulnerabilities from May 2025."""
    print("🔍 Searching for Latest Vulnerabilities (May 2025)")
    print("=" * 60)
    print(f"Current date: {datetime.now().strftime('%Y-%m-%d')}")
    print("Browser mode: VISIBLE (headless=False)\n")
    
    # Create config with headless=False to show browser
    config = Config.from_file(Path("config.toml"))
    config.browser_use.headless = False  # Override to show browser
    
    print("Configuration:")
    print(f"  Provider: {config.browser_use.provider or config.llm.provider}")
    print(f"  Model: {config.browser_use.model or config.llm.model}")
    print(f"  Headless: {config.browser_use.headless}")
    print()
    
    try:
        # Create browser agent
        agent = BrowserUseAgent(config=config)
        
        # Task 1: Search for latest CVEs from May 2025
        print("📋 Task 1: Searching for latest CVEs from May 2025...")
        task1 = """
        Go to the MITRE CVE database (cve.mitre.org) or NVD (nvd.nist.gov) 
        and search for the 2 most recent critical vulnerabilities from May 2025.
        Look for CVEs with CVSS score >= 9.0 or marked as CRITICAL.
        Extract:
        1. CVE ID
        2. Description
        3. CVSS Score
        4. Affected software/vendors
        5. Published date
        """
        
        print("🌐 Opening browser to search for CVEs...\n")
        result1 = await agent(task1)
        print("✅ Latest CVEs from May 2025:")
        print("-" * 40)
        print(result1)
        print()
        
        # Task 2: Search security news for May 2025 vulnerabilities
        print("\n📋 Task 2: Checking security news for May 2025 vulnerabilities...")
        task2 = """
        Go to a security news website like:
        - The Hacker News (thehackernews.com)
        - Bleeping Computer (bleepingcomputer.com)
        - SecurityWeek (securityweek.com)
        
        Search for the 2 most significant vulnerability reports from May 2025.
        Focus on:
        1. Zero-day vulnerabilities
        2. Actively exploited vulnerabilities
        3. High-impact security breaches
        
        Extract the vulnerability details including:
        - Name/Title
        - Affected systems
        - Impact description
        - Exploitation status
        """
        
        print("🌐 Searching security news sites...\n")
        result2 = await agent(task2)
        print("✅ Security News - May 2025 Vulnerabilities:")
        print("-" * 40)
        print(result2)
        print()
        
        # Task 3: Assess specific vulnerability details
        print("\n📋 Task 3: Deep dive into vulnerability assessment...")
        task3 = """
        Based on what you found, pick one of the most critical vulnerabilities
        and visit its detailed page or advisory. Extract:
        1. Technical details of the vulnerability
        2. Attack vector and complexity
        3. Mitigation recommendations
        4. Patch availability
        5. Real-world exploitation evidence
        """
        
        print("🌐 Analyzing vulnerability details...\n")
        result3 = await agent(task3)
        print("✅ Detailed Vulnerability Assessment:")
        print("-" * 40)
        print(result3)
        
    except Exception as e:
        print(f"❌ Error during assessment: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 60)
    print("✅ May 2025 Vulnerability Assessment Complete!")
    print("\nNote: The browser was running in visible mode (headless=False)")
    print("so you could observe the search process.")


async def main():
    """Run the vulnerability assessment."""
    print("May 2025 Vulnerability Assessment using Browser-Use Agent")
    print("=" * 60)
    print("This will open a visible browser window to search for vulnerabilities.\n")
    
    await assess_may_2025_vulnerabilities()


if __name__ == "__main__":
    asyncio.run(main())