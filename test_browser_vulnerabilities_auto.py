#!/usr/bin/env python3
"""Automated test to demonstrate browser_use_agent.py vulnerabilities."""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.agents.browser_use_agent import BrowserUseAgent
from manus_use.config import Config


async def test_vulnerabilities():
    """Test browser vulnerabilities using browser_use_agent."""
    print("Browser-Use Agent Vulnerability Assessment (Automated)")
    print("=" * 60)
    
    # Test 1: Demonstrate security implications
    print("\n🔍 VULNERABILITY ANALYSIS USING BROWSER-USE AGENT\n")
    
    try:
        # Create a safe config for testing
        config = Config()
        config.browser_use.headless = True  # Keep it headless for automated test
        config.llm.provider = "bedrock"
        config.llm.model = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
        
        agent = BrowserUseAgent(config=config)
        
        # Task 1: Check for common web vulnerabilities
        print("📋 Test 1: Checking for latest web vulnerabilities...")
        task1 = """
        Go to the OWASP Top 10 website (https://owasp.org/www-project-top-ten/) 
        and find the 2 most recent critical web application security risks.
        Extract their names and brief descriptions.
        """
        
        try:
            result1 = await agent(task1)
            print(f"✅ Latest vulnerabilities from OWASP:\n{result1}\n")
        except Exception as e:
            print(f"❌ Error accessing OWASP: {e}\n")
        
        # Task 2: Check browser security headers
        print("📋 Test 2: Analyzing security headers...")
        task2 = """
        Go to https://securityheaders.com and analyze the security headers 
        for example.com. List any missing security headers that could 
        represent vulnerabilities.
        """
        
        try:
            result2 = await agent(task2)
            print(f"✅ Security header analysis:\n{result2}\n")
        except Exception as e:
            print(f"❌ Error analyzing headers: {e}\n")
            
    except Exception as e:
        print(f"❌ Test failed: {e}")
    
    # Display vulnerability summary for browser_use_agent.py itself
    print("\n" + "=" * 60)
    print("🚨 BROWSER_USE_AGENT.PY VULNERABILITY SUMMARY\n")
    
    print("1️⃣ CRITICAL: Security Sandbox Bypass")
    print("   - Location: disable_security parameter (lines 152, 236, 412)")
    print("   - Risk: Allows disabling Chrome's security sandbox")
    print("   - Impact: Remote code execution, system access")
    print("   - Mitigation: Remove or restrict disable_security option\n")
    
    print("2️⃣ HIGH: Command Line Injection")
    print("   - Location: extra_chromium_args parameter (lines 153, 237, 413)")  
    print("   - Risk: Injection of arbitrary Chrome flags")
    print("   - Impact: Remote debugging, CORS bypass, file access")
    print("   - Mitigation: Whitelist allowed Chrome arguments\n")
    
    print("🔒 RECOMMENDATIONS:")
    print("   1. Validate and sanitize all browser configuration inputs")
    print("   2. Use a whitelist for allowed Chrome arguments")
    print("   3. Log security-sensitive configuration changes")
    print("   4. Run browser in isolated environment")
    print("   5. Enable security features by default")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    asyncio.run(test_vulnerabilities())