#!/usr/bin/env python3
"""Test to demonstrate browser_use_agent.py vulnerabilities."""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.agents.browser_use_agent import BrowserUseAgent
from manus_use.config import Config


async def test_vulnerability_1_disable_security():
    """Test Vulnerability 1: Security Sandbox Bypass"""
    print("=== Testing Vulnerability 1: Security Sandbox Bypass ===\n")
    
    # Create config with security disabled
    config = Config()
    config.browser_use.disable_security = True  # DANGEROUS: Disables Chrome security sandbox
    config.browser_use.headless = False  # Show browser for demonstration
    config.llm.provider = "bedrock"
    config.llm.model = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
    
    print("⚠️  WARNING: Creating browser with security sandbox DISABLED")
    print("This makes the browser vulnerable to:")
    print("- Remote code execution from malicious websites")
    print("- Privilege escalation attacks")
    print("- Unrestricted access to system resources\n")
    
    try:
        agent = BrowserUseAgent(config=config)
        
        # Demonstrate the risk by visiting a potentially malicious site
        # (using a safe example for demonstration)
        task = """
        Go to https://example.com and check if JavaScript can access local files.
        Try to evaluate: window.location = 'file:///etc/passwd'
        """
        
        print("🔴 Attempting to access local files from web context...")
        result = await agent(task)
        print(f"Result: {result}\n")
        
    except Exception as e:
        print(f"Error: {e}\n")


async def test_vulnerability_2_command_injection():
    """Test Vulnerability 2: Chromium Command Line Injection"""
    print("=== Testing Vulnerability 2: Command Line Injection ===\n")
    
    # Create config with dangerous Chrome arguments
    config = Config()
    config.browser_use.extra_chromium_args = [
        "--remote-debugging-port=9222",  # Opens remote debugging
        "--disable-web-security",         # Disables CORS
        "--allow-file-access-from-files", # Allows file:// access
        "--no-sandbox",                   # Disables sandbox (redundant with disable_security)
        "--disable-setuid-sandbox"        # Disables setuid sandbox
    ]
    config.browser_use.headless = False
    config.llm.provider = "bedrock"
    config.llm.model = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
    
    print("⚠️  WARNING: Injecting dangerous Chrome command line arguments:")
    for arg in config.browser_use.extra_chromium_args:
        print(f"  - {arg}")
    print("\nThis configuration enables:")
    print("- Remote debugging on port 9222 (allows remote control)")
    print("- Disabled CORS (bypass same-origin policy)")
    print("- File access from web content")
    print("- No security sandbox\n")
    
    try:
        agent = BrowserUseAgent(config=config)
        
        # Demonstrate the risk
        task = """
        Go to https://example.com and check browser security status.
        Try to access chrome://version to see all command line flags.
        """
        
        print("🔴 Browser launched with dangerous configuration...")
        print("⚠️  Remote debugging available at: http://localhost:9222")
        print("Anyone can now connect and control the browser!\n")
        
        result = await agent(task)
        print(f"Result: {result}\n")
        
    except Exception as e:
        print(f"Error: {e}\n")


async def test_safe_configuration():
    """Test with safe configuration for comparison"""
    print("=== Testing Safe Configuration ===\n")
    
    # Create config with safe settings
    config = Config()
    config.browser_use.disable_security = False  # Security enabled
    config.browser_use.extra_chromium_args = []  # No extra args
    config.browser_use.headless = True          # Headless for safety
    config.llm.provider = "bedrock"
    config.llm.model = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
    
    print("✅ Using safe browser configuration:")
    print("- Security sandbox ENABLED")
    print("- No dangerous command line arguments")
    print("- Running in headless mode\n")
    
    try:
        agent = BrowserUseAgent(config=config)
        
        task = "Go to https://example.com and get the page title"
        
        print("🟢 Running safe browser task...")
        result = await agent(task)
        print(f"Result: {result}\n")
        
    except Exception as e:
        print(f"Error: {e}\n")


async def main():
    """Run all vulnerability tests."""
    print("Browser-Use Agent Vulnerability Assessment")
    print("=" * 50)
    print("⚠️  WARNING: This test demonstrates security vulnerabilities.")
    print("Only run in a controlled environment!\n")
    
    # Get user confirmation
    response = input("Do you want to proceed with the vulnerability test? (yes/no): ")
    if response.lower() != 'yes':
        print("Test cancelled.")
        return
    
    print("\n")
    
    # Test vulnerabilities
    await test_vulnerability_1_disable_security()
    await test_vulnerability_2_command_injection()
    await test_safe_configuration()
    
    print("=" * 50)
    print("Vulnerability Assessment Complete!")
    print("\n🔒 Security Recommendations:")
    print("1. Never set disable_security=True in production")
    print("2. Validate/whitelist extra_chromium_args")
    print("3. Use headless=True when possible")
    print("4. Run browser in isolated environment (Docker/VM)")
    print("5. Implement proper input validation for all browser tasks")


if __name__ == "__main__":
    asyncio.run(main())