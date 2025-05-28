#!/usr/bin/env python3
"""Simple demonstration of browser_use_agent security vulnerabilities."""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.agents.browser_use_agent import BrowserUseAgent
from manus_use.config import Config


def demonstrate_vulnerabilities():
    """Demonstrate the security vulnerabilities without running actual browser."""
    print("Browser-Use Agent Security Vulnerability Demonstration")
    print("=" * 60)
    
    print("\n🔍 VULNERABILITY 1: Security Sandbox Bypass")
    print("-" * 40)
    print("Code Location: browser_use_agent.py")
    print("Lines: 152, 236-239, 405-408\n")
    
    print("Vulnerable Code:")
    print("```python")
    print("# In __init__ method:")
    print("self.disable_security = browser_config.disable_security")
    print("")
    print("# In browser profile creation:")
    print("browser_profile = BrowserProfile(")
    print("    headless=self.headless,")
    print("    disable_security=self.disable_security,  # <-- VULNERABILITY")
    print("    extra_chromium_args=self.extra_chromium_args,")
    print("    keep_alive=self.keep_alive,")
    print(")")
    print("```\n")
    
    print("🚨 Risk: When disable_security=True, Chrome runs without sandbox")
    print("💥 Impact: Malicious websites can:")
    print("   - Execute code on the host system")
    print("   - Access local files")
    print("   - Escape browser isolation")
    
    print("\n\n🔍 VULNERABILITY 2: Command Line Injection")
    print("-" * 40)
    print("Code Location: browser_use_agent.py")
    print("Lines: 153, 237-239, 405-408\n")
    
    print("Vulnerable Code:")
    print("```python")
    print("# In __init__ method:")
    print("self.extra_chromium_args = browser_config.extra_chromium_args")
    print("")
    print("# Passed directly to browser without validation:")
    print("browser_profile = BrowserProfile(")
    print("    ...,")
    print("    extra_chromium_args=self.extra_chromium_args,  # <-- VULNERABILITY")
    print("    ...,")
    print(")")
    print("```\n")
    
    print("🚨 Risk: Arbitrary Chrome flags can be injected")
    print("💥 Attack Vector Examples:")
    print("```python")
    print("# Enable remote debugging (allows remote control):")
    print('extra_chromium_args = ["--remote-debugging-port=9222"]')
    print("")
    print("# Disable all security features:")
    print('extra_chromium_args = [')
    print('    "--no-sandbox",')
    print('    "--disable-setuid-sandbox",')
    print('    "--disable-web-security",')
    print('    "--allow-file-access-from-files"')
    print(']')
    print("```\n")
    
    print("=" * 60)
    print("\n🛡️ PROOF OF CONCEPT")
    print("-" * 40)
    
    print("\nCreating vulnerable configuration...")
    config = Config()
    config.browser_use.disable_security = True
    config.browser_use.extra_chromium_args = [
        "--remote-debugging-port=9222",
        "--disable-web-security",
        "--allow-file-access-from-files"
    ]
    
    print("\nVulnerable Config:")
    print(f"  disable_security: {config.browser_use.disable_security}")
    print(f"  extra_chromium_args: {config.browser_use.extra_chromium_args}")
    
    print("\n⚠️  With this config, an attacker could:")
    print("  1. Connect to port 9222 and control the browser remotely")
    print("  2. Access local files from web pages")
    print("  3. Bypass CORS and other security policies")
    print("  4. Execute arbitrary code if combined with other exploits")
    
    print("\n=" * 60)
    print("\n🔐 SECURITY RECOMMENDATIONS")
    print("-" * 40)
    
    print("\n1. Add validation in BrowserUseAgent.__init__:")
    print("```python")
    print("# Validate disable_security")
    print("if browser_config.disable_security:")
    print('    logging.warning("Security sandbox disabled - use with extreme caution!")')
    print("    # Or better: raise ValueError('disable_security not allowed')")
    print("")
    print("# Whitelist allowed Chrome args")
    print("ALLOWED_CHROME_ARGS = [")
    print('    "--headless",')
    print('    "--window-size=1920,1080",')
    print('    "--user-agent=...",')
    print(']')
    print("for arg in browser_config.extra_chromium_args:")
    print("    if not any(arg.startswith(allowed) for allowed in ALLOWED_CHROME_ARGS):")
    print('        raise ValueError(f"Chrome arg not allowed: {arg}")')
    print("```")
    
    print("\n2. Default to secure configuration:")
    print("```python")
    print("# In BrowserUseConfig defaults:")
    print("disable_security: bool = False  # Never True by default")
    print("extra_chromium_args: list[str] = []  # Empty by default")
    print("```")
    
    print("\n3. Add security warnings in config.example.toml")
    print("\n4. Consider removing disable_security option entirely")
    print("\n5. Run browser in Docker/sandbox for additional isolation")
    
    print("\n=" * 60)
    print("✅ Vulnerability demonstration complete!")


async def test_with_safe_browser():
    """Test browser with safe configuration."""
    print("\n\n🟢 TESTING WITH SAFE CONFIGURATION")
    print("=" * 60)
    
    # Create safe config
    config = Config()
    config.browser_use.disable_security = False  # Security enabled
    config.browser_use.extra_chromium_args = []  # No dangerous args
    config.browser_use.headless = True
    config.llm.provider = "bedrock"
    config.llm.model = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
    
    print("Safe Configuration:")
    print(f"  disable_security: {config.browser_use.disable_security}")
    print(f"  extra_chromium_args: {config.browser_use.extra_chromium_args}")
    print(f"  headless: {config.browser_use.headless}")
    
    try:
        agent = BrowserUseAgent(config=config)
        print("\n✅ Browser agent created with safe configuration")
        
        # Simple safe task
        task = "What is 2+2?"
        print(f"\nExecuting safe task: {task}")
        result = await agent(task)
        print(f"Result: {result}")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")


async def main():
    """Run the vulnerability demonstration."""
    # First show the vulnerabilities
    demonstrate_vulnerabilities()
    
    # Then test with safe config
    await test_with_safe_browser()


if __name__ == "__main__":
    asyncio.run(main())