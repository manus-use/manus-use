#!/usr/bin/env python3
"""Test browser-use configuration loading."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.config import Config


def test_config_loading():
    """Test that browser_use config section loads correctly."""
    print("Testing browser-use configuration loading...\n")
    
    # Load config from file
    config = Config.from_file(Path("config.toml"))
    
    # Check main config
    print("=== Main LLM Config ===")
    print(f"Provider: {config.llm.provider}")
    print(f"Model: {config.llm.model}")
    print(f"Temperature: {config.llm.temperature}")
    print(f"Max tokens: {config.llm.max_tokens}")
    
    # Check browser_use config
    print("\n=== Browser-Use Config ===")
    browser_config = config.browser_use
    print(f"Provider: {browser_config.provider or 'inherits from main'}")
    print(f"Model: {browser_config.model or 'inherits from main'}")
    print(f"Temperature: {browser_config.temperature}")
    print(f"Max tokens: {browser_config.max_tokens}")
    print(f"Headless: {browser_config.headless}")
    print(f"Keep alive: {browser_config.keep_alive}")
    print(f"Max steps: {browser_config.max_steps}")
    print(f"Use vision: {browser_config.use_vision}")
    print(f"Enable memory: {browser_config.enable_memory}")
    print(f"Tool calling method: {browser_config.tool_calling_method}")
    print(f"Debug: {browser_config.debug}")
    print(f"Save screenshots: {browser_config.save_screenshots}")
    
    # Test BrowserUseAgent initialization
    print("\n=== Testing BrowserUseAgent Initialization ===")
    try:
        from manus_use.agents.browser_use_agent import BrowserUseAgent
        
        agent = BrowserUseAgent(config=config)
        print("✅ BrowserUseAgent initialized successfully")
        print(f"   - Headless: {agent.headless}")
        print(f"   - Enable memory: {agent.enable_memory}")
        print(f"   - Max steps: {agent.max_steps}")
        print(f"   - Use vision: {agent.use_vision}")
        
    except Exception as e:
        print(f"❌ Failed to initialize BrowserUseAgent: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n✅ Configuration test completed!")


if __name__ == "__main__":
    test_config_loading()