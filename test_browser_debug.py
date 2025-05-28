#!/usr/bin/env python3
"""
Debug script to test browser-use integration and configuration.
"""

import os
import sys
import logging
from pathlib import Path

# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def check_imports():
    """Check if required packages are installed"""
    print("="*60)
    print("CHECKING IMPORTS")
    print("="*60)
    
    # Check browser-use
    try:
        import browser_use
        print("✓ browser-use is installed")
        print(f"  Location: {browser_use.__file__}")
    except ImportError as e:
        print(f"✗ browser-use NOT installed: {e}")
        return False
    
    # Check langchain packages
    try:
        import langchain_aws
        print("✓ langchain-aws is installed")
    except ImportError:
        print("✗ langchain-aws NOT installed")
    
    try:
        import langchain_openai
        print("✓ langchain-openai is installed")
    except ImportError:
        print("✗ langchain-openai NOT installed")
    
    # Check playwright
    try:
        import playwright
        print("✓ playwright is installed")
    except ImportError:
        print("✗ playwright NOT installed")
        return False
    
    return True

def check_config():
    """Check configuration"""
    print("\n" + "="*60)
    print("CHECKING CONFIGURATION")
    print("="*60)
    
    # Check config file
    config_path = Path("config.toml")
    if config_path.exists():
        print(f"✓ Config file exists: {config_path}")
        
        # Load and check config
        try:
            from manus_use.config import Config
            config = Config.from_file(config_path)
            print(f"✓ Config loaded successfully")
            
            # Check browser_use section
            browser_config = config.browser_use
            print(f"\nBrowser-use configuration:")
            print(f"  Provider: {browser_config.provider}")
            print(f"  Model: {browser_config.model}")
            print(f"  Headless: {browser_config.headless}")
            print(f"  Enable Memory: {browser_config.enable_memory}")
            
            # Check API keys
            if browser_config.provider == "openai":
                api_key = browser_config.api_key or os.getenv("OPENAI_API_KEY")
                if api_key:
                    print(f"  ✓ OpenAI API key is set")
                else:
                    print(f"  ✗ OpenAI API key NOT set")
                    
            elif browser_config.provider == "bedrock":
                if os.getenv("AWS_ACCESS_KEY_ID"):
                    print(f"  ✓ AWS credentials are set")
                else:
                    print(f"  ✗ AWS credentials NOT set")
                    
        except Exception as e:
            print(f"✗ Error loading config: {e}")
            import traceback
            traceback.print_exc()
    else:
        print(f"✗ Config file NOT found: {config_path}")

def test_browser_use_direct():
    """Test browser-use library directly"""
    print("\n" + "="*60)
    print("TESTING BROWSER-USE DIRECTLY")
    print("="*60)
    
    try:
        from browser_use import Agent
        from langchain_openai import ChatOpenAI
        
        # Check if API key is available
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            print("✗ OPENAI_API_KEY not set, cannot test browser-use")
            return
        
        print("Creating browser-use Agent...")
        
        # Create a simple LLM
        llm = ChatOpenAI(
            model_name="gpt-4o-mini",
            api_key=api_key,
            temperature=0
        )
        
        # Create browser-use agent
        agent = Agent(
            task="Go to https://example.com and tell me the page title",
            llm=llm
        )
        
        print("✓ Browser-use Agent created successfully")
        print("  Note: To run the agent, use: asyncio.run(agent.run())")
        
    except Exception as e:
        print(f"✗ Error creating browser-use Agent: {e}")
        import traceback
        traceback.print_exc()

def test_manus_browser_agent():
    """Test Manus BrowserUseAgent"""
    print("\n" + "="*60)
    print("TESTING MANUS BROWSERUSEAGENT")
    print("="*60)
    
    try:
        from manus_use.agents.browser_use_agent import BrowserUseAgent
        from manus_use.config import Config
        
        config = Config.from_file(Path("config.toml"))
        
        print("Creating BrowserUseAgent...")
        agent = BrowserUseAgent(config)
        print("✓ BrowserUseAgent created successfully")
        
        # Check agent attributes
        print(f"\nAgent configuration:")
        print(f"  Headless: {agent.headless}")
        print(f"  Enable Memory: {agent.enable_memory}")
        print(f"  Max Steps: {agent.max_steps}")
        
    except Exception as e:
        print(f"✗ Error creating BrowserUseAgent: {e}")
        import traceback
        traceback.print_exc()

def main():
    """Run all checks"""
    print("BROWSER-USE INTEGRATION DEBUG")
    print("="*60)
    print(f"Python: {sys.version}")
    print(f"Working Directory: {os.getcwd()}")
    print("="*60)
    
    # Check imports
    if not check_imports():
        print("\n❌ Missing required packages. Please install them first.")
        return
    
    # Check configuration
    check_config()
    
    # Test browser-use directly
    test_browser_use_direct()
    
    # Test Manus BrowserUseAgent
    test_manus_browser_agent()
    
    print("\n" + "="*60)
    print("DEBUG COMPLETE")
    print("="*60)

if __name__ == "__main__":
    main()