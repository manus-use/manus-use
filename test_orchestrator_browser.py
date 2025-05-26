"""Test the orchestrator with BrowserUseAgent."""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from manus_use.multi_agents.orchestrator import Orchestrator
from manus_use.config import Config


def test_orchestrator_browser():
    """Test orchestrator with browser task."""
    print("Testing Orchestrator with BrowserUseAgent...")
    
    # Create config
    config_path = Path(__file__).parent / "config" / "config.bedrock.toml"
    config = Config.from_file(config_path)
    
    # Create orchestrator
    orchestrator = Orchestrator(config)
    
    # Test browser task
    task = "Go to https://www.python.org and tell me what the latest Python version is"
    print(f"\nTask: {task}")
    
    try:
        # Run orchestrator
        result = orchestrator.run(task)
        print(f"\nResult: {result}")
        print("\n✅ Test passed!")
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    test_orchestrator_browser()