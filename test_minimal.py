#!/usr/bin/env python3
"""Minimal test for AWS Bedrock integration."""

import os
import sys
from pathlib import Path

# Add paths
sys.path.insert(0, str(Path(__file__).parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent / "sdk-python" / "src"))


def test_bedrock_direct():
    """Test Bedrock directly without ManusUse."""
    print("=== Testing Direct Bedrock Connection ===")
    try:
        from strands.models import BedrockModel
        
        # Create model directly
        model = BedrockModel(
            model_id="us.anthropic.claude-3-5-sonnet-20241022-v2:0",
            region_name=os.getenv("AWS_DEFAULT_REGION", "us-west-2"),
            temperature=0.0,
            max_tokens=100
        )
        
        print(f"✓ Created BedrockModel: {model}")
        
        # Test with simple prompt
        from strands import Agent
        agent = Agent(
            model=model,
            tools=[],
            system_prompt="You are a helpful assistant. Keep answers very brief."
        )
        
        response = agent("What is 2 + 2? Answer with just the number.")
        print(f"✓ Response: {response}")
        
        return True
        
    except Exception as e:
        print(f"✗ Direct Bedrock test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_file_tools():
    """Test file tools independently."""
    print("\n=== Testing File Tools ===")
    try:
        from strands.tools import tool
        import tempfile
        
        @tool
        def simple_write(content: str) -> str:
            """Write content to a temp file."""
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(content)
                return f"Wrote to {f.name}"
        
        # Test the tool
        result = simple_write("Hello, test!")
        print(f"✓ Tool result: {result}")
        
        return True
        
    except Exception as e:
        print(f"✗ File tools test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_manus_config():
    """Test ManusUse configuration."""
    print("\n=== Testing ManusUse Config ===")
    try:
        from manus_use.config import Config, LLMConfig
        
        # Create config programmatically
        config = Config(
            llm=LLMConfig(
                provider="bedrock",
                model="us.anthropic.claude-3-5-sonnet-20241022-v2:0",
                temperature=0.0,
                max_tokens=100
            )
        )
        
        print(f"✓ Config created: provider={config.llm.provider}, model={config.llm.model}")
        
        # Get model kwargs
        kwargs = config.llm.model_kwargs
        print(f"✓ Model kwargs: {kwargs}")
        
        return True
        
    except Exception as e:
        print(f"✗ Config test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run minimal tests."""
    print("ManusUse Minimal Test Suite")
    print("=" * 40)
    
    # Check environment
    print("\n=== Environment Check ===")
    print(f"✓ Python: {sys.version.split()[0]}")
    print(f"✓ AWS Region: {os.getenv('AWS_DEFAULT_REGION', 'us-west-2')}")
    
    # Check AWS credentials
    try:
        import boto3
        session = boto3.Session()
        credentials = session.get_credentials()
        if credentials:
            print("✓ AWS credentials found")
        else:
            print("✗ No AWS credentials found")
            return
    except Exception as e:
        print(f"✗ Could not check AWS credentials: {e}")
    
    # Run tests
    tests = [
        test_bedrock_direct,
        test_file_tools,
        test_manus_config,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} crashed: {e}")
            failed += 1
    
    # Summary
    print("\n" + "=" * 40)
    print(f"Tests passed: {passed}")
    print(f"Tests failed: {failed}")


if __name__ == "__main__":
    main()