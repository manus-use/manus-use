#!/usr/bin/env python3
"""Test script for ManusUse with AWS Bedrock."""

import os
import sys
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Set config file path
os.environ["MANUS_CONFIG_PATH"] = str(Path(__file__).parent / "config" / "config.bedrock.toml")


def test_config():
    """Test configuration loading."""
    print("=== Testing Configuration ===")
    try:
        from manus_use.config import Config
        
        config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
        print(f"✓ Provider: {config.llm.provider}")
        print(f"✓ Model: {config.llm.model}")
        print(f"✓ Region: {os.getenv('AWS_DEFAULT_REGION', 'us-west-2')}")
        
        # Test model creation
        model = config.get_model()
        print(f"✓ Model instance created: {type(model).__name__}")
        
        return True
    except Exception as e:
        print(f"✗ Configuration test failed: {e}")
        return False


def test_basic_tools():
    """Test basic tools without external dependencies."""
    print("\n=== Testing Basic Tools ===")
    try:
        from manus_use.tools import file_read, file_write, file_list
        import tempfile
        
        # Test file operations
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write
            test_file = Path(tmpdir) / "test.txt"
            result = file_write(str(test_file), "Hello, ManusUse!")
            print(f"✓ File write: {result}")
            
            # Read
            content = file_read(str(test_file))
            print(f"✓ File read: {content}")
            
            # List
            files = file_list(tmpdir)
            print(f"✓ File list: {files}")
            
        return True
    except Exception as e:
        print(f"✗ Tools test failed: {e}")
        return False


def test_simple_agent():
    """Test a simple agent without tools."""
    print("\n=== Testing Simple Agent ===")
    try:
        from manus_use.config import Config
        from strands import Agent
        
        # Load config
        config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
        model = config.get_model()
        
        # Create simple agent
        agent = Agent(
            model=model,
            tools=[],
            system_prompt="You are a helpful AI assistant. Keep responses brief."
        )
        
        # Test simple query
        response = agent("What is 2 + 2?")
        print(f"✓ Agent response: {response}")
        
        return True
    except Exception as e:
        print(f"✗ Simple agent test failed: {e}")
        print(f"  Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return False


def test_manus_agent():
    """Test ManusAgent with file tools."""
    print("\n=== Testing ManusAgent ===")
    try:
        from manus_use import ManusAgent
        from manus_use.config import Config
        from manus_use.tools import file_write, file_read
        import tempfile
        
        # Load config
        config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
        
        # Create agent with file tools only
        agent = ManusAgent(
            tools=[file_write, file_read],
            config=config,
            enable_sandbox=False  # Disable sandbox for testing
        )
        
        # Test with a simple task
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "greeting.txt"
            response = agent(f"Write 'Hello from Bedrock!' to the file {test_file}")
            print(f"✓ ManusAgent response: {response}")
            
            # Verify file was created
            if test_file.exists():
                content = test_file.read_text()
                print(f"✓ File content: {content}")
            
        return True
    except Exception as e:
        print(f"✗ ManusAgent test failed: {e}")
        print(f"  Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return False


def test_code_execution():
    """Test code execution without sandbox."""
    print("\n=== Testing Code Execution ===")
    try:
        from manus_use.tools.code_execute import code_execute_sync
        
        # Simple Python code
        code = """
print("Hello from Python!")
result = 2 + 3
print(f"2 + 3 = {result}")
"""
        
        result = code_execute_sync(code, language="python")
        print(f"✓ Exit code: {result['exit_code']}")
        print(f"✓ Output: {result['stdout'].strip()}")
        if result['stderr']:
            print(f"  Stderr: {result['stderr']}")
            
        return result['exit_code'] == 0
    except Exception as e:
        print(f"✗ Code execution test failed: {e}")
        return False


def main():
    """Run all tests."""
    print("ManusUse AWS Bedrock Test Suite")
    print("=" * 40)
    
    # Check AWS credentials
    print("\n=== Checking AWS Configuration ===")
    aws_region = os.getenv("AWS_DEFAULT_REGION", "us-west-2")
    print(f"✓ AWS Region: {aws_region}")
    
    # Check if credentials are configured
    try:
        import boto3
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        print(f"✓ AWS Account: {identity['Account']}")
        print(f"✓ AWS User/Role: {identity['Arn']}")
    except Exception as e:
        print(f"✗ AWS credentials not configured: {e}")
        print("  Please run 'aws configure' first")
        return
    
    # Run tests
    tests = [
        test_config,
        test_basic_tools,
        test_simple_agent,
        test_manus_agent,
        test_code_execution,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        if test():
            passed += 1
        else:
            failed += 1
    
    # Summary
    print("\n" + "=" * 40)
    print(f"Tests passed: {passed}")
    print(f"Tests failed: {failed}")
    
    if failed == 0:
        print("\n✅ All tests passed!")
    else:
        print(f"\n❌ {failed} tests failed")


if __name__ == "__main__":
    main()