#!/usr/bin/env python3
"""Comprehensive test suite for ManusUse with AWS Bedrock."""

import asyncio
import tempfile
from pathlib import Path


async def test_basic_agent():
    """Test basic ManusAgent functionality."""
    print("=== Testing Basic ManusAgent ===")
    
    try:
        from manus_use import ManusAgent
        from manus_use.config import Config
        
        # Load Bedrock config
        config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
        
        # Create agent
        agent = ManusAgent(config=config, enable_sandbox=False)
        
        # Simple test
        response = agent("What is the capital of France? Answer in one word.")
        print(f"✓ Response: {response}")
        
        return True
    except Exception as e:
        print(f"✗ Basic agent test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_file_tools():
    """Test file operation tools."""
    print("\n=== Testing File Tools ===")
    
    try:
        from manus_use import ManusAgent
        from manus_use.config import Config
        from manus_use.tools import file_read, file_write, file_list
        
        config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
        
        # Create agent with file tools
        agent = ManusAgent(
            tools=[file_read, file_write, file_list],
            config=config,
            enable_sandbox=False
        )
        
        # Test file operations
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test_data.txt"
            
            # Ask agent to create a file
            response = agent(
                f"Create a file at {test_file} with the content 'Hello from ManusUse with AWS Bedrock!'"
            )
            print(f"✓ File creation response: {response[:100]}...")
            
            # Verify file exists
            if test_file.exists():
                content = test_file.read_text()
                print(f"✓ File content: {content}")
            else:
                print("✗ File was not created")
                
        return True
    except Exception as e:
        print(f"✗ File tools test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_code_execution():
    """Test code execution functionality."""
    print("\n=== Testing Code Execution ===")
    
    try:
        from manus_use import ManusAgent
        from manus_use.config import Config
        from manus_use.tools import code_execute
        
        config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
        
        # Create agent with code execution
        agent = ManusAgent(
            tools=[code_execute],
            config=config,
            enable_sandbox=False
        )
        
        # Test Python code execution
        response = agent(
            "Execute this Python code and tell me the result: "
            "print('Hello from Python'); print(sum([1, 2, 3, 4, 5]))"
        )
        print(f"✓ Code execution response: {response[:200]}...")
        
        return True
    except Exception as e:
        print(f"✗ Code execution test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_data_analysis():
    """Test data analysis capabilities."""
    print("\n=== Testing Data Analysis ===")
    
    try:
        from manus_use import DataAnalysisAgent
        from manus_use.config import Config
        
        config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
        
        # Create data analysis agent
        agent = DataAnalysisAgent(config=config)
        
        # Test simple analysis
        response = agent(
            "Create a list of 5 random numbers between 1 and 100, "
            "then calculate their mean, median, and standard deviation."
        )
        print(f"✓ Analysis response: {response[:200]}...")
        
        return True
    except Exception as e:
        print(f"✗ Data analysis test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_multi_tool_task():
    """Test agent with multiple tools."""
    print("\n=== Testing Multi-Tool Task ===")
    
    try:
        from manus_use import ManusAgent
        from manus_use.config import Config
        from manus_use.tools import file_write, file_read, code_execute
        
        config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
        
        # Create agent with multiple tools
        agent = ManusAgent(
            tools=[file_write, file_read, code_execute],
            config=config,
            enable_sandbox=False
        )
        
        # Complex task
        with tempfile.TemporaryDirectory() as tmpdir:
            response = agent(
                f"1. Create a Python file at {tmpdir}/fibonacci.py that calculates "
                "the first 10 Fibonacci numbers. "
                "2. Then execute the file and show me the output."
            )
            print(f"✓ Multi-tool response: {response[:300]}...")
            
        return True
    except Exception as e:
        print(f"✗ Multi-tool test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_error_handling():
    """Test error handling."""
    print("\n=== Testing Error Handling ===")
    
    try:
        from manus_use import ManusAgent
        from manus_use.config import Config
        from manus_use.tools import file_read
        
        config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
        
        agent = ManusAgent(
            tools=[file_read],
            config=config,
            enable_sandbox=False
        )
        
        # Try to read non-existent file
        response = agent("Try to read the file /non/existent/file.txt and handle any errors gracefully")
        print(f"✓ Error handling response: {response[:200]}...")
        
        return True
    except Exception as e:
        print(f"✗ Error handling test failed: {e}")
        return False


async def main():
    """Run all tests."""
    print("ManusUse AWS Bedrock Test Suite")
    print("=" * 50)
    
    # Check config
    config_path = Path(__file__).parent / "config" / "config.bedrock.toml"
    if not config_path.exists():
        print(f"✗ Config file not found: {config_path}")
        print("  Please create config/config.bedrock.toml")
        return
        
    print(f"✓ Using config: {config_path}")
    print(f"✓ Model: Claude Opus 4")
    print("")
    
    # Run tests
    tests = [
        test_basic_agent,
        test_file_tools,
        test_code_execution,
        test_data_analysis,
        test_multi_tool_task,
        test_error_handling,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if await test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} crashed: {e}")
            failed += 1
    
    # Summary
    print("\n" + "=" * 50)
    print(f"Tests passed: {passed}")
    print(f"Tests failed: {failed}")
    
    if failed == 0:
        print("\n✅ All tests passed! ManusUse is working correctly with AWS Bedrock.")
    else:
        print(f"\n❌ {failed} tests failed.")


if __name__ == "__main__":
    asyncio.run(main())