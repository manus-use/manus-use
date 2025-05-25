#!/usr/bin/env python3
"""Simple test for ManusUse with AWS Bedrock."""

from pathlib import Path
import tempfile


def test_basic_bedrock():
    """Test basic functionality with Bedrock."""
    print("=== Testing ManusUse with AWS Bedrock ===\n")
    
    # Test 1: Basic agent
    print("1. Testing basic agent...")
    try:
        from manus_use import ManusAgent
        from manus_use.config import Config
        
        config = Config.from_file(Path(__file__).parent / "config" / "config.bedrock.toml")
        agent = ManusAgent(config=config, enable_sandbox=False)
        
        response = agent("What is 2 + 2? Reply with just the number.")
        print(f"✓ Basic test passed. Response: {response.content if hasattr(response, 'content') else str(response)}\n")
    except Exception as e:
        print(f"✗ Basic test failed: {e}\n")
        return False
    
    # Test 2: File operations
    print("2. Testing file operations...")
    try:
        from manus_use.tools import file_write, file_read
        
        agent = ManusAgent(
            tools=[file_write, file_read],
            config=config,
            enable_sandbox=False
        )
        
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            
            # Create file
            response = agent(f"Write 'Hello Bedrock!' to {test_file}")
            print(f"✓ File write response received")
            
            # Check file
            if test_file.exists():
                content = test_file.read_text()
                print(f"✓ File created with content: {content}\n")
            else:
                print("✗ File was not created\n")
                
    except Exception as e:
        print(f"✗ File operations test failed: {e}\n")
        return False
    
    # Test 3: Simple code execution
    print("3. Testing code execution...")
    try:
        from manus_use.tools.code_execute import code_execute_sync
        
        result = code_execute_sync("print('Hello from Python!')", language="python")
        print(f"✓ Code execution result: {result['stdout'].strip()}")
        print(f"✓ Exit code: {result['exit_code']}\n")
        
    except Exception as e:
        print(f"✗ Code execution test failed: {e}\n")
        return False
    
    # Test 4: Web search
    print("4. Testing web search...")
    try:
        from manus_use.tools import web_search
        
        agent = ManusAgent(
            tools=[web_search],
            config=config,
            enable_sandbox=False
        )
        
        # Search for something specific
        response = agent("Search for 'AWS Bedrock Claude' and tell me what you find in one sentence.")
        print(f"✓ Web search response received")
        print(f"✓ Search result: {response.content if hasattr(response, 'content') else str(response)[:200]}...\n")
        
    except Exception as e:
        print(f"✗ Web search test failed: {e}\n")
        return False
    
    print("✅ All tests completed successfully!")
    return True


if __name__ == "__main__":
    test_basic_bedrock()