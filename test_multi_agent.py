#!/usr/bin/env python3
"""Test multi-agent functionality."""

from manus_use.config import Config
from manus_use.multi_agents import FlowOrchestrator

def test_multi_agent_execution():
    print("Testing multi-agent execution...")
    
    # Load configuration
    config = Config.from_file()
    print(f"✓ Configuration loaded (provider: {config.llm.provider})")
    
    # Create orchestrator
    orchestrator = FlowOrchestrator(config=config)
    print("✓ FlowOrchestrator created")
    
    # Test simple request
    request = "What is the capital of France?"
    print(f"\nExecuting request: {request}")
    
    result = orchestrator.run(request)
    
    if result.success:
        print(f"✓ Success: {result.output}")
    else:
        print(f"✗ Failed: {result.error}")
    
    # Test complex request that should use multiple agents
    complex_request = "Research the top 3 programming languages in 2024 and create a summary"
    print(f"\nExecuting complex request: {complex_request}")
    
    result = orchestrator.run(complex_request)
    
    if result.success:
        print(f"✓ Success: {result.output[:200]}...")  # Show first 200 chars
    else:
        print(f"✗ Failed: {result.error}")
    
    print("\nTest completed!")

if __name__ == "__main__":
    test_multi_agent_execution()