#!/usr/bin/env python3
"""Simplified browser automation for Strands documentation."""

import asyncio
from browser_use import Agent
from langchain_aws import ChatBedrock


async def browse_strands_docs():
    """Browse Strands documentation with simplified configuration."""
    
    print("=== Strands Documentation Browser (Simplified) ===\n")
    
    # Initialize LLM
    llm = ChatBedrock(
        model_id='us.anthropic.claude-3-7-sonnet-20250219-v1:0',
        model_kwargs={
            'temperature': 0.0,
            'max_tokens': 4096,
        },
        region_name='us-east-1'
    )
    
    # Simple, focused task
    task = """
    Navigate to https://strandsagents.com/0.1.x/user-guide/concepts/agent-loop/ and extract:
    1. The main steps of the agent loop
    2. Any code examples showing the agent loop implementation
    3. Key concepts mentioned
    
    Be concise and extract only the essential information.
    """
    
    print("Task: Extract agent loop documentation")
    print("Target: https://strandsagents.com/0.1.x/user-guide/concepts/agent-loop/\n")
    
    # Create agent with minimal configuration
    agent = Agent(
        task=task,
        llm=llm,
    )
    
    try:
        print("Starting browser agent...\n")
        result = await agent.run(max_steps=20)
        
        if result and hasattr(result, 'history') and result.history:
            # Get the final extracted content
            final_content = result.history[-1].extracted_content if hasattr(result.history[-1], 'extracted_content') else str(result.history[-1])
            
            print("\n" + "="*60)
            print("EXTRACTED CONTENT")
            print("="*60)
            print(final_content)
            
            # Save the extracted content
            with open("strands_agent_loop_extract.md", "w") as f:
                f.write("# Strands Agent Loop Documentation\n\n")
                f.write("Source: https://strandsagents.com/0.1.x/user-guide/concepts/agent-loop/\n\n")
                f.write("## Extracted Content\n\n")
                f.write(final_content)
            
            print(f"\n✓ Content saved to strands_agent_loop_extract.md")
            
        else:
            print("\n✗ No content extracted")
            
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()


async def main():
    """Run the documentation extraction."""
    print("Starting Strands documentation extraction...")
    print("Using simplified browser automation approach\n")
    
    await browse_strands_docs()
    
    print("\n✅ Extraction complete!")


if __name__ == "__main__":
    asyncio.run(main())