#!/usr/bin/env python3
"""Browse Strands documentation to understand best practices."""

import asyncio
from browser_use import Agent
from langchain_aws import ChatBedrock


async def browse_strands_docs():
    """Browse Strands documentation for best practices."""
    
    print("=== Browsing Strands Documentation ===\n")
    
    # Initialize LLM
    llm = ChatBedrock(
        model_id='us.anthropic.claude-3-7-sonnet-20250219-v1:0',
        model_kwargs={'temperature': 0.0, 'max_tokens': 4096},
        region_name='us-east-1'
    )
    
    # Task to browse documentation
    task = """
    Go to https://strandsagents.com/0.1.x/ and:
    1. Look for documentation about creating custom agents
    2. Find information about best practices for agent architecture
    3. Look for examples of task planning or orchestration
    4. Extract key patterns and recommendations for agent design
    """
    
    print("Browsing Strands documentation...")
    print("Task: Finding best practices for agent architecture\n")
    
    # Create agent
    agent = Agent(
        task=task,
        llm=llm,
        enable_memory=False,
    )
    
    # Run the agent
    try:
        result = await agent.run(max_steps=20)
        
        # Extract the final content
        final_content = result.history[-1].extracted_content if result.history else "No content extracted"
        
        print("\n=== Documentation Insights ===")
        print(final_content)
        
        # Save the insights
        with open("strands_best_practices.md", "w") as f:
            f.write("# Strands Agent Best Practices\n\n")
            f.write("Extracted from https://strandsagents.com/0.1.x/\n\n")
            f.write(final_content)
        
        print("\n✓ Saved insights to strands_best_practices.md")
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n✅ Documentation review completed!")


if __name__ == "__main__":
    asyncio.run(browse_strands_docs())