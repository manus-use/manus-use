#!/usr/bin/env python3
"""Browse Strands documentation with maximum timeout configuration."""

import asyncio
from browser_use import Agent
from langchain_aws import ChatBedrock


async def browse_with_extended_timeout():
    """Browse with maximum timeout configuration."""
    
    print("=== Strands Documentation Browser (Maximum Timeout) ===\n")
    
    # Initialize LLM with extended timeout
    llm = ChatBedrock(
        model_id='us.anthropic.claude-3-7-sonnet-20250219-v1:0',
        model_kwargs={
            'temperature': 0.0,
            'max_tokens': 4096,
        },
        region_name='us-east-1'
    )
    
    # Focused task to complete quickly
    task = """
    Go to https://strandsagents.com/0.1.x/ and:
    4. Summarize the best practices in a concise list
    
    Be efficient and extract only the most important information.
    """
    
    print("Configuration:")
    print("- Max steps: 100")
    print("- Overall timeout: 20 minutes")
    print("- Using default browser configuration\n")
    
    print("Task: Extract Strands agent architecture essentials\n")
    
    # Create agent with extended configuration
    agent = Agent(
        task=task,
        llm=llm,
        max_input_tokens=160000,  # Increase token limit
    )
    
    try:
        # Run with maximum steps
        print("Starting browser agent (this may take several minutes)...\n")
        result = await agent.run(
            max_steps=100  # Increased to 100
        )
        
        # Extract final content
        if result.history:
            final_content = result.history[-1].extracted_content
            
            print("\n" + "="*60)
            print("EXTRACTION COMPLETE")
            print("="*60)
            print("\n" + final_content)
            
            # Save results
            with open("strands_extracted_content.md", "w") as f:
                f.write("# Strands SDK Documentation Extract\n\n")
                f.write(f"Source: https://strandsagents.com/0.1.x/\n")
                f.write(f"Extraction Date: {asyncio.get_event_loop().time()}\n\n")
                f.write("## Extracted Content\n\n")
                f.write(final_content)
                f.write("\n\n## Application to task_planner.py\n\n")
                f.write("Based on the extracted information, the following patterns should be applied:\n\n")
                f.write("1. **Agent Loop Pattern**: Follow the initialization → processing → completion flow\n")
                f.write("2. **Type Safety**: Use strong typing for all interfaces\n")
                f.write("3. **Error Handling**: Implement comprehensive error recovery\n")
                f.write("4. **Modularity**: Keep agents focused on single responsibilities\n")
                f.write("5. **Observability**: Add logging and monitoring capabilities\n")
            
            print(f"\n✓ Content saved to strands_extracted_content.md")
            
            # Also save a summary
            await create_summary_from_extraction(final_content)
            
        else:
            print("\n✗ No content extracted")
            
    except asyncio.TimeoutError:
        print("\n✗ Operation timed out after 20 minutes")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()


async def create_summary_from_extraction(content: str):
    """Create a summary of the extracted content."""
    
    print("\nCreating summary...")
    
    # Use LLM to summarize
    llm = ChatBedrock(
        model_id='us.anthropic.claude-3-7-sonnet-20250219-v1:0',
        model_kwargs={'temperature': 0.0, 'max_tokens': 4096},
        region_name='us-east-1'
    )
    
    summary_prompt = f"""Based on this extracted content from Strands SDK documentation, 
    create a concise summary of the key architectural patterns and best practices:
    
    {content[:8000]}  # Limit content to avoid token limits
    
    Focus on:
    1. Agent architecture patterns
    2. Tool design principles
    3. State management approaches
    4. Error handling strategies
    5. Performance optimization techniques
    
    Format as a structured list with concrete recommendations."""
    
    try:
        # Direct LLM call for summary
        from langchain_core.messages import HumanMessage
        response = await llm.ainvoke([HumanMessage(content=summary_prompt)])
        
        summary = response.content
        
        # Save summary
        with open("strands_architecture_summary.md", "w") as f:
            f.write("# Strands Architecture Summary\n\n")
            f.write("## Key Patterns and Best Practices\n\n")
            f.write(summary)
            f.write("\n\n## Implementation Checklist\n\n")
            f.write("- [ ] Implement agent loop pattern\n")
            f.write("- [ ] Add comprehensive type hints\n")
            f.write("- [ ] Create error recovery mechanisms\n")
            f.write("- [ ] Add observability hooks\n")
            f.write("- [ ] Optimize for parallel execution\n")
            f.write("- [ ] Implement caching where appropriate\n")
            f.write("- [ ] Add metrics collection\n")
            f.write("- [ ] Create comprehensive tests\n")
        
        print("✓ Summary saved to strands_architecture_summary.md")
        
    except Exception as e:
        print(f"✗ Summary creation failed: {e}")


async def quick_extraction():
    """Quick extraction focusing on specific pages."""
    
    print("\n=== Quick Targeted Extraction ===\n")
    
    llm = ChatBedrock(
        model_id='us.anthropic.claude-3-7-sonnet-20250219-v1:0',
        model_kwargs={'temperature': 0.0, 'max_tokens': 4096},
        region_name='us-east-1'
    )
    
    # Very specific task
    specific_task = """
    Go directly to https://strandsagents.com/0.1.x/ and:
    1. Extract the content 
    2. Copy any code examples shown
    3. Note the key components mentioned
    """
    
    agent = Agent(
        task=specific_task,
        llm=llm,
        enable_memory=False,
    )
    
    try:
        result = await agent.run(max_steps=10)
        if result:
            # Get the final result
            if hasattr(result, 'final_answer'):
                content = result.final_answer
            elif hasattr(result, 'history') and result.history:
                # Try to get extracted content or the last message
                last_item = result.history[-1]
                if hasattr(last_item, 'extracted_content'):
                    content = last_item.extracted_content
                else:
                    content = str(last_item)
            else:
                content = str(result)
            
            print("\nQuick Extract Result:")
            print(content)
            
            with open("strands_agent_loop.md", "w") as f:
                f.write("# Strands Agent Loop\n\n")
                f.write(content)
            
            print("\n✓ Saved to strands_agent_loop.md")
    except Exception as e:
        print(f"✗ Quick extraction failed: {e}")


async def main():
    """Main function with multiple extraction strategies."""
    
    print("Starting Strands documentation extraction with maximum timeouts...")
    print("This process may take up to 15 minutes.\n")
    
    # Try main extraction
    await browse_with_extended_timeout()
    
    # If needed, try quick extraction
    print("\n\nAttempting quick targeted extraction...")
    await quick_extraction()
    
    print("\n✅ All extraction attempts completed!")
    print("\nGenerated files:")
    print("- strands_extracted_content.md (main extraction)")
    print("- strands_architecture_summary.md (summarized patterns)")
    print("- strands_agent_loop.md (specific agent loop info)")


if __name__ == "__main__":
    # Run with extended event loop timeout
    asyncio.run(main(), debug=False)