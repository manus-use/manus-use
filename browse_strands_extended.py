#!/usr/bin/env python3
"""Browse Strands documentation with extended timeout and specific extraction."""

import asyncio
from browser_use import Agent
from langchain_aws import ChatBedrock


async def browse_strands_comprehensive():
    """Browse Strands documentation comprehensively."""
    
    print("=== Browsing Strands Documentation (Extended) ===\n")
    
    # Initialize LLM
    llm = ChatBedrock(
        model_id='us.anthropic.claude-3-7-sonnet-20250219-v1:0',
        model_kwargs={'temperature': 0.0, 'max_tokens': 40960},
        region_name='us-east-1'
    )
    
    # More focused task with specific pages
    task = """
    Go to https://strandsagents.com/0.1.x/ and extract the following information:
    
    1. First, click on "Agents" in the navigation and read about:
       - Agent Loop structure
       - How agents process tasks
       - Best practices for agent design
    
    2. Then look for "Tools" section and understand:
       - How to create custom tools
       - Tool decorators and patterns
       - Tool execution flow
    
    3. Find any examples of multi-agent patterns or orchestration
    
    4. Extract key architectural patterns and design principles
    
    Focus on extracting concrete patterns and code examples that show best practices.
    """
    
    print("Task: Extract Strands agent architecture patterns")
    print("Timeout: 30 steps (extended)\n")
    
    # Create agent with extended steps
    agent = Agent(
        task=task,
        llm=llm,
        enable_memory=False,
    )
    
    # Run with more steps
    try:
        result = await agent.run(max_steps=30)  # Increased from default
        
        # Extract final content
        if result.history:
            final_content = result.history[-1].extracted_content
            
            print("\n=== Documentation Analysis ===")
            print(final_content)
            
            # Save comprehensive analysis
            with open("strands_architecture_analysis.md", "w") as f:
                f.write("# Strands SDK Architecture Analysis\n\n")
                f.write("Source: https://strandsagents.com/0.1.x/\n\n")
                f.write("## Key Findings\n\n")
                f.write(final_content)
                f.write("\n\n## Implementation Recommendations\n\n")
                f.write("Based on the analysis, here are recommendations for task_planner.py:\n\n")
                f.write("1. **Agent Loop Pattern**: Follow the standard initialization → processing → completion flow\n")
                f.write("2. **Tool Integration**: Use proper tool decorators and type hints\n")
                f.write("3. **State Management**: Implement conversation managers for context\n")
                f.write("4. **Error Handling**: Use structured error responses\n")
                f.write("5. **Async Support**: Consider async tool execution for better performance\n")
            
            print("\n✓ Analysis saved to strands_architecture_analysis.md")
            
            return final_content
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return None


async def browse_specific_sections():
    """Browse specific documentation sections one by one."""
    
    print("\n=== Targeted Section Browsing ===\n")
    
    llm = ChatBedrock(
        model_id='us.anthropic.claude-3-7-sonnet-20250219-v1:0',
        model_kwargs={'temperature': 0.0, 'max_tokens': 40960},
        region_name='us-east-1'
    )
    
    sections = [
        {
            "name": "Agent Architecture",
            "task": "Go to https://strandsagents.com/0.1.x/user-guide/concepts/agent-loop/ and extract the complete agent loop architecture, including initialization, processing, and completion phases."
        },
        {
            "name": "Tool Patterns",
            "task": "Go to https://strandsagents.com/0.1.x/user-guide/tools/overview/ and extract best practices for creating and using tools in Strands agents."
        },
        {
            "name": "Multi-Agent Patterns",
            "task": "Go to https://strandsagents.com/0.1.x/user-guide/concepts/multi-agent/ and look for patterns about coordinating multiple agents."
        }
    ]
    
    all_findings = []
    
    for section in sections:
        print(f"Browsing: {section['name']}...")
        
        agent = Agent(
            task=section["task"],
            llm=llm,
            enable_memory=False,
        )
        
        try:
            result = await agent.run(max_steps=15)
            if result.history:
                content = result.history[-1].extracted_content
                all_findings.append(f"## {section['name']}\n\n{content}")
                print(f"✓ Completed {section['name']}")
        except Exception as e:
            print(f"✗ Failed {section['name']}: {e}")
    
    # Combine all findings
    if all_findings:
        with open("strands_detailed_analysis.md", "w") as f:
            f.write("# Detailed Strands SDK Analysis\n\n")
            f.write("\n\n".join(all_findings))
        
        print("\n✓ Detailed analysis saved to strands_detailed_analysis.md")
    
    return all_findings


async def main():
    """Main function to run extended browsing."""
    
    print("Starting extended Strands documentation analysis...")
    print("This may take several minutes...\n")
    
    # Try comprehensive browse first
    comprehensive_result = await browse_strands_comprehensive()
    
    # If that times out or fails, try targeted browsing
    if not comprehensive_result:
        print("\nTrying targeted section browsing...")
        await browse_specific_sections()
    
    print("\n✅ Documentation analysis completed!")
    print("\nNext steps:")
    print("1. Review the generated analysis files")
    print("2. Apply patterns to task_planner.py")
    print("3. Test the refined implementation")


if __name__ == "__main__":
    # Run with extended timeout
    asyncio.run(main())