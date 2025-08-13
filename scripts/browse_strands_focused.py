#!/usr/bin/env python3
"""Browse Strands documentation with focused extraction."""

import asyncio
from browser_use import Agent
from langchain_aws import ChatBedrock


async def browse_strands_agents():
    """Browse Strands documentation focusing on agents section."""
    
    print("=== Browsing Strands Agents Documentation ===\n")
    
    # Initialize LLM
    llm = ChatBedrock(
        model_id='us.anthropic.claude-3-7-sonnet-20250219-v1:0',
        model_kwargs={'temperature': 0.0, 'max_tokens': 4096},
        region_name='us-east-1'
    )
    
    # Focused task
    task = """
    Go to https://strandsagents.com/0.1.x/ and:
    1. Click on "Agents" in the navigation
    2. Look at the "Agent Loop" section
    3. Extract the key concepts about how agents work
    4. Take a screenshot of the agent architecture diagram if available
    5. Summarize the best practices for creating agents
    """
    
    print("Task: Extract agent architecture best practices\n")
    
    # Create agent
    agent = Agent(
        task=task,
        llm=llm,
        enable_memory=False,
    )
    
    # Run the agent
    try:
        result = await agent.run(max_steps=10)
        
        # Extract insights
        final_content = result.history[-1].extracted_content if result.history else "No content"
        
        print("\n=== Key Insights ===")
        print(final_content)
        
        return final_content
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        return None


async def main():
    """Main function to browse and analyze."""
    
    # Browse documentation
    insights = await browse_strands_agents()
    
    if insights:
        # Save insights
        with open("strands_agent_insights.md", "w") as f:
            f.write("# Strands Agent Architecture Insights\n\n")
            f.write("Based on https://strandsagents.com/0.1.x/\n\n")
            f.write("## Key Concepts\n\n")
            f.write(insights)
            f.write("\n\n## Recommendations for task_planner.py\n\n")
            f.write("1. Follow the Agent Loop pattern\n")
            f.write("2. Use proper initialization with tools and model\n")
            f.write("3. Implement clear system prompts\n")
            f.write("4. Handle tool execution properly\n")
            f.write("5. Manage conversation state effectively\n")
        
        print("\n✓ Saved to strands_agent_insights.md")
    
    print("\n✅ Analysis completed!")


if __name__ == "__main__":
    asyncio.run(main())