from strands import Agent
from strands.tools.mcp.mcp_client import MCPClient
from mcp.client.stdio import StdioServerParameters, stdio_client
from pydantic import BaseModel, Field
class AssetMatch(BaseModel):
    result: str = Field(description="Result data, or error messages from the tasks.")
    precisely_matched_assets: int = Field(description="The number of Assets Precisely Matched")
    fuzzy_matched_asset: int = Field(description="The number of Assets Fuzzy Matched (Name + Version)")


stdio_params = StdioServerParameters(
    command="uv", 
    args =["run", "--with", "mcp", "mcp", "run", "main.py"], # run --with mcp mcp run main.py
    cwd="/Users/x/Develop/manus/mcp-server-demo"
)

# Create the MCP client that wraps the stdio client
mcp_client = MCPClient(lambda: stdio_client(stdio_params))

with mcp_client:
    # List available tools from MCP server (sync call)
    tools = mcp_client.list_tools_sync()

    # Instantiate strands Agent with the MCP tools
    agent = Agent(tools=tools)

    # Now you can call tools by name
    result = agent("")
    esult = agent.structured_output(AssetMatch,
                                     "ased on our conversation, provide an asset match"
                                     )
    print(result)
