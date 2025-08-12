from strands import Agent
from strands.tools.mcp.mcp_client import MCPClient
from mcp.client.streamable_http import streamablehttp_client
from mcp.client.stdio import StdioServerParameters, stdio_client
from pydantic import BaseModel, Field
class AssetMatch(BaseModel):
    result: str = Field(description="Result data, or error messages from the tasks.")


stdio_params = StdioServerParameters(
    command="uv", 
    args =["run", "--with", "mcp", "mcp", "run", "main.py"], # run --with mcp mcp run main.py
    cwd="/Users/x/Develop/manus/mcp-server-demo"
)

# Create the MCP client that wraps the stdio client
# mcp_client = MCPClient(lambda: stdio_client(stdio_params))

sse_url = "http://localhost:3001/mcp"
sse_mcp_client = MCPClient(lambda: streamablehttp_client(sse_url))

# Create an agent with MCP tools
sse_mcp_client.start()
# List available tools from MCP server (sync call)
tools = sse_mcp_client.list_tools_sync()

# Instantiate strands Agent with the MCP tools

# Now you can call tools by name
import concurrent.futures

def process_asset(cve):
    agent = Agent(tools=tools)
    result = agent(
        f"please submit a match asset task for {cve}."
    )
    return result

urls = [
    "CVE-2025-50738",
    "CVE-2025-31650",
    "CVE-2025-21480",
    "CVE-2025-32724"
]

with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
    futures = [executor.submit(process_asset, url) for url in urls]
    for future in concurrent.futures.as_completed(futures):
        print(future.result())
