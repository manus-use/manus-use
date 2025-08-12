import os
from mcp.client.sse import sse_client
from strands import Agent
from strands.tools.mcp import MCPClient
from src.manus_use.config import Config

# Get the SSE URL from the config file
config = Config.from_file()
sse_url = getattr(getattr(config, 'mcp', None), 'server_url', None)
if not sse_url and not os.environ.get("MCP_SSE_URL"):
    # Get the SSE URL from the environment variable
    raise ValueError("MCP SSE server URL not set in config. Please set [mcp] server_url in your config.toml.")
if not sse_url:
    sse_url = os.environ.get("MCP_SSE_URL")
# Connect to an MCP server using SSE transport
sse_mcp_client = MCPClient(lambda: sse_client(sse_url))

# Create an agent with MCP tools
sse_mcp_client.start()
# Get the tools from the MCP server
tools = sse_mcp_client.list_tools_sync()

# Create an agent with these tools
agent = Agent(tools=tools)
agent("print (100*100)")