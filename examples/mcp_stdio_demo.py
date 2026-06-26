"""Demo: connect to a local MCP server over stdio transport.

The server is launched as a subprocess via ``uv run``. Point ``server_cwd``
at a directory that contains a ``main.py`` exposing an MCP server.

Usage::

    python examples/mcp_stdio_demo.py /path/to/your/mcp-server
"""

import sys

from mcp.client.stdio import StdioServerParameters, stdio_client
from strands import Agent
from strands.tools.mcp.mcp_client import MCPClient

# Path to the MCP server directory (override via CLI arg or edit here)
server_cwd = sys.argv[1] if len(sys.argv) > 1 else "./mcp-server"

stdio_params = StdioServerParameters(
    command="uv",
    args=["run", "--with", "mcp", "mcp", "run", "main.py"],
    cwd=server_cwd,
)

with MCPClient(lambda: stdio_client(stdio_params)) as mcp_client:
    tools = mcp_client.list_tools_sync()
    print("Available tools:")
    for tool in tools:
        print(f"  - {tool.name}")

    agent = Agent(tools=tools)
    result = agent("List all available assets.")
    print(result)
