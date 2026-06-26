"""Demo: connect to an MCP server over SSE transport and list available tools.

This is a minimal client example showing how to connect, list tools, and
optionally dispatch concurrent tasks using a thread pool.

Usage::

    export MCP_SSE_URL=http://localhost:8000/sse
    python examples/mcp_sse_client_demo.py
"""

import os

from mcp.client.sse import sse_client
from strands.tools.mcp.mcp_client import MCPClient

sse_url = os.environ.get("MCP_SSE_URL", "")
if not sse_url:
    raise ValueError("Set MCP_SSE_URL to the SSE endpoint of your MCP server.")

sse_mcp_client = MCPClient(lambda: sse_client(sse_url))
sse_mcp_client.start()

tools = sse_mcp_client.list_tools_sync()
print("Available tools:")
for tool in tools:
    print(f"  - {tool.name}")

# Example: dispatch multiple CVE tasks concurrently
#
# import concurrent.futures
# from strands import Agent
#
# cves = ["CVE-2025-50738", "CVE-2025-31650", "CVE-2025-21480", "CVE-2025-32724"]
#
# def process_cve(cve):
#     agent = Agent(tools=tools)
#     return agent(f"Submit a match-asset task for {cve}.")
#
# with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
#     futures = [executor.submit(process_cve, cve) for cve in cves]
#     for future in concurrent.futures.as_completed(futures):
#         print(future.result())
