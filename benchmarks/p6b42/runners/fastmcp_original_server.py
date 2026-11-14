#!/usr/bin/env python3
"""B42 evaluator-only MCP server, using original installed FastMCP server code.

All tools are synthetic, no filesystem/network access or credentials.
"""
from fastmcp import FastMCP

server = FastMCP("B42-original-FastMCP-controlled-server")

@server.tool
def b42_success() -> str:
    """B42 benign success contract."""
    return "b42 original fastmcp hello"

@server.tool
def b42_denied() -> str:
    """B42 deterministic tool execution failure, not JSONRPC transport error."""
    raise ValueError("B42 synthetic access denied")

if __name__ == "__main__":
    server.run(transport="stdio")
