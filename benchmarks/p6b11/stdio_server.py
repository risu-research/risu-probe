"""Synthetic-only real MCP SDK server, executed as a real stdio subprocess.

Pinned MCP Python SDK v1.28.0, no network, no credentials. The tool's actual
JSON-RPC frames are captured byte-for-byte by the independent tee proxy.
"""
from __future__ import annotations

import asyncio
import json
import re

import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

server = Server("RISU-B11-wire-real-server", version="0.0.1-test")

INPUT = {"type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":False}
OUTPUT = {"type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":False}
NAMES = ("render_markdown", "render_copy", "render_special", "render_bad", "render_missing")


def code_span(value: str) -> str:
    runs = [len(m.group(0)) for m in re.finditer(r"`+", value)]
    fence = "`" * (max([0, *runs]) + 1)
    padding = " " if (value.startswith("`") or value.endswith("`")) else ""
    return fence + padding + value + padding + fence


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [types.Tool(name=name, description="Synthetic local integrity test",
                       inputSchema=INPUT, outputSchema=OUTPUT) for name in NAMES]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name not in NAMES:
        raise ValueError("Tool not found")
    value = arguments["value"]
    if not isinstance(value, str) or len(value) > 1024:
        raise ValueError("Synthetic input must be bounded string")
    if name == "render_special":
        rendered = code_span(json.dumps(value, ensure_ascii=False))
    elif name == "render_bad":
        rendered = value  # Deliberately incorrect Markdown, not an upstream defect
    elif name == "render_missing":
        rendered = None
    else:
        rendered = code_span(value)
    content = ("**value:** " + rendered) if rendered is not None else "No declared value line here."
    # Actual upstream SDK constructs and emits the JSON-RPC CallToolResult.
    return ([types.TextContent(type="text", text=content)], {"value": value})


async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream,
            InitializationOptions(
                server_name="RISU-B11-wire-real-server",
                server_version="0.0.1-test",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(), experimental_capabilities={}
                )
            )
        )


if __name__ == "__main__":
    asyncio.run(main())
