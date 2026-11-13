"""B36 controlled native MCP stdio source: first-party synthetic witness only.

This fixture uses the REAL pinned MCP Python SDK server and sends no external
network traffic. It is not an execution of third-party B34/B35/B36 source.
"""
from __future__ import annotations

from mcp.server import MCPServer
from mcp_types import CallToolResult, ImageContent, TextContent

PNG_1PX = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
mcp = MCPServer("RISU-B36-controlled-no-external-data")


@mcp.tool()
def rich_result() -> CallToolResult:
    """A real MCP result carries multiple content types and structured data."""
    return CallToolResult(
        content=[
            TextContent(type="text", text="first message"),
            ImageContent(type="image", data=PNG_1PX, mime_type="image/png"),
            TextContent(type="text", text="second message"),
        ],
        structured_content={"item_id": "B36-CONTROL", "quantity": 17},
        is_error=False,
    )


@mcp.tool()
def plain_result() -> CallToolResult:
    """A valid normal control: one text block, no structured metadata."""
    return CallToolResult(
        content=[TextContent(type="text", text="safe singleton")],
        is_error=False,
    )


@mcp.tool()
def error_result() -> CallToolResult:
    """An error is sent as an MCP tool result with its reason, not an exception."""
    return CallToolResult(
        content=[TextContent(type="text", text="VALIDATION_FAILED: missing document")],
        is_error=True,
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")
