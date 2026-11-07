"""PUBLIC synthetic MCP stdio fixture: no network, files, credentials or external tools."""
from __future__ import annotations
from mcp.server.mcpserver import MCPServer

app=MCPServer('risu-p6b4-stdio-only')

@app.tool()
def get_count() -> dict[str,int]:
    """Return a harmless fixture count."""
    return {'value':3}

@app.tool()
def get_total() -> dict[str,int]:
    """Return another harmless fixture count."""
    return {'value':17}

if __name__=='__main__':
    app.run('stdio')
