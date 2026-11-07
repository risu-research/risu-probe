"""Public synthetic MCP Python SDK v1 FastMCP server: separate implementation lineage."""
from mcp.server.fastmcp import FastMCP

app=FastMCP('risu-official-sdk-v1-interoperability')

@app.tool()
async def get_count() -> dict[str,int]:
    return {'value':7}

@app.tool()
async def get_label() -> dict[str,str]:
    return {'label':'ready'}

@app.tool()
async def get_error() -> dict[str,int]:
    raise ValueError('PUBLIC_SYNTHETIC_EXPECTED_ERROR')

if __name__=='__main__':
    app.run(transport='stdio')
