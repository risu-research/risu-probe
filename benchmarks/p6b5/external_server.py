"""Public synthetic FastMCP server for independent real stdio interop tests.

No network, user code, files, customer data, or environment secrets.
"""
from fastmcp import FastMCP

app = FastMCP('risu-external-interoperability')

@app.tool
async def get_count() -> dict[str, int]:
    """Harmless integer record."""
    return {'value': 7}

@app.tool
async def get_label() -> dict[str, str]:
    """Harmless string record."""
    return {'label': 'ready'}

@app.tool
async def get_error() -> dict[str, int]:
    """Deliberate public fixture failure; a normal MCP tool error."""
    raise ValueError('PUBLIC_SYNTHETIC_EXPECTED_ERROR')

if __name__ == '__main__':
    app.run(transport='stdio')
