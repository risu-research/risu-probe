"""Synthetic actual MCP stdio server wrapping ORIGINAL pinned robotcode formatter.

Tool content[] is generated only by MarkDownFormatter from original upstream
source; source scalar is separately declared for comparison. The server process
and response bytes are real MCP SDK stdio; robotcode itself is not an MCP server.
"""
from __future__ import annotations
import asyncio
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp import types
from robotcode.robot.utils.markdownformatter import MarkDownFormatter

sdk_server=Server('risu-robotcode-public-wrapper')

@sdk_server.list_tools()
async def list_tools()->list[types.Tool]:
    return [types.Tool(name=name,
        description='Synthetic pinned upstream formatter regression',
        inputSchema={'type':'object','properties':{},'additionalProperties':False},
        outputSchema={'type':'object','properties':{'value':{'type':'string'}},
                      'required':['value'],'additionalProperties':False})
        for name in ('literal_code','normal_code')]

@sdk_server.call_tool()
async def call_tool(name:str,arguments:dict)->types.CallToolResult:
    if name not in ('literal_code','normal_code'):
        return types.CallToolResult.model_validate({
            'isError':True,'content':[{'type':'text','text':'Unknown synthetic tool'}]})
    raw='#FF00FF' if name=='literal_code' else 'ordinary'
    # The original library's unmodified formatter is the *only* rendering
    # implementation. This wrapper does not insert, remove or escape any
    # characters within its output string.
    formatted=MarkDownFormatter().format('``'+raw+'``').strip()
    return types.CallToolResult.model_validate({
        'isError':False,
        'structuredContent':{'value':raw},
        'content':[{'type':'text','text':'Value: '+formatted}],
    })

async def serve()->None:
    async with stdio_server() as (read,write):
        await sdk_server.run(read,write,sdk_server.create_initialization_options())

if __name__=='__main__':
    asyncio.run(serve())
