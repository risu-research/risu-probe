// B43 EVALUATOR-OWNED synthetic no-effect MCP tool peer.
// Runs under official @modelcontextprotocol/sdk original in selected nanocoder tree.
// NO console.log: stdout is the actual MCP stdio JSON-RPC channel.
import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js';
import {ListToolsRequestSchema, CallToolRequestSchema} from '@modelcontextprotocol/sdk/types.js';
const server = new Server({name:'b43-original-native-peer',version:'1.0'}, {capabilities:{tools:{}}});
server.setRequestHandler(ListToolsRequestSchema, async () => ({
 tools:[
 {name:'b43_success',description:'synthetic no-side-effect normal',
  inputSchema:{type:'object',properties:{},additionalProperties:false}},
 {name:'b43_denied',description:'synthetic no-side-effect refused',
  inputSchema:{type:'object',properties:{},additionalProperties:false}},
 ],
}));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
 if(req.params.name==='b43_success')
  return {isError:false,content:[{type:'text',text:'B43 native benign success'}]};
 if(req.params.name==='b43_denied')
  return {isError:true,content:[{type:'text',text:'B43 native denied: no external effect'}]};
 throw new Error('Unknown synthetic B43 tool');
});
const transport = new StdioServerTransport();
await server.connect(transport);
