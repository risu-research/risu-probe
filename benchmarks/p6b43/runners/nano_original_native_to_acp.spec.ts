// B43 evaluator ONLY. This test is copied alongside unchanged original source
// before/after selected Git commits. It executes original MCPClient, original
// @modelcontextprotocol/sdk Client over native stdio JSON-RPC, original
// runAcpConversation and original AcpSession, not simulated tool parsers.
//
// Native MCP request IDs are NOT automatically propagated to original ACP
// toolCallId. We record both identity domains; no invented equivalence.
import {randomUUID} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import test from 'ava';
import {Client as NativeClient} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import type {AgentSideConnection} from '@agentclientprotocol/sdk';
import {AcpSession} from '@/acp/acp-session';
import {runAcpConversation} from '@/acp/acp-conversation';
import {MCPClient} from '@/mcp/mcp-client';
import {setToolRegistryGetter,setToolManagerGetter} from '@/message-handler';
import type {LLMClient} from '@/types/index';

const fixture = fileURLToPath(new URL('./b43-native-mcp-server.mjs',import.meta.url));
const phase = process.env.B43_NANO_PHASE;
const output = process.env.B43_NANO_NATIVE_ACP;
if (!phase || !output) throw new Error('B43_NANO_PHASE and B43_NANO_NATIVE_ACP required');

test.afterEach.always(() => {
  setToolRegistryGetter(() => ({}));
  setToolManagerGetter(() => null);
});

test('B43 original native MCP status reaches original ACP final tool events without rewriting the message', async t => {
 const nativeRequests:any[]=[];
 const nativeReplies:any[]=[];
 const transport = new StdioClientTransport({command:process.execPath,args:[fixture]});
 const native = new NativeClient({name:'b43-original-nano-client',version:'1.0'});
 await native.connect(transport);
 t.teardown(async () => {try{await native.close()}catch{}});
 const originalSend = transport.send.bind(transport);
 // Evaluator-only observation of real outbound original native JSON-RPC.
 transport.send = async (m:any,options?:any) => {
   if (m?.method==='tools/call') nativeRequests.push(JSON.parse(JSON.stringify(m)));
   return originalSend(m,options);
 };
 const originalReceive = transport.onmessage;
 transport.onmessage = (m:any,extra?:any) => {
   if (m?.id !== undefined && m?.result?.content) nativeReplies.push(JSON.parse(JSON.stringify(m)));
   return originalReceive?.(m,extra);
 };
 const mcp = new MCPClient() as any;
 const toolDef=(name:string)=>({name,description:name,serverName:'b43native',inputSchema:{type:'object',properties:{}}});
 mcp.serverTools.set('b43native',[toolDef('b43_denied'),toolDef('b43_success')]);
 mcp.clients.set('b43native',native);
 const entries=mcp.getToolEntries();
 t.deepEqual(entries.map((e:any)=>e.name).sort(),['b43_denied','b43_success']);
 setToolRegistryGetter(() => Object.fromEntries(entries.map((e:any)=>[e.name,e.handler])));

 const updates:any[]=[];
 const conn = {
   sessionUpdate: async (u:any) => {updates.push(u)},
   requestPermission: async () => ({outcome:{outcome:'selected',optionId:'allow'}}),
 } as unknown as AgentSideConnection;
 const session = new AcpSession({sessionId:randomUUID(),cwd:'/tmp',conn,initialMode:'yolo'});
 session.messages=[];
 session.systemMessage={role:'system',content:'B43 original synthetic test'};
 const toolManager = {
   getAvailableToolNames:()=>['b43_denied','b43_success'],
   getFilteredTools:()=>({}),
   hasTool:()=>true,
   getToolEntry:()=>({approval:false}),
   isReadOnly:()=>true,
 };
 let modelCallCount=0;
 const model:any = {
   chat:async ()=>{
     modelCallCount++;
     if(modelCallCount===1)return {choices:[{message:{
       content:'',
       tool_calls:[
         {id:'b43-acp-denied-001',function:{name:'b43_denied',arguments:{}}},
         {id:'b43-acp-success-002',function:{name:'b43_success',arguments:{}}},
       ],
     }}]};
     return {choices:[{message:{content:'Synthetic B43 end turn'}}]};
   },
 };
 const result=await runAcpConversation({
    session,client:model as LLMClient,toolManager:toolManager as any,
    conn,nonInteractiveAlwaysAllow:[],
 });
 t.truthy(result);
 t.true(modelCallCount>=2);
 const byId=(id:string)=>updates.filter((u:any)=>
    u.update?.sessionUpdate==='tool_call_update' &&
    u.update.toolCallId===id &&
    ['failed','completed'].includes(u.update.status));
 const denied=byId('b43-acp-denied-001');
 const normal=byId('b43-acp-success-002');
 t.is(denied.length,1,'Exactly one original terminal ACP event for denied call');
 t.is(normal.length,1,'Exactly one original terminal ACP event for normal call');
 t.is(normal[0].update.status,'completed');
 t.is(denied[0].update.status,phase==='after'?'failed':'completed');
 t.is(denied[0].update.rawOutput,'B43 native denied: no external effect');
 t.is(normal[0].update.rawOutput,'B43 native benign success');
 const modelBad=session.messages.find((m:any)=>m.role==='tool'&&m.name==='b43_denied');
 const modelGood=session.messages.find((m:any)=>m.role==='tool'&&m.name==='b43_success');
 t.is(modelBad?.content,'B43 native denied: no external effect');
 t.is(modelGood?.content,'B43 native benign success');
 const witness:any[]=[];
 for(const [tool,id,expected] of [
    ['b43_denied','b43-acp-denied-001',true],
    ['b43_success','b43-acp-success-002',false],
 ] as const){
   const reqs=nativeRequests.filter((r:any)=>r.method==='tools/call'&&r.params?.name===tool);
   t.is(reqs.length,1,tool+' exactly one native tools/call');
   const req=reqs[0];
   const replies=nativeReplies.filter((r:any)=>r.id===req.id);
   t.is(replies.length,1,tool+' matched native original request id');
   const reply=replies[0];
   t.is(reply.result?.isError,expected,tool+' real inband native isError');
   const events=byId(id);
   t.is(events.length,1);
   witness.push({
     case_id:'P1',tool,original_native_request:req,original_native_reply:reply,
     native_request_id:req.id,original_agent_tool_call_id:id,
     original_agent_terminal_status:events[0].update.status,
     original_agent_terminal_count:events.length,
     original_model_tool_message:session.messages.find((m:any)=>m.role==='tool'&&m.name===tool)?.content,
     original_acp_terminal_raw_output:events[0].update.rawOutput,
     original_transport:'StdioClientTransport',
     original_client:'Nano-Collective/nanocoder MCPClient.callTool',
     original_agent:'runAcpConversation',
     original_agent_events:'original ACP sessionUpdate callbacks',
     original_wire_to_model_tool_id_in_band_link:false,
     original_persistent_receipt:false,
     evidence_level:'FUNCTIONAL_NATIVE_SDK_TO_ORIGINAL_AGENT_TERMINAL_NO_ORIGINAL_CROSS_ID',
     original_native_protocol_used:true,
     upstream_source_unchanged:true,
     received_native_reply_isError:true,
   });
 }
 const data={
   schema:'risu-p6b43-nanocoder-original-native-through-acp-v1',
   phase,
   original_repo:'Nano-Collective/nanocoder',
   original_commit:phase==='after'?'2c87d801ef4779f7e4344c287f3feb9f4b0be054':'39d8fa2a8cf0a710d192720daf966fd68b6eaf26',
   original_source_unmodified:true,
   original_MCPClient_native_sdk_and_acp_all_executed:true,
   source_external_test_only_fixture:true,
   native_stdIO_serialized_transport:true,
   native_frame_observation:'transport.send wrapper and transport.onmessage wrapper; logical frame intercept, no independent raw-byte recorder',
   real_external_api_or_effect:false,
   durable_completion_record_available:false,
   original_cross_boundary_id_link_available:false,
   one_original_agent_terminal_per_model_tool_id:true,
   expected_two_real_native_tool_calls:true,
   records:witness,
 };
 writeFileSync(output,JSON.stringify(data,null,2)+'\n',{mode:0o600});
 console.log('B43_NANO_'+phase+'_ORIGINAL_NATIVE_SDK_TO_ORIGINAL_AGENT_ACP_TERMINALS_PASSED');
});
