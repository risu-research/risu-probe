/**
 * B40 post-seal integration adapter. It executes original, unmodified external
 * LangChain loadMcpTools and the original MCP TypeScript SDK client/server.
 * Controlled synthetic server responses only; no model/production credentials.
 *
 * This is an EXTRA, after-exposure integration experiment, not the original
 * maintainer-authored regression test and not a pre-exposure hypothesis.
 */
import { test, expect } from "vitest";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { McpServer } from "@modelcontextprotocol/server";
import { ToolMessage } from "@langchain/core/messages";
import { loadMcpTools } from "../tools.js";
import { z } from "zod";
import { writeFileSync } from "node:fs";

test("B40 actual external MCP consumer function reads native JSON-RPC success and error separately",async()=>{
 const out=process.env.B40_NATIVE_WITNESS;
 const variant=process.env.B40_ORIGINAL_VERSION;
 if(!out||!["before","after"].includes(variant??""))throw new Error("B40_RUNNER_MISSING_OUTPUT_OR_VERSION");
 const server=new McpServer({name:"b40-synthetic",version:"1"},{capabilities:{tools:{}}});
 server.registerTool("fail",{description:"local in-band failure",inputSchema:z.object({})},
   async()=>({isError:true,content:[{type:"text",text:"denied"}],structuredContent:{code:"DENIED"}}));
 server.registerTool("ok",{description:"local success",inputSchema:z.object({})},
   async()=>({content:[{type:"text",text:"hello"}]}));
 const client=new Client({name:"b40-original-client",version:"1"});
 const [clientTransport,serverTransport]=InMemoryTransport.createLinkedPair();
 const sent:unknown[]=[];
 const received:unknown[]=[];
 const sendClient=clientTransport.send.bind(clientTransport);
 const sendServer=serverTransport.send.bind(serverTransport);
 clientTransport.send=async(message,...rest)=>{ sent.push(JSON.parse(JSON.stringify(message)));return sendClient(message,...rest);};
 serverTransport.send=async(message,...rest)=>{ received.push(JSON.parse(JSON.stringify(message)));return sendServer(message,...rest);};
 await server.connect(serverTransport);
 const results:any[]=[];
 try{
   await client.connect(clientTransport);
   const loaded=await loadMcpTools("b40",client);
   for (const [name,callID] of [["ok","call-ok"],["fail","call-fail"]]){
     const tool=loaded.find(x=>x.name===name);
     expect(tool).toBeDefined();
     let value:any=null;
     let thrown:any=null;
     try{value=await tool!.invoke({type:"tool_call",id:callID,name,args:{}} as any);}
     catch(error){thrown=error;}
     const reqs=sent.filter((x:any)=>x?.method==="tools/call"&&x?.params?.name===name) as any[];
     expect(reqs).toHaveLength(1);
     const req=reqs[0];
     const reps=received.filter((x:any)=>x?.id===req.id&&x?.jsonrpc==="2.0") as any[];
     expect(reps).toHaveLength(1);
     const resp=reps[0];
     const originalObservation = {
       tool:name,request_id:req.id,
       outcome: thrown? "tool_error": (ToolMessage.isInstance(value)?(value.status==="error"?"tool_error":"success"):"success"),
       original_observation_form: thrown?"THROWN_EXCEPTION":ToolMessage.isInstance(value)?"ORIGINAL_LANGCHAIN_TOOL_MESSAGE":"OTHER",
       original_tool_message_status:ToolMessage.isInstance(value)?value.status:null,
       original_tool_message_name:ToolMessage.isInstance(value)?value.name:null,
       original_tool_message_call_id:ToolMessage.isInstance(value)?value.tool_call_id:null,
       original_content:ToolMessage.isInstance(value)?value.content:null,
       original_exception_name:thrown?.name??null,
       original_exception_message:thrown?.message??null,
     };
     if(name==="ok"){
       expect(thrown).toBeNull();
       expect(ToolMessage.isInstance(value)).toBe(true);
       expect(value.status??"success").toBe("success");
     }else if(variant==="before"){
       expect(thrown).not.toBeNull();
       expect(ToolMessage.isInstance(value)).toBe(false);
     }else{
       expect(thrown).toBeNull();
       expect(ToolMessage.isInstance(value)).toBe(true);
       expect(value.status).toBe("error");
       expect(value.tool_call_id).toBe(callID);
       expect(value.name).toBe(name);
       expect(value.content).toBe("denied");
     }
     results.push({case_id:"P2",original_variant:variant,tool:name,wire:{request:req,response:resp},
       observed:originalObservation,
       contract:{status:true,text:"none",structured:"none",media:"none"},
       execution_provenance:"ORIGINAL_EXTERNAL_CLIENT_CONTROLLED_SERVER",
       original_commit_verified:true,
       original_source_git_blob:variant==="before"
         ?"6d5b4b713a3acea3b2b001285e3af8272b9bef9b"
         :"2b687c45315d13d9450a33161b1a7e67d36fcbf5",
       original_upstream_source_unchanged:true,
       test_only_overlay:true,
       original_app_level_outcome_captured:true,
       native_transport:"OFFICIAL_SDK_IN_MEMORY_JSONRPC_NOT_HTTP",
       independent_full_application_executed:false});
   }
 }finally{await client.close();await server.close();}
 writeFileSync(out,JSON.stringify({schema:"risu-b40-p2-native-original-consumer-v1",variant,real_original_client_adapter:true,
   first_party_test_only_adapter:true,not_full_original_app:true,
   expected_generic_detector_sensitivity:"DO_NOT_CLAIM_CHANGED_STATUS_ON_THROW_VS_TOOLMESSAGE",
   scenarios:results},null,2)+"\n");
});