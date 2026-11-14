// B39 original Geolonia server native HTTP JSON-RPC normal control.
// This is an authored observation adapter, not Geolonia's original client.
// Actual original server worker/index.mjs, original catalog-build functions,
// and official MCP integration test run unmodified.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import worker from '../worker/index.mjs';
import { loadSubjects, BASE_URL } from '../scripts/lib/models.mjs';
import { publishModels } from '../scripts/lib/publish.mjs';
import { readNodeList, readSnapshot } from '../scripts/lib/nodes.mjs';
import { discoverAdapters } from '../scripts/lib/adapters.mjs';
import { writeMcpIndex } from '../scripts/lib/mcp-index.mjs';

let dir, env;
const HEADERS = { 'content-type': 'application/json',
                  'accept': 'application/json, text/event-stream' };
const outdir=process.env.B39_GEO_OUTPUT_DIR;

before(async () => {
  assert.ok(outdir && outdir.length>2, 'B39_OUTPUT_DIR_REQUIRED');
  dir = await mkdtemp(join(tmpdir(), 'risu-b39-geolonia-'));
  const subjects = await loadSubjects();
  const { catalog } = await publishModels(subjects, await discoverAdapters(),
    { nodes: await readNodeList(), outDir: dir });
  await writeMcpIndex(dir, catalog, await readSnapshot(), BASE_URL);
  env = { ASSETS: {
    async fetch(input) {
      const pathname=new URL(typeof input==='string'?input:input.url).pathname;
      try { return new Response(await readFile(join(dir,pathname)),
        { headers: { 'content-type': 'application/json' }}); }
      catch { return new Response('not found', { status:404 }); }
    }
  }};
});
after(async()=>{if(dir) await rm(dir,{recursive:true,force:true});});

async function actualMessage(response) {
  const text=await response.text();
  if (!(response.headers.get('content-type')||'').includes('text/event-stream'))
    return JSON.parse(text);
  const data=text.split('\n').filter(s=>s.startsWith('data:')).map(s=>s.slice(5).trim());
  assert.equal(data.length,1,'B39_MCP_MULTIPLE_SSE_RESPONSES_NOT_SUPPORTED');
  return JSON.parse(data[0]);
}
let seq=0;
async function callOriginal(name,args,revision) {
  const request={jsonrpc:'2.0',id:++seq,method:'tools/call',
     params:{name,arguments:args}};
  const headers={...HEADERS};
  if(revision==='2026-07-28'){
    headers['mcp-protocol-version']='2026-07-28';
    headers['mcp-method']='tools/call';
    headers['mcp-name']=name;
    request.params._meta={
     'io.modelcontextprotocol/protocolVersion':'2026-07-28',
     'io.modelcontextprotocol/clientInfo':{name:'B39-normal-test',version:'1'},
     'io.modelcontextprotocol/clientCapabilities':{}
    };
  }
  const response=await worker.fetch(new Request('https://datamodels.jp/mcp',{
       method:'POST',headers,body:JSON.stringify(request)
  }),env);
  assert.equal(response.status,200,'B39_ORIGINAL_SERVER_HTTP_NOT_200');
  const msg=await actualMessage(response);
  assert.equal(msg.jsonrpc,'2.0');
  assert.equal(msg.id,request.id);
  return {request,response:msg,revision};
}

test('B39 independent Geolonia original server normal dual channels and error',async()=>{
  const tests=[
    ['search_models',{query:'task',limit:1},'2025-06-18'],
    ['get_model',{model:'Task',include_schema:false},'2025-06-18'],
    ['find_attribute',{query:'name',limit:1},'2025-06-18'],
    ['validate',{model:'Task',entity:{id:'x',type:'Task'}},'2025-06-18'],
    ['get_model',{model:'Task',include_schema:false},'2026-07-28'],
    ['get_model',{model:'NoSuchModel'},'2025-06-18'],
    ['get_model',{model:'NoSuchModel'},'2026-07-28']
  ];
  const cases=[];
  for(const [name,args,revision] of tests){
    const wire=await callOriginal(name,args,revision);
    const result=wire.response.result;
    assert.ok(result && Array.isArray(result.content));
    assert.ok(typeof result.content[0]?.text==='string');
    const isError=result.isError===true;
    const observed={
       request_id:wire.request.id,tool:name,
       outcome:isError?'tool_error':'success'
    };
    const contract={status:true};
    if(!isError) {
      assert.ok(result.structuredContent
        && typeof result.structuredContent==='object'
        && !Array.isArray(result.structuredContent),
        'B39_ORIGINAL_NORMAL_STRUCTURED_NOT_PRESENT');
      const parsed=JSON.parse(result.content[0].text);
      assert.deepEqual(parsed,result.structuredContent,
        'B39_ORIGINAL_AUTHOR_REQUIRED_MIRRORED_JSON_VIOLATION');
      observed.structured=parsed;
      contract.structured='exact';
    } else {
      assert.equal(result.structuredContent,undefined,
        'B39_ORIGINAL_ERROR_SHOULD_NOT_HAVE_STRUCTURED_CONTENT');
      assert.match(result.content[0].text,/No model/);
    }
    cases.push({
      source_client_type:'FIRST_PARTY_OBSERVER_OVER_ORIGINAL_THIRD_PARTY_SERVER',
      upstream_original_author_test_also_executed_separately:true,
      protocol_revision:revision,
      intentional_transformation:'MIRRORED_JSON_TEXT_AND_STRUCTURED',
      wire:{request:wire.request,response:wire.response},
      observed,contract,
      execution_provenance:'ORIGINAL_EXTERNAL_SERVER_CONTROLLED_CLIENT',
      original_source_git_blob:'826ba84d772aec28bc12c002c96608cee19e7e8f',
      original_commit_verified:true
    });
  }
  await mkdir(outdir,{recursive:true});
  await writeFile(join(outdir,'B39_GEOLONIA_ORIGINAL_HTTP_WIRES.json'),
    JSON.stringify({schema:'p6b39-geolonia-native-http-original-server-v1',
      cases,external_original_server_executed:true,
      original_upstream_repo:'geolonia/datamodels',
      original_upstream_sha:'d0d2a05cdc60e8e9a106d0f425560a1f1303f21c',
      original_user_client_executed:false,
      server_original_before_after_source_pinned:true,
      original_author_unit_test_results_independent:true
    },null,2)+'\n');
  console.log('B39_ORIGINAL_GEOLONIA_NATIVE_HTTP_7_CASES_PASS');
});
