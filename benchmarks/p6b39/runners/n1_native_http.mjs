// P6-B39 N1: real original Geolonia HTTP MCP server, credential-free local fixture.
// No source modifications; all import paths resolve to pinned original Git checkout.
// The first-party caller exercises upstream production handleMcp over a native HTTP request.
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const [sourcePath, outputPath] = process.argv.slice(2);
assert(sourcePath && outputPath, "usage: node n1_native_http.mjs original/worker/mcp.mjs out.json");
const { handleMcp } = await import(pathToFileURL(resolve(sourcePath)).href);
const index = {
  models: [{ id: "example/Trial", type: "Trial", typeIri: "urn:example:trial",
             title: { en: "Synthetic trial" }, kind: "model", status: "published" }],
  nodeModels: [], search: [], attributes: [],
};
const env = {
  ASSETS: { async fetch(request) {
    const path = new URL(request.url).pathname;
    return path === "/mcp/index.json"
      ? Response.json(index)
      : new Response("not found", { status: 404 });
  } },
};
async function call(id, name, args) {
  const request = { jsonrpc: "2.0", id, method: "tools/call",
                    params: { name, arguments: args } };
  const res = await handleMcp(
    new Request("https://datamodels.jp/mcp", {
      method: "POST",
      headers: { "content-type": "application/json",
                 accept: "application/json, text/event-stream",
                 "mcp-protocol-version": "2025-06-18" },
      body: JSON.stringify(request),
    }), env,
  );
  const body = await res.text();
  const messages = res.headers.get("content-type")?.includes("text/event-stream")
    ? body.split("\n").filter(x => x.startsWith("data:")).map(x => JSON.parse(x.slice(5)))
    : [JSON.parse(body)];
  assert.equal(messages.length, 1, "exactly one original native JSON-RPC response");
  const response = messages[0];
  assert.equal(response.id, id);
  return { request, response, http_status: res.status, transport: "ORIGINAL_NATIVE_HTTP" };
}
const cases = [];
const commit = "d0d2a05cdc60e8e9a106d0f425560a1f1303f21c";
const blob = "826ba84d772aec28bc12c002c96608cee19e7e8f";
function append(name, record, observation, contract) {
  cases.push({
    case_id: "N1", name, original_commit: commit,
    original_source_git_blob: blob, original_commit_verified: true,
    execution_provenance: "ORIGINAL_EXTERNAL_SERVER_CONTROLLED_CLIENT",
    wire: { request: record.request, response: record.response },
    observed: { tool: record.request.params.name, request_id: record.request.id, ...observation },
    contract,
    native_http_status: record.http_status,
    native_transport: record.transport,
    original_source_unchanged: true,
    consumer_evidence: "FIRST_PARTY_CONTROLLER_TEXT_DECODER; not an original upstream client",
  });
}
const ok = await call(1101, "search_models", { query: "*" });
assert.equal(ok.http_status, 200);
assert.equal(ok.response.result?.isError, undefined);
const text = ok.response.result.content.filter(x => x.type === "text").map(x => x.text).join("\n");
const parsed = JSON.parse(text); // independent controlled-client text-channel observation
assert.equal(parsed.results[0].model, "example/Trial");
assert.deepEqual(parsed, ok.response.result.structuredContent, "upstream mirror expected to agree");
append("normal_dual_channel_json", ok,
       { outcome: "success", structured: parsed },
       { status: true, structured: "exact" });
const toolErr = await call(1102, "get_model", { model: "NotPublished" });
assert.equal(toolErr.response.result?.isError, true);
assert.ok(toolErr.response.result.content[0].text.length > 0);
append("normal_tool_error", toolErr, { outcome: "tool_error" }, { status: true });
const rpcErr = await call(1103, "missing_tool", {});
assert.equal(typeof rpcErr.response.error?.message, "string");
append("normal_jsonrpc_error", rpcErr,
       { outcome: "jsonrpc_error", error_text: rpcErr.response.error.message },
       { status: true });
const output = { schema: "risu-b39-n1-original-server-native-http-v1", native_http_cases: cases,
                 qualification: "original external producer, controlled first-party observer; no claim about an independent external client",
                 upstream_policy: "MIRRORED_TEXT_AND_STRUCTURED_JSON", sampled_normal_orgs: 1 };
mkdirSync(resolve(outputPath,".."), { recursive:true });
writeFileSync(resolve(outputPath), JSON.stringify(output, null, 2) + "\n");
console.log(JSON.stringify({ case:"N1", scenarios: cases.map(c=>c.name),
                            original_external_native_http:true, original_source_unchanged:true }));
