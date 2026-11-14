// P6-B39 P1 positive: upstream FastMCP EdgeFastMCP original source over native HTTP.
// This proves pre/post *producer* projection against the independently fixed callback
// return value. It is NOT a B38 source-independent wire-to-consumer verifier hit.
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const [sourceFile, version, output] = process.argv.slice(2);
assert(["before","after"].includes(version) && sourceFile && output,
       "usage: tsx p1_edge_native.ts source.ts before|after out.json");
const { EdgeFastMCP } = await import(pathToFileURL(resolve(sourceFile)).href);
const original = version === "before"
  ? { commit: "cf6f981305e4f8c11c0a3e1d1401bcdcb1530587",
      blob: "f16c4f0856d37d36037a9be6e484a25de26be109" }
  : { commit: "93c1a2bdb2cfbabb242805e5c1ab02cf5d10f91f",
      blob: "e58f3ebfded3ec2091da5728639087f3d1a76cbe" };
const server = new EdgeFastMCP({ name: "b39-local-no-network", version: "1.0" });
const returned = {
  content: [{ type: "text", text: "Synthetic failure, no real secrets" }],
  isError: true,
  structuredContent: { code: "SYNTHETIC_ERR", recoverable: true },
  _meta: { witness: "B39_LOCAL_ONLY" },
};
server.addTool({ name: "declared_error", description: "synthetic error return",
                 execute: async () => returned });
server.addTool({ name: "normal_string", description: "plain text success",
                 execute: async () => "normal success" });
server.addTool({ name: "exception", description: "real local exception",
                 execute: async () => { throw new Error("synthetic throw"); } });
async function call(id, name) {
  const request = { jsonrpc: "2.0", id, method: "tools/call",
                    params: { name, arguments: {} } };
  const response = await server.fetch(new Request("http://localhost/mcp", {
    method: "POST", headers: { accept: "application/json",
                            "content-type": "application/json" },
    body: JSON.stringify(request),
  }));
  const body = await response.text();
  assert.equal(response.status, 200, body.slice(0,350));
  const native = JSON.parse(body);
  assert.equal(native.jsonrpc, "2.0");
  assert.equal(native.id, id);
  return { request, response: native, http_status: response.status };
}
const err = await call(2101, "declared_error");
const normal = await call(2102, "normal_string");
const thrown = await call(2103, "exception");
assert.equal(err.response.result.content[0].text, returned.content[0].text);
assert.equal(normal.response.result.content[0].text, "normal success");
assert.equal(thrown.response.result.isError, true);
assert.equal(typeof thrown.response.result.content[0].text, "string");
const projected = {
  isError: err.response.result.isError ?? null,
  structuredContent: err.response.result.structuredContent ?? null,
  _meta: err.response.result._meta ?? null,
};
if (version === "before") {
  assert.equal(projected.isError, null);
  assert.equal(projected.structuredContent, null);
  assert.equal(projected._meta, null);
} else {
  assert.equal(projected.isError, true);
  assert.deepEqual(projected.structuredContent, returned.structuredContent);
  assert.deepEqual(projected._meta, returned._meta);
}
const report = {
  schema: "risu-b39-p1-original-edge-http-v1", case: "P1", version,
  original_commit: original.commit, original_source_git_blob: original.blob,
  original_source_unchanged: true,
  execution_class: "ORIGINAL_NATIVE_SERVER_CONTROLLED_CLIENT",
  primary_b38_verifier_scored: false,
  reason_not_b38_verifier_scored:
    "Upstream server itself drops the fields before wire. Frozen B38 auditor compares wire to consumer, not callback to wire.",
  source_callback_return: returned, native_http_wire: { error: err, normal, thrown },
  observed_projection: projected, expected_official_repair:
    "P1 error status, structuredContent and _meta copied into native wire",
  repair_predicate_satisfied: version === "after"
    ? projected.isError === true
    : projected.isError === null,
};
mkdirSync(dirname(resolve(output)), { recursive: true });
writeFileSync(resolve(output), JSON.stringify(report,null,2)+"\n");
console.log(JSON.stringify({ case: "P1", version, projection: projected,
                             normal_ok: true, throw_ok: true,
                             original_native_http: true }));
