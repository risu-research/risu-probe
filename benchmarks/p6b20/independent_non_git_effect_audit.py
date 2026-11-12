"""B20 independently auditable, source-original non-Git effect observation.

No imports of RISU generic effect product. Verifies original published Python
wheel, original server Git blob, actual raw MCP calls and independently
captured original before/after payload bytes, across four safe fixtures.
This is a normal functional holdout, NOT a genuine novel security defect.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

COMMIT="1aff1e094ed317ec2c5de06591978781d660c48a"
BLOB="f886fcbc6e61f3be8e6fd76b6e5f3ad1f8cbb7b6"
MODULE_SHA="c754a7720d52d92eb49324649b19f58b07b20703fcc2c2c1b02ce1f20152fcc8"
RELEASE_WHEEL="filesystem_mcp-1.0.2-py3-none-any.whl"
WHEEL_SHA="94610f0b73df1d3ada4ef0353353eb93695645c7b82f71ca80ed13dc1022c235"
TEXT=b"RISU B20 safe synthetic write\n"
CELLS=("before_trigger","before_control","after_trigger","after_control")


def must(expr,reason):
    if not expr:raise ValueError(reason)

def sha(raw):return hashlib.sha256(raw).hexdigest()
def json_file(path):return json.loads(Path(path).read_text("utf-8"))

def audit(evidence_root:Path, package:Path):
    m=json_file(package/"original_distribution.json")
    pub=json_file(package/"independent_upstream_source.json")
    wheel=package/RELEASE_WHEEL
    must(sha(wheel.read_bytes())==WHEEL_SHA==m["wheel_sha256"]==pub["pypi_wheel_sha256"],
         "Original public publisher distribution bytes differ from firstpass")
    must(pub["publisher"]=="kujirahand/mcp_server-filesystem" and
         pub["pinned_commit"]==COMMIT and
         pub["original_git_blob"]==BLOB and
         pub["publisher_origin_bytes_match_wheel"] is True,
         "Independent source publisher Git blob provenance missing")
    with zipfile.ZipFile(wheel) as z:
        original=z.read("filesystem_mcp/server.py")
    must(sha(original)==MODULE_SHA==pub["source_code_sha256"],"Original installed module not pinned")
    must(hashlib.sha1(b"blob "+str(len(original)).encode()+bytes([0])+original).hexdigest()==BLOB,
         "Original Git object content differs from published package")
    observations={}
    results={}
    for cell in CELLS:
        root=evidence_root/cell
        wire=(root/"original_stdio.jsonl").read_bytes()
        log=json_file(root/"original_native_process.json")
        observed=json_file(root/"original_file_observer.json")
        derived=json_file(root/"episode.json")
        must(log["status"]=="CAPTURED_ORIGINAL_NATIVE" and log["tool_success"] is True,
             "Original upstream MCP tool did not complete normally")
        must(log["code_unmodified"] is True and
             log["target_distribution"]=="filesystem-mcp==1.0.2",
             "Original upstream package identity incomplete")
        must(log["trace_sha256"]==sha(wire)==derived["trace_sha256"],
             "Raw original stdout disconnected from independent observer")
        messages=[json.loads(line) for line in wire.splitlines()]
        must(len(messages)==7 and all(x.get("jsonrpc")=="2.0" for x in messages),
             "Original native MCP message sequence incomplete")
        must(messages[0]["method"]=="initialize" and
             messages[1]["id"]==1 and messages[2]["method"]=="notifications/initialized"
             and messages[3]["method"]=="tools/list",
             "No original initialization and catalog negotiation")
        # Native request order: initialize request, reply, initialized,
        # tools/list request, tools/list reply, tool request, tool reply.
        # Use a structural search so no RISU parsing code is required.
        requests=[m for m in messages if m.get("method")=="tools/call"]
        catalog=[m["result"] for m in messages if m.get("id")==2 and
                 type(m.get("result")) is dict]
        replies=[m["result"] for m in messages if m.get("id")==20 and
                 type(m.get("result")) is dict]
        must(len(requests)==len(catalog)==len(replies)==1,
             "Original MCP call/catalog/result not unique")
        must(any(t.get("name")=="write_file" for t in catalog[0]["tools"]),
             "Upstream server did not advertise actual tool")
        req=requests[0]["params"]
        must(req.get("name")=="write_file" and
             req.get("arguments",{}).get("content")=="RISU B20 safe synthetic write\n"
             and req.get("arguments",{}).get("append") is False,
             "Original selected new-publisher tool call changed")
        original_path=Path(req["arguments"]["path"])
        must(original_path.name=="payload.txt" and original_path.parent.name=="allowed",
             "Original source effect target outside synthetic fixture")
        must(replies[0].get("isError") is not True,"Actual original source tool failed")
        must(log["expected_after_content_matches"] is True,"External observer saw wrong payload")
        prefile=root/"observed_before_payload.bin"
        postfile=root/"observed_after_payload.bin"
        pre=prefile.read_bytes() if prefile.exists() else None
        post=postfile.read_bytes() if postfile.exists() else None
        expect_pre=None if cell.endswith("_trigger") else TEXT
        must(pre==expect_pre and post==TEXT,
             "Original observed before/after *bytes* inconsistent with selected control")
        state={
            "before_exists":pre is not None,
            "after_exists":post is not None,
            "before_sha256":sha(pre) if pre is not None else None,
            "after_sha256":sha(post) if post is not None else None,
            "before_bytes":len(pre) if pre is not None else 0,
            "after_bytes":len(post) if post is not None else 0
        }
        for key,value in state.items():
            must(observed[key]==value,"Original observer JSON differs from captured file bytes")
        must(log["before"]["exists"]==state["before_exists"] and
             log["before"]["digest"]==state["before_sha256"] and
             log["before"]["size"]==state["before_bytes"] and
             log["after"]["exists"]==state["after_exists"] and
             log["after"]["digest"]==state["after_sha256"] and
             log["after"]["size"]==state["after_bytes"],
             "Original process witness not verified against original before/after payload")
        observations[cell]=state
        # The tool response is a successful structured result. It need not
        # have identical body across randomized independent fixture paths.
        results[cell]=sha(json.dumps(replies[0],sort_keys=True,
                         separators=(",",":"),ensure_ascii=False).encode())
    before_trigger=observations["before_trigger"]
    before_control=observations["before_control"]
    after_trigger=observations["after_trigger"]
    after_control=observations["after_control"]
    must(before_trigger==after_trigger and before_control==after_control,
         "Independent original duplicate run produced different state transition")
    must(before_trigger["before_exists"] is False and
         before_trigger["after_exists"] is True and
         before_control["before_exists"] is True and
         before_control["after_exists"] is True,
         "Normal and trigger state observations mixed")
    return {
       "schema":"risu-b20-independent-other-publisher-original-file-effect-audit-v1",
       "public_publisher":"kujirahand/mcp_server-filesystem",
       "published_version":"1.0.2","upstream_git_commit":COMMIT,
       "upstream_original_code_blob":BLOB,
       "pypi_distributed_wheel_sha256":WHEEL_SHA,
       "original_server_module_sha256":MODULE_SHA,
       "publisher_release_signature":"NOT_VERIFIED_OR_CLAIMED",
       "actual_native_mcp_calls_independently_audited":4,
       "original_independent_file_snapshots_audited":8,
       "original_independent_fixture_before_after_bytes_match":True,
       "one_real_mcp_tool_name":"write_file",
       "three_effect_sensor_transition_patterns":{
          "file_exists":[True,False,True,False],
          "file_sha256":[True,False,True,False],
          "file_byte_count":[True,False,True,False],
       },
       "source_original_status":"ALL_FOUR_SUCCESSFUL",
       "software_version_comparison":False,
       "new_upstream_defects_confirmed":0,
       "independent_source_file_SHA256":sha(original),
       "tool_result_sha256_by_case":results,
       "limits":"All four cases use one exact upstream version in two independent replicas. Original captured payload bytes are rehashed but the physical external observer is CI supplied and not remotely signed. Passing this normal file effect test does not establish novel bug discovery."
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--evidence",required=True,type=Path)
    p.add_argument("--package",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    r=audit(a.evidence,a.package)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(r,indent=2,sort_keys=True,ensure_ascii=False)+"\n")
    print("B20_INDEPENDENT_NEW_PUBLISHER_REAL_ORIGINAL_EFFECT_AUDIT",
         r["actual_native_mcp_calls_independently_audited"],
         r["three_effect_sensor_transition_patterns"])


if __name__=="__main__":main()
