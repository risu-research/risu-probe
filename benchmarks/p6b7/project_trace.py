"""Explicit SECONDARY experiment: project genuine tools/list to just chosen tool.

Never label the output as raw stdio. No tool schema or call result is altered.
The original genuine capture is always retained; original RISU outcome is
the primary product-acceptance criterion.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

TOOLS={"A11Y205":"check_contrast","FS5184":"read_text_file"}

def project(source:Path, family:str, output:Path, meta:Path)->dict:
    if family not in TOOLS:raise ValueError("not a frozen case")
    orig=source.read_bytes()
    if not orig or len(orig)>4_194_304:raise ValueError("source bounds exceeded")
    lines=[x for x in orig.splitlines() if x.strip()]
    records=[json.loads(x) for x in lines]
    pairs={}
    for idx, rec in enumerate(records):
        if rec.get("method")=="tools/list":
            pairs[rec.get("id")]=idx
    changed=0;target=TOOLS[family];target_hash=None
    for idx,rec in enumerate(records):
        if rec.get("id") in pairs and "result" in rec and
           isinstance(rec["result"],dict) and isinstance(rec["result"].get("tools"),list):
            tools=rec["result"]["tools"]
            selected=[v for v in tools if isinstance(v,dict) and v.get("name")==target]
            if len(selected)!=1:raise ValueError("Frozen tool missing/ambiguous")
            target_hash=hashlib.sha256(json.dumps(selected[0],sort_keys=True).encode()).hexdigest()
            rec["result"]["tools"]=selected
            changed+=1
    if changed != 1:raise ValueError("Exactly one tools/list response expected")
    data=b"".join((json.dumps(r,separators=(",",":"),ensure_ascii=False)+"\n").encode() for r in records)
    if len(data)>524288:raise ValueError("Projected evidence exceeds safe scanner scope")
    output.write_bytes(data)
    result={"schema":"risu-p6b7-secondary-projected-catalog-v1",
       "source_raw_sha256":hashlib.sha256(orig).hexdigest(),
       "projected_sha256":hashlib.sha256(data).hexdigest(),
       "selected_tool_declaration_sha256":target_hash,
       "removed_other_tool_declarations":True,
       "tool_calls_and_responses_unchanged_semantically":True,
       "primary_raw_capture_preserved":True,
       "CANNOT_CLAIM_ACTUAL_RAW_CAPTURE":True}
    meta.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("P6B7_PROJECTION_ONLY_SECONDARY",family,target_hash,flush=True)
    return result

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--raw",type=Path,required=True)
    p.add_argument("--family",choices=TOOLS.keys(),required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--meta",type=Path,required=True)
    a=p.parse_args()
    project(a.raw,a.family,a.out,a.meta)
