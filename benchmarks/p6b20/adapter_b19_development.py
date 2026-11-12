"""Adapt preserved B19 original signed-wheel security repair into B20 DEV only.

All B19 raw wire and observer JSON are copied byte-for-byte into separate
B20 development evidence, with JSON pointers back to the originals.
B19 is not used as an independent held-out evaluation and no product rule
is learned after the holdout is selected.
"""
from __future__ import annotations
import argparse,hashlib,json,shutil
from pathlib import Path
from risu_mcp_authority import correlate
from risu_mcp_trace import _read_trace
from risu_mcp_effects import PLAN,EPISODE,canonical,sha

CASES={
 "before_trigger":("VULNERABLE","CONFIGURED"),
 "before_control":("VULNERABLE","NORMAL"),
 "after_trigger":("FIXED","CONFIGURED"),
 "after_control":("FIXED","NORMAL"),
}

def adapt(source,out):
    assert not out.exists(),"Refuse to overwrite original B20 development artifacts"
    first=json.loads((source/".b19-final/REAL_BEFORE_AFTER_FIRSTPASS.json").read_text())
    assert first["summary"]["known_security_repair_reproduced"] is True
    assert first["summary"]["publisher_signed_wheels_checked"]==2
    out.mkdir(parents=True)
    plan={
       "schema":PLAN,
       "experiment":"B19_PUBLISHER_SIGNED_GIT_HIDDEN_EFFECT_DEVELOPMENT_ONLY",
       "classification":"DEVELOPMENT_POSITIVE_CONTROL",
       "tool":"git_status",
       "cells":{},
       "sensors":[{"id":"unexpected-external-effect",
           "kind":"boolean","pattern":"suppressed-in-after-with-controls-stable",
           "expected":None}]
    }
    for cell,(version,case) in CASES.items():
        source_dir=source/".b19-native-firstpass"/version/case
        dest=out/cell
        dest.mkdir()
        for name in ("original_stdio.jsonl","original_effect_witness.json"):
            shutil.copyfile(source_dir/name,dest/name)
            assert dest.joinpath(name).read_bytes()==source_dir.joinpath(name).read_bytes()
        trace=dest/"original_stdio.jsonl"
        origin=dest/"original_effect_witness.json"
        previous=json.loads(origin.read_text())
        assert previous["status"]=="CAPTURED_ORIGINAL_NATIVE"
        assert previous["trace_sha256"]==sha(trace.read_bytes())
        assert previous["variant"]==version and previous["case"]==case
        assert previous["marker_before"] is False
        assert previous["marker_content_valid"] is True
        wire,digest=_read_trace(trace)
        calls,errors=correlate(wire)
        assert not errors and len(calls)==1
        c=calls[0]
        assert c["name"]=="git_status" and type(c["response"]) is dict
        assert c["response"].get("isError") is not True
        entry={
          "schema":EPISODE,
          "case":cell,
          "trace_sha256":digest,
          "call":{
             "tool":c["name"],
             "arguments_sha256":sha(canonical(c["args"])),
             "result_sha256":sha(canonical(c["response"])),
             "request_line":c["request_line"],
             "response_line":c["response_line"]
          },
          "sensors":[{
             "id":"unexpected-external-effect","kind":"boolean",
             "before":previous["marker_before"],
             "after":previous["marker_after"],
             "original_observer":{
                "file":cell+"/original_effect_witness.json",
                "sha256":sha(origin.read_bytes()),
                "before_pointer":"/marker_before",
                "after_pointer":"/marker_after"
              }
          }],
          "observer_trust_scope":"CI_OBSERVED_NOT_REMOTELY_ATTESTED"
        }
        (dest/"episode.json").write_text(json.dumps(entry,indent=2,sort_keys=True,
                                               ensure_ascii=False)+"\n")
        plan["cells"][cell]={
          "trace":cell+"/original_stdio.jsonl",
          "episode":cell+"/episode.json"}
    (out/"PLAN_DEVELOPMENT_B19.json").write_text(
        json.dumps(plan,indent=2,sort_keys=True,ensure_ascii=False)+"\n")
    (out/"B19_SOURCE_COHORT_NOTE.json").write_text(
      json.dumps({"schema":"risu-b20-development-vs-evaluation-separation-v1",
       "origin":"B19 prior known-public-issue upstream signed wheel experiment",
       "upstream_advisory":"GHSA-6hqx-gqrx-c5r2",
       "original_source_run":43316866530,
       "original_independent_audit":43317961883,
       "development_only":True,
       "eligible_for_new_bug_discovery_count":False,
       "observer_authorship_claim":"CI source witness; separate B19 authenticated publisher and independent audit, not protected by this B20 JSON adapter"},indent=2,sort_keys=True)+"\n")
    print("B20_B19_DEVELOPMENT_POSITIVE_ADAPTED",len(plan["cells"]),sha(canonical(plan)))


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    adapt(a.source,a.out)
if __name__=="__main__":main()
