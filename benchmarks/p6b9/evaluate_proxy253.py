"""Prelocked PROXY253 original upstream pagination observations and frozen RISU check."""
import argparse
import json
from pathlib import Path

def read(p):
    obj=json.loads(p.read_text())
    assert obj["schema"]=="risu-p6b9-proxy253-component-v1"
    assert obj["source"]=="ACTUAL_PINNED_UPSTREAM_PROXY_HANDLER_WITH_SYNTHETIC_REMOTE_PEER"
    assert len(obj["pages"])==2
    return obj

def value(page):
    x=page["returned"]
    if "root" in x and "tools" not in x: x=x["root"]
    assert type(x)==dict and isinstance(x.get("tools"),list)
    return x

def names(page):
    return [t["name"] for t in value(page)["tools"]]

def make_trace(c):
    rows=[]
    for i,page in enumerate(c["pages"],1):
        params={} if page["requested_cursor"] is None else {"cursor":page["requested_cursor"]}
        rows += [
            {"jsonrpc":"2.0","id":i,"method":"tools/list","params":params},
            {"jsonrpc":"2.0","id":i,"result":value(page)}
        ]
    return rows

def score(o,f,oldr,newr):
    on=[names(x) for x in o["pages"]];fn=[names(x) for x in f["pages"]]
    upstream=(o["actual_remote_cursors"]==[None,None]
            and f["actual_remote_cursors"]==[None,"p2"]
            and on==[["first"],["first"]] and fn==[["first"],["second"]])
    initial_control=on[0]==fn[0]==["first"]
    oc={v["code"] for v in oldr.get("unverified",[])}
    fc={v["code"] for v in newr.get("unverified",[])}
    detected=upstream and "INVALID_CATALOG" in oc and "INVALID_CATALOG" not in fc and newr["summary"]["latest_catalog_declarations_indexed"]==2
    return {"schema":"risu-p6b9-proxy253-paired-score-v1",
            "family":"PROXY253","role":"PRELOCKED_NEW_INDEPENDENT_FAMILY",
            "reproduced":bool(upstream),
            "normal_initial_page_control_pass":bool(initial_control),
            "old_unverified_codes":sorted(oc),"fixed_unverified_codes":sorted(fc),
            "diagnostic_detected":bool(detected),
            "confirmed_mcp_semantic_violation_by_risu":False,
            "source_evidence":"ACTUAL_UPSTREAM_PROXY_HANDLER_WITH_LOCAL_MOCK_PEER_AND_ADAPTER_JSONRPC_NOT_WIRE",
            "limitation":"Duplicate/cyclic catalog detection is a verified symptom; it does not independently prove which proxy line discarded the cursor. Four affected methods count as one root cause."}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("mode",choices=("trace","score"))
    p.add_argument("files",nargs="+",type=Path)
    a=p.parse_args()
    if a.mode=="trace":
        assert len(a.files)==2
        rows=make_trace(read(a.files[0]))
        a.files[1].write_text("".join(json.dumps(x,sort_keys=True)+"\n" for x in rows))
    else:
        assert len(a.files)==5
        old,fixed,ro,rf,out=a.files
        q=score(read(old),read(fixed),json.loads(ro.read_text()),json.loads(rf.read_text()))
        out.write_text(json.dumps(q,indent=2,sort_keys=True)+"\n")
        print(json.dumps(q,indent=2,sort_keys=True))
        if not q["normal_initial_page_control_pass"]:raise SystemExit("Control failed")
if __name__=="__main__":main()
