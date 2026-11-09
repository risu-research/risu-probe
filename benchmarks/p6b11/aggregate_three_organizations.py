"""P6-B11 preregistered three-organization cross-run integrity score ledger.

External source/workflow scores are data, never instructions or executable inputs.
Keep all preselected rows even if a reproduction or normal control failed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

FAMILIES={"PARTICULARS15":"RMC509","HITCH60":"RMC509","ROBOT682":"RMC507"}
FROZEN={
 "src/risu_mcp_trace.py":"9f017ca0344d94cf54bd0229ddb14d4f586101c8",
 "src/risu_display_fidelity.py":"6785b2ed912d3e9a41dda956da537dc2e5f4f8e3",
}

def audit(manifest:Path,scores:dict[str,Path])->dict:
    raw=manifest.read_bytes()
    m=json.loads(raw)
    if (m.get("schema")!="risu-p6b11-three-organization-frozen-source-and-transport-v1"
         or m.get("frozen_engine")!=FROZEN
         or m.get("preselected_families")!=3):
        raise ValueError("Initial frozen benchmark declaration changed")
    selected=m.get("cases")
    ids={case["id"] for case in selected}
    owners={case["repository"].split("/")[0] for case in selected}
    if len(selected)!=3 or ids!=set(FAMILIES) or len(owners)!=3 or set(scores)-ids:
        raise ValueError("Selected issue family or publisher declaration changed")
    rows=[]
    for case in selected:
        id=case["id"]
        row={"id":id,"publisher":case["repository"].split("/")[0],
             "repository":case["repository"],"issue":case["issue"],
             "prelocked":True,"status":"UNVERIFIED_NOT_EXECUTED",
             "reproduction":None,"normal_control":None,
             "relevant_detection":None,"transport_tier":None}
        if id in scores:
            raw_score=scores[id].read_bytes()
            result=json.loads(raw_score)
            if (result.get("schema")!="risu-p6b11-source-real-stdio-scored-v1"
                or result.get("family")!=id
                or result.get("role")!="PRELOCKED_NEW_CROSS_ORGANIZATION_SOURCE_FAMILY"
                or result.get("origin_is_native_mcp_server")!=(id=="PARTICULARS15")):
                raise ValueError("Wrong provenance or score family "+id)
            original=result.get("upstream_original_bugfix_reproduced") is True
            normal=result.get("normal_controls_passed") is True
            relevant=result.get("frozen_risu_detected_old_not_fixed") is True
            old_findings=result.get("old_risu_findings")
            new_findings=result.get("official_fixed_risu_findings")
            if not isinstance(old_findings,list) or not isinstance(new_findings,list):
                raise ValueError("Missing actual before and after scanner outputs")
            if new_findings or (relevant and (not old_findings or
                set(old_findings)!={FAMILIES[id]})):
                raise ValueError("Confirmed result lists contradict claimed detection")
            for k in ("old_original_trace_sha256","fixed_original_trace_sha256"):
                h=result.get(k)
                if not isinstance(h,str) or len(h)!=64:
                    raise ValueError("Actual source transport digest missing")
            row.update({
                "status":"VERIFIED_REPRODUCTION" if original and normal else "UNVERIFIED_REPRODUCTION_OR_CONTROL",
                "reproduction":original,"normal_control":normal,
                "relevant_detection":(relevant if original and normal else None),
                "transport_tier":result.get("transport"),
                "source_score_sha256":hashlib.sha256(raw_score).hexdigest(),
                "original_capture_sha256":result["old_original_trace_sha256"],
                "fixed_capture_sha256":result["fixed_original_trace_sha256"],
                "old_findings":old_findings,"fixed_findings":new_findings,
            })
        rows.append(row)
    valid=[v for v in rows if v["status"]=="VERIFIED_REPRODUCTION"]
    detected=[v for v in valid if v["relevant_detection"] is True]
    return {"schema":"risu-p6b11-cross-organization-3-source-stdio-ledger-v1",
        "manifest_sha256":hashlib.sha256(raw).hexdigest(),
        "frozen_engine":FROZEN,
        "summary":{
            "preselected_defect_families":3,
            "different_repository_owners":len(owners),
            "source_scores_received":len(scores),
            "source_reproductions_with_normal_controls":len(valid),
            "relevant_detections":len(detected),
            "confirmed_misses":len(valid)-len(detected),
            "unverified_or_missing":3-len(valid),
            "native_source_original_mcp_stdio_verified":sum(v["id"]=="PARTICULARS15" for v in valid),
            "actual_source_with_sdk_stdio_wrapper_verified":sum(v["id"]!="PARTICULARS15" for v in valid),
            "ecosystem_detection_rate":"NOT_ESTIMABLE_NONRANDOM_PRESELECTED_ISSUES",
            "ecosystem_false_positive_rate":"NOT_ESTIMABLE_NARROW_HAND_SELECTED_CONTROLS"},
        "case_rows":rows,
        "limitations":[
            "The 3 cases were chosen nonrandomly from public fixed issues",
            "An original host tool source under a test MCP SDK stdio wrapper is not a native MCP server implementation",
            "For RobotCode the originally selected historic SHA was not shallow-fetchable; a fixed commit parent with identical functional source blobs was transparently substituted",
            "Particulars source fix chronologically predates the formal linked GitHub issue",
            "All raw stdout was captured in isolated synthetic test executions, not production or remote MCP instances",
            "An explicit client output mirror obligation is not an MCP MUST for all tools",
        ],
    }

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--manifest",type=Path,default=Path("benchmarks/p6b11/prelocked_three_organizations.json"))
    parser.add_argument("--score",action="append",default=[])
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args()
    mapping={}
    for item in args.score:
        ident,sep,path=item.partition("=")
        if not sep or ident in mapping:parser.error("Unique FAMILY=score.json required")
        mapping[ident]=Path(path)
    r=audit(args.manifest,mapping)
    args.out.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
    print(json.dumps(r["summary"],indent=2,sort_keys=True))
    if len(mapping)!=3:raise SystemExit("All preregistered cases must be present")
if __name__=="__main__":
    main()
