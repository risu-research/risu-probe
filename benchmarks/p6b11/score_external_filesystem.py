"""Score authentic official Python MCP SDK wire against PINNED external Node MCP server.

FS5184 was used in B7/B8: a DEVELOPMENT regression, not a new independent
external bug family. Both captures contain the original byte-for-byte wire.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

from score_real_stdio import convert
from risu_mcp_trace import verify_trace

def score(root:Path):
    outputs={}
    policy=json.loads(Path("benchmarks/p6b8/fs5184_explicit_dev_contract.json").read_text())
    for rev in ("old","fixed"):
        folder=root/rev
        raw=folder/"original_raw_stdio.jsonl"
        observation=json.loads((folder/"origin.json").read_text())
        assert observation["revision"]==rev
        assert observation["dataset_role"]=="KNOWN_B7_DEVELOPMENT_PAIR_NOT_NEW_INDEPENDENT_HOLDOUT"
        transcript=folder/"exact_value_transcript.jsonl"
        wire=convert(raw,transcript,expected_calls=2)
        if wire["raw_sha256"]!=observation["raw_capture_sha256"]:
            raise RuntimeError("Captured original wire and SDK client digest disagree")
        raw_report=verify_trace(transcript)
        behavior=verify_trace(transcript,behavior_contract=policy)
        (folder/"schema_report.json").write_text(json.dumps(raw_report,indent=2)+"\n")
        (folder/"behavior_report.json").write_text(json.dumps(behavior,indent=2)+"\n")
        if raw_report["summary"]["findings"]:
            raise RuntimeError("Unexpected schema finding in pinned original external MCP stdout")
        outputs[rev]={"origin":observation,"wire":wire,"behavior":behavior}

    old=outputs["old"]
    fixed=outputs["fixed"]
    a=old["origin"]["outcomes"]
    b=fixed["origin"]["outcomes"]
    def normal(x):
        text=x["normal_two"]["text"]
        return text.startswith("one") and "two" in text and "three" not in text
    reproduced=(all(normal(z) for z in (a,b))
        and "three" in a["head_zero"]["text"]
        and b["head_zero"]["text"]=="")
    old_rule={v["rule_id"] for v in old["behavior"]["findings"]}
    fixed_rule={v["rule_id"] for v in fixed["behavior"]["findings"]}
    detected=reproduced and "RMC506" in old_rule and "RMC506" not in fixed_rule
    evidence={
        "schema":"risu-p6b11-real-external-upstream-pair-stdio-v1",
        "role":"B7_FS5184_PREVIOUSLY_KNOWN_DEVELOPMENT_PAIR_NOT_INDEPENDENT",
        "actual_upstream_source":"modelcontextprotocol/servers original pinned filesystem old/fix",
        "official_mcp_client":"mcp==1.28.0 Python ClientSession",
        "wire_evidence":"BYTE_PRESERVED_GENUINE_STDIO_TWO_WAY_ORIGINAL_AND_FIXED",
        "source_component_before_fix_reproduced":bool(reproduced),
        "frozen_behavior_rule_on_old_only":bool(detected),
        "normal_head_two_control_both":all(normal(z) for z in (a,b)),
        "semantic_rule":"RMC506_USER_DECLARED_HEAD_ZERO_ORACLE",
        "raw_original_sha256":{v:outputs[v]["wire"]["raw_sha256"] for v in ("old","fixed")},
        "captured_tool_calls":{v:outputs[v]["wire"]["calls"] for v in ("old","fixed")},
        "claim_boundary":"Actual third-party upstream Node MCP server over official Python SDK client stdio, source pins verified; B7/B8 previously used as dev bug and oracle explicitly supplied, NOT independent discovery or autonomous semantic inference. Files synthetic only.",
    }
    (root/"external_real_wire_score.json").write_text(json.dumps(evidence,indent=2,sort_keys=True)+"\n")
    print(json.dumps(evidence,indent=2,sort_keys=True))
    if not reproduced or not detected:
        raise SystemExit("Pinned external real-stdio causal/source diagnostic regression failed")

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("out",type=Path)
    a=p.parse_args()
    score(a.out)
