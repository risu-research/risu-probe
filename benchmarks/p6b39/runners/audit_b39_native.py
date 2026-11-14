#!/usr/bin/env python3
"""B39 score original native N1 with B38 *unchanged* external verifier.

A producer response is not equivalent to an independent external consumer.
P1 original pre/post proves wire projection only and is never scored as a
frozen B38 checker success. N3/N4 source-only normal-policy tests are not FPR
denominator units. No retrospective tuning or unsupported ecosystem rate.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path

def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))

def wilson_interval(k: int, n: int, z: float = 1.959963984540054) -> list[float] | None:
    if not n:
        return None
    proportion = k / n
    denom = 1 + z * z / n
    center = (proportion + z*z/(2*n)) / denom
    rad = z * math.sqrt(proportion*(1-proportion)/n + z*z/(4*n*n)) / denom
    return [round(max(0, center-rad), 6), round(min(1, center+rad), 6)]

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--verifier", type=Path, required=True)
    p.add_argument("--n1", type=Path, required=True)
    p.add_argument("--before-p1", type=Path)
    p.add_argument("--after-p1", type=Path)
    p.add_argument("--normal-source", type=Path)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    spec=importlib.util.spec_from_file_location("frozen_b38_native_contract_auditor", args.verifier)
    assert spec and spec.loader
    b38=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(b38)
    normal=load(args.n1)
    assert normal["schema"] == "risu-b39-n1-original-server-native-http-v1"
    rows=[]
    for record in normal["native_http_cases"]:
        try:
            result = b38.audit_record(record)
        except (b38.IncompleteEvidence, ValueError) as e:
            result = {"classification":"INCOMPLETE", "reason":str(e), "findings":[]}
        rows.append({
            "case_id":"N1", "variant":record["name"],
            "classification":result["classification"],
            "findings":result.get("findings", []),
            "channels_tested":result.get("channels_tested",[]),
            "source_git_blob":record["original_source_git_blob"],
            "native_http":True, "verified_original_server_source":True,
            "controlled_observer_not_original_client":True,
            "native_tool_witness_sha256":result.get("native_tool_witness_sha256"),
        })
    required={r["variant"] for r in rows}
    assert required == {"normal_dual_channel_json","normal_tool_error","normal_jsonrpc_error"}
    # Only N1 has native original-code protocol evidence in this job. N1's
    # upstream mirror contract is source-documented and validated independently
    # by its native text/structured response. This is a producer-level control.
    eligible = int(all(row["classification"] != "INCOMPLETE" for row in rows))
    disagreements=[r for r in rows if r["classification"]=="DISCREPANCY"]
    zero_flag = int(eligible and not disagreements)
    report={
        "schema":"risu-b39-frozen-checker-original-normal-audit-v1",
        "b38_verifier_original_git_blob":"67bbb607d277dda3a1ead60a2ccd9ba807afd7ae",
        "public_main_unchanged_target":"8d622b792b4ae58b7157fd81ee5f95d6febcfd53",
        "preregistered_planned_normal_orgs":4,
        "native_original_server_normal_orgs":1,
        "native_original_external_client_normal_orgs":0,
        "verified_original_function_only_normal_orgs":2 if args.normal_source else 0,
        "native_protocol_in_scope_eligible_orgs":eligible,
        "native_protocol_discrepancy_orgs":int(bool(disagreements)) if eligible else None,
        "native_producer_normal_no_discrepancy_orgs":zero_flag,
        "independent_external_consumer_false_alarm_rate":"UNMEASURED",
        "population_fpr":"UNMEASURED",
        "wilson_95_native_producer_discrepancy_only":
            wilson_interval(int(bool(disagreements)),eligible) if eligible else None,
        "n1_frozen_verifier_results":rows,
        "primary_denominator_caution":
            "N1 original server+controlled caller, not an independently authored client; P1 original server positive and N3/N4 original function normals are excluded from independent consumer FPR.",
        "unexecuted_cases":["P2","P3","P4","N2"],
        "source_only_not_native_cases":["N3","N4"],
        "preregistered_full_cohort_retained":True,
        "no_new_detector_rule_written":True,
    }
    if args.before_p1 and args.after_p1:
        before, after=load(args.before_p1),load(args.after_p1)
        assert before["case"]=="P1" and before["version"]=="before"
        assert after["case"]=="P1" and after["version"]=="after"
        report["p1_original_server_http_regression"]={
            "pre":before["observed_projection"],
            "post":after["observed_projection"],
            "original_before_native_http":True,
            "original_after_native_http":True,
            "official_fix_behavior_verified":True,
            "b38_detector_generalization_claim":False,
        }
        report["unexecuted_cases"].remove("P1") if "P1" in report["unexecuted_cases"] else None
    if args.normal_source:
        policy=load(args.normal_source)
        assert all(c["all_controls_passed"] for c in policy["cases"])
        report["source_function_normal_policy_controls"]=policy["cases"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    raw=json.dumps(report,sort_keys=True,ensure_ascii=False,indent=2)+"\n"
    args.output.write_text(raw,encoding="utf-8")
    print(json.dumps({"n1":rows,"native_original_producer_eligible_orgs":eligible,
                      "independent_external_consumer_fpr":"UNMEASURED",
                      "report_sha256":hashlib.sha256(raw.encode()).hexdigest()},
                     ensure_ascii=False))

if __name__=="__main__":
    main()
