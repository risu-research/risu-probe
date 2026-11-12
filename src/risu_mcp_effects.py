"""RISU P6-B20: tool-neutral, bounded, offline MCP effect-difference verifier.

Models a pair of versions crossed with trigger and control conditions.
Each state sensor is measured outside the MCP response and anchored by a
typed JSON pointer into its ORIGINAL observer record. The engine compares
the four effect transitions without knowledge of Git, filesystem, SQLite,
or vulnerability classes. It never runs targets, connects to the network,
or grants normative permission based on MCP readOnlyHint.

Not a remote sensor attestation, source-to-binary proof or automatic
unknown-vulnerability detector. Original sensor trust must be independently
established by the caller/CI.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

from risu_mcp_authority import correlate
from risu_mcp_trace import _read_trace, TraceError

PLAN = "risu-mcp-effect-matrix-plan-v1"
EPISODE = "risu-mcp-effect-episode-v1"
REPORT = "risu-mcp-effect-matrix-report-v1"
MAX_JSON = 131072
MAX_FILE = 4*1024*1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
KINDS = {"boolean", "counter", "digest"}
PATTERNS = {
    "suppressed-in-after-with-controls-stable": (True,False,False,False),
    "preserved-in-both-trigger-cases": (True,False,True,False),
    "no-effect-in-any-case": (False,False,False,False),
    "custom": None,
}
CELLS = ("before_trigger","before_control","after_trigger","after_control")


class EffectError(ValueError): pass


def ensure(cond, reason):
    if not cond:raise EffectError(reason)


def pairs_unique(items):
    value={}
    for key,entry in items:
        if key in value:raise EffectError("DUPLICATE_JSON_FIELD")
        value[key]=entry
    return value


def load_json(file):
    ensure(not file.is_symlink() and file.is_file() and
           0<file.stat().st_size<=MAX_JSON,"MISSING_OR_OVERSIZED_EVIDENCE")
    try:
        return json.loads(file.read_text("utf-8"),object_pairs_hook=pairs_unique,
                          parse_constant=lambda x:(_ for _ in ()).throw(EffectError("NONFINITE_NUMBER")))
    except (OSError,UnicodeError,json.JSONDecodeError,RecursionError) as exc:
        raise EffectError("INVALID_EVIDENCE_JSON") from exc


def canonical(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,
         separators=(",",":"),allow_nan=False).encode("utf-8")


def sha(value):
    return hashlib.sha256(value).hexdigest()


def relative(root,rel):
    ensure(type(rel) is str and len(rel)<=240 and '\\' not in rel and
           not rel.startswith('/'),"UNSAFE_EVIDENCE_RELATIVE_PATH")
    parts=PurePosixPath(rel).parts
    ensure(0<len(parts)<=16 and all(p not in ('.','..') for p in parts),
           "UNSAFE_EVIDENCE_RELATIVE_PATH")
    absolute=root.joinpath(*parts)
    ensure(not absolute.is_symlink() and absolute.is_file(),
           "MISSING_OR_SYMLINKED_EVIDENCE_FILE")
    resolved=absolute.resolve()
    ensure(resolved.is_relative_to(root),"EVIDENCE_ESCAPE_FROM_ROOT")
    ensure(absolute.stat().st_size<=MAX_FILE,"OVERSIZED_EVIDENCE_FILE")
    return absolute


def pointer(doc,path):
    ensure(type(path) is str and path.startswith('/') and
           len(path)<=256,"INVALID_EVIDENCE_JSON_POINTER")
    current=doc
    for item in path.split('/')[1:]:
        item=item.replace('~1','/').replace('~0','~')
        ensure(item!="", "EMPTY_JSON_POINTER_COMPONENT")
        if type(current) is dict:
            ensure(item in current,"EVIDENCE_JSON_POINTER_MISSING")
            current=current[item]
        elif type(current) is list:
            ensure(item.isdigit() and str(int(item))==item
                   and int(item)<len(current),"INVALID_ARRAY_POINTER_INDEX")
            current=current[int(item)]
        else:raise EffectError("EVIDENCE_POINTER_NOT_CONTAINED")
    return current


def validate_plan(doc):
    ensure(type(doc) is dict and doc.get("schema")==PLAN,"BAD_EFFECT_PLAN_SCHEMA")
    ensure(set(doc)=={"schema","experiment","classification","tool","cells","sensors"},
           "UNKNOWN_OR_MISSING_EFFECT_PLAN_FIELDS")
    ensure(type(doc["experiment"]) is str and 1<=len(doc["experiment"])<=120,
           "INVALID_EXPERIMENT_NAME")
    ensure(doc["classification"] in
           ("DEVELOPMENT_POSITIVE_CONTROL","HELDOUT_NORMAL_CONTROL",
            "HELDOUT_EXTERNAL_BEFORE_AFTER"),"INVALID_DATASET_ROLE")
    ensure(type(doc["tool"]) is str and 1<=len(doc["tool"])<=128,
           "INVALID_PRESELECTED_TOOL")
    cells=doc["cells"]
    ensure(type(cells) is dict and set(cells)==set(CELLS),"INCOMPLETE_OR_DUPLICATED_2X2_MATRIX")
    for cell in CELLS:
        row=cells[cell]
        ensure(type(row) is dict and set(row)=={"trace","episode"},
               "MALFORMED_PRELOCKED_CELL")
        for name in ("trace","episode"):
            ensure(type(row[name]) is str and len(row[name])<=240,
                   "INVALID_CELL_FILE_REFERENCE")
    sensors=doc["sensors"]
    ensure(type(sensors) is list and 1<=len(sensors)<=12,
           "INVALID_EFFECT_SENSOR_DECLARATION_SIZE")
    ids=set()
    for item in sensors:
        ensure(type(item) is dict and set(item)=={"id","kind","pattern","expected"},
               "INVALID_EFFECT_SENSOR_DECLARATION")
        id_=item["id"]
        ensure(type(id_) is str and 1<=len(id_)<=100 and id_ not in ids,
               "DUPLICATE_OR_INVALID_EFFECT_SENSOR_ID")
        ids.add(id_)
        ensure(item["kind"] in KINDS and item["pattern"] in PATTERNS,
               "UNSUPPORTED_SENSOR_KIND_OR_PATTERN")
        if item["pattern"]=="custom":
            ensure(type(item["expected"]) is dict and
                   set(item["expected"])==set(CELLS) and
                   all(type(v) is bool for v in item["expected"].values()),
                   "MISSING_CUSTOM_EFFECT_TRUTH_TABLE")
        else:ensure(item["expected"] is None,"NONCUSTOM_EXPECTATION_NOT_NULL")
    return doc


def snapshot_type(value,kind):
    if kind=="boolean":return type(value) is bool
    if kind=="counter":return type(value) is int and 0<=value<=2**53
    if kind=="digest":return value is None or (type(value) is str and
                                    bool(HEX.fullmatch(value)))
    return False


def sensor_delta(before,after,kind):
    if kind=="boolean":return before!=after
    if kind=="counter":return before!=after
    if kind=="digest":return before!=after
    raise EffectError("INVALID_SENSOR_KIND")


def judge(root,plan):
    root=root.resolve(strict=True)
    validate_plan(plan)
    declarations={item["id"]:item for item in plan["sensors"]}
    results={}
    external_paths={}
    for cell in CELLS:
        row=plan["cells"][cell]
        trace=relative(root,row["trace"])
        episode_file=relative(root,row["episode"])
        episode=load_json(episode_file)
        ensure(type(episode) is dict and episode.get("schema")==EPISODE and
               set(episode)=={"schema","case","trace_sha256","call","sensors",
                             "observer_trust_scope"},"BAD_OR_EXTRA_EPISODE_FIELDS")
        ensure(episode["case"]==cell and
               episode["observer_trust_scope"] in (
                   "CI_OBSERVED_NOT_REMOTELY_ATTESTED",
                   "DECLARED_LOCAL_OBSERVATION"),
               "EPISODE_CASE_OR_OBSERVER_SCOPE")
        records,original_hash=_read_trace(trace)
        ensure(episode["trace_sha256"]==original_hash,
               "TRUSTED_RAW_MCP_HASH_MISMATCH")
        calls,anomalies=correlate(records)
        ensure(len(calls)==1 and not anomalies,
               "MCP_CALL_OR_CATALOG_INCOMPLETE_OR_AMBIGUOUS")
        call=calls[0]
        expected_call=episode["call"]
        ensure(type(expected_call) is dict and
               set(expected_call)=={"tool","arguments_sha256","result_sha256",
                                    "request_line","response_line"},
               "INVALID_EPISODE_MCP_BINDING")
        ensure(call["name"]==plan["tool"]==expected_call["tool"] and
               call["request_line"]==expected_call["request_line"] and
               call["response_line"]==expected_call["response_line"] and
               call["snapshot"] is not None and
               call["name"] in call["snapshot"]["tools"],
               "MCP_TOOL_OR_CATALOG_CORRELATION_INVALID")
        ensure(type(call["args"]) is dict and
               expected_call["arguments_sha256"]==sha(canonical(call["args"])),
               "MCP_CALL_ARGUMENTS_NOT_BOUND_TO_ORIGINAL_EVIDENCE")
        response=call["response"]
        ensure(not call["jsonrpc_error"] and type(response) is dict and
               response.get("isError") is not True,
               "ORIGINAL_MCP_TOOL_FAILED_OR_JSONRPC_ERROR")
        result_hash=sha(canonical(response))
        ensure(result_hash==expected_call["result_sha256"],
               "MCP_RESULT_HASH_NOT_BOUND_TO_CAPTURE")
        observations=episode["sensors"]
        ensure(type(observations) is list and len(observations)==len(declarations),
               "MISSING_EFFECT_OBSERVATIONS")
        measured={}
        for sensor in observations:
            ensure(type(sensor) is dict and
                   set(sensor)=={"id","kind","before","after","original_observer"},
                   "INVALID_SENSOR_EVIDENCE_SHAPE")
            id_=sensor["id"]
            ensure(id_ in declarations and id_ not in measured and
                   sensor["kind"]==declarations[id_]["kind"],
                   "SENSOR_DUPLICATE_OR_TYPE_CONFLICT")
            kind=sensor["kind"]
            before,after=sensor["before"],sensor["after"]
            ensure(snapshot_type(before,kind) and snapshot_type(after,kind),
                   "SENSOR_INVALID_TYPED_STATE")
            source=sensor["original_observer"]
            ensure(type(source) is dict and set(source)=={
                "file","sha256","before_pointer","after_pointer"},
                "MISSING_ORIGINAL_INDEPENDENT_SENSOR_RECORD")
            original=relative(root,source["file"])
            ensure(type(source["sha256"]) is str and
                   bool(HEX.fullmatch(source["sha256"])) and
                   sha(original.read_bytes())==source["sha256"],
                   "OBSERVER_SOURCE_FILE_CONTENT_MISMATCH")
            ensure(source["file"] not in external_paths or
                   external_paths[source["file"]]==cell,
                   "REUSED_SENSOR_ORIGINAL_ACROSS_EXPERIMENT_CELLS")
            external_paths[source["file"]]=cell
            raw=load_json(original)
            ensure(pointer(raw,source["before_pointer"])==before and
                   type(pointer(raw,source["before_pointer"])) is type(before) and
                   pointer(raw,source["after_pointer"])==after and
                   type(pointer(raw,source["after_pointer"])) is type(after),
                   "INDEPENDENT_ORIGINAL_SENSOR_DOES_NOT_MATCH_DERIVED_STATE")
            measured[id_]={
                "changed":sensor_delta(before,after,kind),
                "before_type":kind,"after_type":kind,
                "original_observer_sha256":source["sha256"]
            }
        ensure(set(measured)==set(declarations),"PARTIAL_SENSOR_COVERAGE")
        results[cell]={
            "trace_sha256":original_hash,
            "tool_result_sha256":result_hash,
            "tool_hash":sha(call["name"].encode())[:16],
            "catalog_sha256":call["snapshot"]["catalog_sha256"],
            "response_status":"SUCCESS",
            "observer_trust_scope":episode["observer_trust_scope"],
            "sensors":measured,
        }
    decisions=[]
    for id_,rule in declarations.items():
        actual={cell:results[cell]["sensors"][id_]["changed"] for cell in CELLS}
        expected=({cell:v for cell,v in zip(CELLS,PATTERNS[rule["pattern"]])}
                  if rule["pattern"]!="custom" else rule["expected"])
        matched=actual==expected
        decisions.append({
            "sensor":id_,
            "kind":rule["kind"],
            "declared_pattern":rule["pattern"],
            "observed_matrix":actual,
            "expected_matrix":expected,
            "matrix_matches_predeclared_pattern":matched,
            "mismatch_cases":[cell for cell in CELLS if actual[cell]!=expected[cell]],
            "effect_suppressed_in_after_trigger":(
                actual["before_trigger"] and not actual["after_trigger"]),
            "controls_unchanged":not actual["before_control"] and not actual["after_control"]
        })
    identical_responses=len({data["tool_result_sha256"]
                         for data in results.values()})==1
    all_patterns=all(item["matrix_matches_predeclared_pattern"] for item in decisions)
    return {
        "schema":REPORT,
        "experiment_id":plan["experiment"],
        "cohort_classification":plan["classification"],
        "experiment_plan_sha256":sha(canonical(plan)),
        "summary":{
            "paired_cells":4,
            "independently_source_bound_sensors":len(declarations),
            "matched_predeclared_effect_patterns":sum(
                x["matrix_matches_predeclared_pattern"] for x in decisions),
            "all_predeclared_patterns_met":all_patterns,
            "all_four_original_mcp_result_bodies_identical":identical_responses,
            "tool_response_only_observability_gap":(
                identical_responses and all_patterns and any(
                    x["effect_suppressed_in_after_trigger"] for x in decisions)),
            "new_upstream_defects_claimed":0
        },
        "decisions":decisions,
        "episodes":{cell:{
            "trace_sha256":value["trace_sha256"],
            "tool_result_sha256":value["tool_result_sha256"],
            "catalog_sha256":value["catalog_sha256"],
            "observation_source_sha256":{
                id_:o["original_observer_sha256"] for id_,o in value["sensors"].items()}}
            for cell,value in results.items()},
        "limitations":[
            "No tool name, repository config key, original vulnerability family or file-path behavior is encoded in this algorithm.",
            "The observer source JSON and captured MCP wire are integrity cross-bound, but their authorship and physical measurement are not cryptographically authenticated by this offline tool.",
            "A matched effect truth table is an observed conditional change, not normative permission or proof of root cause.",
            "The plan is user-declared; only independently verified original publisher releases/advisories can ground a real externally authenticated repair claim.",
            "A developer positive control does not count as held-out discovery and cannot estimate population precision or recall."
        ],
        "status":"EFFECT_PATTERNS_OBSERVED" if all_patterns else "PREDECLARED_EFFECT_PATTERN_MISMATCH"
    }


def cli(argv=None):
    p=argparse.ArgumentParser(prog="risu-probe verify-mcp-effects")
    p.add_argument("--plan",type=Path,required=True)
    p.add_argument("--evidence-root",type=Path,required=True)
    p.add_argument("--format",choices=("json","text"),default="text")
    p.add_argument("--out",type=Path)
    p.add_argument("--fail-on-mismatch",action="store_true")
    args=p.parse_args(argv)
    try:
        report=judge(args.evidence_root,load_json(args.plan))
        output=(json.dumps(report,indent=2,sort_keys=True,ensure_ascii=False)+chr(10)
                if args.format=="json" else
                "RISU generic MCP effect checker | "+report["status"]+chr(10))
        if args.out:
            with args.out.resolve().open("x",encoding="utf-8") as f:f.write(output)
        else:print(output,end="")
        return 1 if args.fail_on_mismatch and not report["summary"]["all_predeclared_patterns_met"] else 0
    except (EffectError,TraceError,ValueError,TypeError,KeyError,OSError,
            UnicodeError,RecursionError) as e:
        print("RME820 EFFECT_OBSERVATION_INCOMPLETE_OR_UNVERIFIED: "+
              type(e).__name__,file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(cli())
