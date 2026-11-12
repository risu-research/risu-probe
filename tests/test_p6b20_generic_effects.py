"""P6-B20 tool-neutral effect matrix adversarial regression.

All generated cases here are synthetic, deliberately *not* a genuine new
external bug. Four real B19 captures and separate native non-Git originals
are qualified through their dedicated workflows.
"""
from __future__ import annotations
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from risu_mcp_effects import (
    judge, canonical, sha, EffectError, PLAN, EPISODE,
    load_json, snapshot_type, sensor_delta
)
from risu_mcp_trace import TraceError

CELLS=("before_trigger","before_control","after_trigger","after_control")


def emit(obj):
    return json.dumps(obj,separators=(",",":"),ensure_ascii=False)+"\n"


class B20GenericEffectTest(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.plan={
            "schema":PLAN,
            "experiment":"opaque-resource-effect-regression",
            "classification":"DEVELOPMENT_POSITIVE_CONTROL",
            "tool":"arbitrary_service_operation",
            "cells":{},
            "sensors":[
                {"id":"effect-exists","kind":"boolean",
                 "pattern":"suppressed-in-after-with-controls-stable",
                 "expected":None},
                {"id":"effect-count","kind":"counter",
                 "pattern":"suppressed-in-after-with-controls-stable",
                 "expected":None},
                {"id":"resource-digest","kind":"digest",
                 "pattern":"suppressed-in-after-with-controls-stable",
                 "expected":None}
            ]
        }
        self.external_files={}
        self.episodes={}
        for cell in CELLS:
            folder=self.root/cell
            folder.mkdir()
            changed=(cell=="before_trigger")
            before={"boolean":False,"counter":0,"digest":None}
            after={"boolean":changed,"counter":1 if changed else 0,
                   "digest":"a"*64 if changed else None}
            observer={
                "snapshot":{
                    "pre_exists":before["boolean"],"post_exists":after["boolean"],
                    "pre_count":before["counter"],"post_count":after["counter"],
                    "pre_sha":before["digest"],"post_sha":after["digest"]
                }}
            (folder/"original_observer.json").write_text(emit(observer))
            original_sha=sha((folder/"original_observer.json").read_bytes())
            wire=[
                {"jsonrpc":"2.0","id":1,"method":"initialize","params":{}},
                {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}},
                {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}},
                {"jsonrpc":"2.0","id":2,"result":{"tools":[{
                    "name":self.plan["tool"],"inputSchema":{"type":"object"}}]}},
                {"jsonrpc":"2.0","id":20,"method":"tools/call","params":{
                    "name":self.plan["tool"],"arguments":{"case_id":cell}}},
                {"jsonrpc":"2.0","id":20,"result":{"isError":False,
                    "content":[{"type":"text","text":"identical result"}]}}
            ]
            (folder/"original_stdio.jsonl").write_text("".join(emit(x) for x in wire))
            episode={"schema":EPISODE,"case":cell,
                "trace_sha256":sha((folder/"original_stdio.jsonl").read_bytes()),
                "call":{"tool":self.plan["tool"],
                    "arguments_sha256":sha(canonical({"case_id":cell})),
                    "result_sha256":sha(canonical(wire[-1]["result"])),
                    "request_line":5,"response_line":6},
                "sensors":[],
                "observer_trust_scope":"DECLARED_LOCAL_OBSERVATION"}
            for id_,kind,pre,post in [
                ("effect-exists","boolean","pre_exists","post_exists"),
                ("effect-count","counter","pre_count","post_count"),
                ("resource-digest","digest","pre_sha","post_sha")
            ]:
                episode["sensors"].append({
                    "id":id_,"kind":kind,
                    "before":before[kind],"after":after[kind],
                    "original_observer":{
                        "file":cell+"/original_observer.json",
                        "sha256":original_sha,
                        "before_pointer":"/snapshot/"+pre,
                        "after_pointer":"/snapshot/"+post
                    }})
            (folder/"episode.json").write_text(emit(episode))
            self.external_files[cell]=folder/"original_observer.json"
            self.episodes[cell]=folder/"episode.json"
            self.plan["cells"][cell]={
                "trace":cell+"/original_stdio.jsonl",
                "episode":cell+"/episode.json"}

    def run_check(self):return judge(self.root,self.plan)
    def reject(self):
        with self.assertRaises((EffectError,TraceError,ValueError,TypeError,KeyError)):
            self.run_check()
    def edit_episode(self,cell,modify):
        path=self.episodes[cell]
        value=json.loads(path.read_text())
        modify(value)
        path.write_text(emit(value))

    def edit_sensor_original(self,cell,modify,update_digest=False):
        p=self.external_files[cell]
        data=json.loads(p.read_text())
        modify(data)
        p.write_text(emit(data))
        if update_digest:
            fresh=sha(p.read_bytes())
            self.edit_episode(cell,lambda e: [
                s["original_observer"].update(sha256=fresh) for s in e["sensors"]])

    def edit_trace(self,cell,modify,update_digest=False):
        path=self.root/cell/"original_stdio.jsonl"
        rows=[json.loads(x) for x in path.read_text().splitlines()]
        rows=modify(rows)
        path.write_text("".join(emit(x) for x in rows))
        if update_digest:
            h=sha(path.read_bytes())
            self.edit_episode(cell,lambda e:e.update(trace_sha256=h))

    def test_generic_three_sensor_kinds_and_exact_response_equivalence(self):
        report=self.run_check()
        self.assertEqual(report["status"],"EFFECT_PATTERNS_OBSERVED")
        self.assertEqual(report["summary"]["matched_predeclared_effect_patterns"],3)
        self.assertTrue(report["summary"]["tool_response_only_observability_gap"])
        self.assertEqual(report["summary"]["new_upstream_defects_claimed"],0)

    def test_no_git_identifiers_in_engine_result(self):
        result=self.run_check()
        encoded=json.dumps(result)
        for k in ("git_status","core.fsmonitor","GHSA-"):
            self.assertNotIn(k,encoded)

    def test_tampered_original_observer_rejected(self):
        self.edit_sensor_original("before_trigger",lambda d:
                                  d["snapshot"].update(post_exists=False))
        self.reject()

    def test_tampered_origin_even_with_updated_hash_rejected(self):
        self.edit_sensor_original("before_trigger",lambda d:
                                  d["snapshot"].update(post_exists=False),True)
        self.reject()

    def test_swapped_observer_across_cases_rejected(self):
        self.edit_episode("after_trigger",lambda d:[
            s["original_observer"].update(
                file="before_trigger/original_observer.json",
                sha256=sha(self.external_files["before_trigger"].read_bytes()))
            for s in d["sensors"]])
        self.reject()

    def test_missing_original_observer_rejected(self):
        self.external_files["before_trigger"].unlink()
        self.reject()

    def test_parent_path_escape_refused(self):
        self.edit_episode("before_trigger",lambda d:
            d["sensors"][0]["original_observer"].update(file="../escape"))
        self.reject()

    def test_sensor_type_conflict_rejected(self):
        self.edit_episode("before_trigger",lambda d:
            d["sensors"][0].update(kind="counter"))
        self.reject()

    def test_bool_as_int_counter_rejected(self):
        self.edit_episode("before_trigger",lambda d:
            d["sensors"][1].update(after=True))
        self.reject()

    def test_negative_counter_rejected(self):
        self.edit_episode("before_trigger",lambda d:
            d["sensors"][1].update(after=-1))
        self.reject()

    def test_dynamic_float_counter_rejected(self):
        self.edit_episode("before_trigger",lambda d:
            d["sensors"][1].update(after=0.5))
        self.reject()

    def test_sha_digest_wrong_length_rejected(self):
        self.edit_episode("before_trigger",lambda d:
            d["sensors"][2].update(after="short"))
        self.reject()

    def test_missing_observer_sensor_rejected(self):
        self.edit_episode("before_trigger",lambda d:d["sensors"].pop())
        self.reject()

    def test_duplicated_observer_sensor_rejected(self):
        self.edit_episode("before_trigger",lambda d:
            d["sensors"].append(copy.deepcopy(d["sensors"][0])))
        self.reject()

    def test_original_mcp_stdout_tamper_rejected(self):
        self.edit_trace("before_trigger",lambda r:r+[
            {"jsonrpc":"2.0","method":"notifications/tools/list_changed"}])
        self.reject()

    def test_original_tools_list_changed_before_call_not_promoted(self):
        self.edit_trace("after_trigger",lambda r:
            r[:4]+[{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}]+r[4:],
            update_digest=True)
        self.reject()

    def test_original_no_catalog_not_promoted(self):
        self.edit_trace("before_trigger",lambda r:r[:2]+r[4:],update_digest=True)
        self.reject()

    def test_original_tool_error_not_accepted_as_success(self):
        self.edit_trace("after_trigger",lambda r:[
            dict(x,**{"result":dict(x["result"],isError=True)})
            if x.get("id")==20 and "result" in x else x for x in r],
            update_digest=True)
        self.reject()

    def test_original_tool_name_changed_rejected(self):
        self.edit_trace("before_trigger",lambda r:[
            dict(x,params=dict(x["params"],name="another_service"))
            if x.get("method")=="tools/call" else x for x in r],update_digest=True)
        self.reject()

    def test_transcript_hash_and_arg_hash_binding(self):
        self.edit_episode("after_trigger",lambda d:
            d["call"].update(arguments_sha256="0"*64))
        self.reject()

    def test_wrong_result_sha_rejected(self):
        self.edit_episode("after_control",lambda d:
            d["call"].update(result_sha256="0"*64))
        self.reject()

    def test_wrong_raw_line_correlation_rejected(self):
        self.edit_episode("before_control",lambda d:
            d["call"].update(request_line=7))
        self.reject()

    def test_contaminated_control_prevents_positive_signal(self):
        self.edit_sensor_original("after_control",lambda d:
            d["snapshot"].update(post_exists=True),True)
        self.edit_episode("after_control",lambda d:
            d["sensors"][0].update(after=True))
        r=self.run_check()
        self.assertFalse(r["summary"]["all_predeclared_patterns_met"])
        self.assertFalse(r["summary"]["tool_response_only_observability_gap"])
        self.assertEqual(r["status"],"PREDECLARED_EFFECT_PATTERN_MISMATCH")

    def test_behaviorally_unrelated_origin_changed_and_response_identical(self):
        self.edit_sensor_original("before_trigger",lambda d:
            d["snapshot"].update(post_exists=False),True)
        self.edit_episode("before_trigger",lambda d:
            d["sensors"][0].update(after=False))
        report=self.run_check()
        self.assertFalse(report["summary"]["all_predeclared_patterns_met"])
        self.assertFalse(report["summary"]["tool_response_only_observability_gap"])

    def test_custom_truth_table_instead_of_hardcoded_fix(self):
        for s in self.plan["sensors"]:
            s["pattern"]="custom"
            s["expected"]={
                "before_trigger":True,"before_control":False,
                "after_trigger":False,"after_control":False}
        self.assertTrue(self.run_check()["summary"]["all_predeclared_patterns_met"])

    def test_preserved_effect_in_both_trigger_cases(self):
        for s in self.plan["sensors"]:
            s["pattern"]="preserved-in-both-trigger-cases"
        self.edit_sensor_original("after_trigger",lambda d:d["snapshot"].update(
            post_exists=True,post_count=1,post_sha="a"*64),True)
        self.edit_episode("after_trigger",lambda d:[
            s.update(after={"boolean":True,"counter":1,"digest":"a"*64}[s["kind"]])
            for s in d["sensors"]])
        self.assertTrue(self.run_check()["summary"]["all_predeclared_patterns_met"])

    def test_no_effect_anywhere(self):
        for s in self.plan["sensors"]:
            s["pattern"]="no-effect-in-any-case"
        self.edit_sensor_original("before_trigger",lambda d:d["snapshot"].update(
            post_exists=False,post_count=0,post_sha=None),True)
        self.edit_episode("before_trigger",lambda d:[
            s.update(after={"boolean":False,"counter":0,"digest":None}[s["kind"]])
            for s in d["sensors"]])
        self.assertTrue(self.run_check()["summary"]["all_predeclared_patterns_met"])

    def test_invalid_dataset_role_not_silently_promoted(self):
        self.plan["classification"]="UNREVIEWED_BUG_DISCOVERY"
        self.reject()

    def test_missing_fourth_case_not_silently_ignored(self):
        self.plan["cells"].pop("after_control")
        self.reject()

    def test_unknown_unbounded_sensor_kind_not_accepted(self):
        self.plan["sensors"][0]["kind"]="eval_code"
        self.reject()

    def test_bad_evidence_json_dup_key(self):
        t=self.external_files["before_trigger"]
        t.write_text('{"snapshot":{},"snapshot":{}}')
        self.reject()

    def test_generic_gauge_support_with_delta(self):
        self.assertTrue(snapshot_type(0,"counter"))
        self.assertFalse(snapshot_type(True,"counter"))
        self.assertTrue(sensor_delta(3,4,"counter"))
        self.assertFalse(sensor_delta(3,3,"counter"))


if __name__=="__main__":
    unittest.main()
