#!/usr/bin/env python3
"""B42 source-independent original-client status scorer, frozen B38 unchanged."""
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path

EXPECTED={
  "N1":("modelcontextprotocol/go-sdk","0fa5e8407aa3fda65166e4207156c03d084bfd44","7894dd0eee3e18bed7137ed88c9b5016ccc90a74"),
  "N2":("PrefectHQ/fastmcp","a8745d61e650467756bb28b4157822dbfbdfa34f","99cfd750f5a3f76f5fbb3c917850ac4e27345b43")
}
def wilson(k,n,z=1.96):
 if not n:return None
 p=k/n
 d=1+z*z/n
 m=(p+z*z/(2*n))/d
 e=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
 return [round(max(0,m-e),6),round(min(1,m+e),6)]

def main():
 p=argparse.ArgumentParser()
 p.add_argument("--case",required=True,choices=tuple(EXPECTED))
 p.add_argument("--input",required=True,type=Path)
 p.add_argument("--checker",required=True,type=Path)
 p.add_argument("--output",required=True,type=Path)
 a=p.parse_args()
 spec=importlib.util.spec_from_file_location("frozen_b38_b42",a.checker)
 checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
 witness=json.loads(a.input.read_text())
 repo,commit,blob=EXPECTED[a.case]
 assert witness["original_repo"]==repo and witness["original_commit"]==commit
 assert witness["original_client_source_unchanged"] is True
 cases=witness["witnesses"]
 assert len(cases)==2
 expected_names={"b42_success","b42_denied"}
 assert {r["tool"] for r in cases}==expected_names
 scores=[]
 for r in cases:
  assert r["case_id"]==a.case and r["original_source_git_blob"]==blob
  assert r["execution_provenance"]=="ORIGINAL_EXTERNAL_CLIENT_CONTROLLED_SERVER"
  assert r["contract"]=={"status":True,"text":"none","structured":"none","media":"none"}
  try:
   score=checker.audit_record(r)
  except checker.IncompleteEvidence as exc:
   score={"classification":"INCOMPLETE","reason":str(exc),"no_success_or_failure_claim":True}
  scores.append({"tool":r["tool"],"original_observed_status":r["observed"]["outcome"],"score":score})
 eligible=all(x["score"]["classification"]!="INCOMPLETE" for x in scores)
 false=any(x["score"]["classification"]=="DISCREPANCY" for x in scores) if eligible else None
 result={
   "schema":"risu-p6b42-original-native-status-fpr-v1",
   "source_organization":repo,
   "original_commit":commit,
   "frozen_b38_original_commit":"425d3d8272c4e725064010ed8fbf5b8217080cab",
   "frozen_b38_source_blob":"67bbb607d277dda3a1ead60a2ccd9ba807afd7ae",
   "frozen_b38_modified":False,
   "original_client_source_modified":False,
   "source_tier":"ORIGINAL_CLIENT_NATIVE_JSONRPC_WITH_LOCAL_PEER",
   "eligible_status_original_client_organization":eligible,
   "normal_organizations_eligible":int(eligible),
   "false_alarm_organizations":int(false) if eligible else None,
   "wilson_95_descriptive_only":wilson(int(false),1) if eligible else None,
   "independently_authored_organization_count":1,
   "native_call_count":len(cases),
   "cases":scores,
   "does_not_estimate_ecosystem_FPR":True,
 }
 raw=json.dumps(result,sort_keys=True,indent=2)+"\n"
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(raw)
 print("B42_NATIVE_ORIGINAL_FPR",a.case,"eligible",eligible,"false_alarm",false,"sha256",hashlib.sha256(raw.encode()).hexdigest())

if __name__=="__main__":main()
