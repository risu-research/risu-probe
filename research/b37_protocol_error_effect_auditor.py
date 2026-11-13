#!/usr/bin/env python3
"""B37 generic provenance-scoped MCP *application error status* wire auditor.

Audit a native JSON-RPC tool result and the observed consumer response from a
controlled execution. No application imports, no LLM inference, no network.
Read-only after collection. SHA-256 ensures internal artifact consistency,
not independent attestation or a trustworthy remote witness.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any

EXPECTED_METHOD="tools/call"


class EvidenceIncomplete(ValueError):
    pass


def require(condition: bool,reason: str) -> None:
    if not condition:
        raise EvidenceIncomplete("MCP_B37_EVIDENCE_INCOMPLETE_"+reason)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def classify_tool_wire(wire: dict[str, Any],tool_name: str,
                       observed: dict[str, Any]) -> str:
    """Classify actual wire outcome against recorded consumer observation.

    Evidence is explicit: this function does not infer what *should* have
    happened from an upstream issue label or source text.
    """
    req=wire.get("request")
    resp=wire.get("response")
    require(isinstance(req,dict) and isinstance(resp,dict),"MISSING_ORIGINAL_PAIR")
    require(req.get("jsonrpc")=="2.0" and req.get("method")==EXPECTED_METHOD,
            "NOT_ORIGINAL_TOOLS_CALL")
    require(isinstance(req.get("id"),(int,str)),"INVALID_REQUEST_ID")
    require(resp.get("jsonrpc")=="2.0" and resp.get("id")==req.get("id"),
            "NO_MATCHING_RESPONSE_ID")
    require(isinstance(req.get("params"),dict) and
            req["params"].get("name")==tool_name,
            "TOOL_IDENTITY_MISMATCH")
    require(isinstance(observed,dict),"MISSING_CONSUMER_OBSERVATION")
    outcome=observed.get("outcome")
    require(outcome in ("success","mcp_tool_error"),"UNKNOWN_CONSUMER_OUTCOME")
    if "error" in resp:
        err=resp["error"]
        require(isinstance(err,dict) and isinstance(err.get("code"),int)
                and isinstance(err.get("message"),str),
                "INVALID_JSONRPC_ERROR_ENVELOPE")
        if outcome=="mcp_tool_error":
            require(err["message"] in str(observed.get("message","")),
                    "JSONRPC_ERROR_MESSAGE_NOT_OBSERVED")
            return "JSONRPC_ERROR_PRESERVED"
        return "JSONRPC_ERROR_AS_SUCCESS"
    result=resp.get("result")
    require(isinstance(result,dict),"MISSING_MCP_CALL_TOOL_RESULT")
    content=result.get("content")
    require(isinstance(content,list),"MALFORMED_MCP_CONTENT")
    err=result.get("isError",False)
    require(type(err) is bool,"NON_BOOLEAN_ISERROR")
    if err:
        if outcome=="success":
            text_content="\n".join(x["text"] for x in content
                                   if isinstance(x,dict) and x.get("type")=="text"
                                   and isinstance(x.get("text"),str))
            require(observed.get("value")==text_content,
                    "ERROR_CONTENT_PROJECTION_NOT_GROUNDED")
            return "APPLICATION_ERROR_AS_SUCCESS_CONFIRMED_IN_CONTROLLED_RUN"
        message=observed.get("message")
        require(isinstance(message,str) and bool(message),
                "MISSING_OBSERVED_ERROR_REASON")
        native_text=[x.get("text") for x in content
                     if isinstance(x,dict) and x.get("type")=="text"
                     and isinstance(x.get("text"),str)]
        if native_text:
            require(any(item in message for item in native_text),
                    "APPLICATION_ERROR_REASON_NOT_PRESERVED")
        return "APPLICATION_ERROR_PROPAGATED"
    if outcome=="mcp_tool_error":
        return "NONERROR_MISCLASSIFIED_AS_ERROR"
    if result.get("structuredContent") is not None:
        return "SUCCESS_STATUS_PRESERVED_OTHER_CHANNELS_UNASSESSED"
    return "NORMAL_SUCCESS_PRESERVED_STATUS"


def audit_collected_execution(record: dict, original_wire: dict[str,bytes]) -> dict:
    """Pair every actual call with exact consumer outcome, reject mismatch."""
    before_after={}
    totals={}
    expectations={
       "normal":"normal",
       "refusal":"refusal",
       "empty_refusal":"empty_refusal",
       "multi":"multi",
       "rpc_error":"rpc_error",
       "normal_again":"normal",
    }
    for side in ("before","after"):
        r=record.get(side)
        require(isinstance(r,dict),"MISSING_SIDE_"+side)
        data=original_wire.get(side)
        require(isinstance(data,bytes) and len(data)>0,"MISSING_RAW_NATIVE_WIRE_"+side)
        require(sha(data)==r.get("original_raw_native_wire_sha256"),
                "MISMATCH_ORIGINAL_TRACE_HASH_"+side)
        require(r.get("original_client_imported_and_executed") is True,
                "ORIGINAL_CLIENT_EXECUTION_NOT_DECLARED_"+side)
        require(len(str(r.get("upstream_original_source_git_blob","")))==40,
                "ORIGINAL_SOURCE_GIT_BLOB_MISSING_"+side)
        lines=[json.loads(v) for v in data.decode("utf-8").splitlines()]
        requests=[x for x in lines if
                  isinstance(x,dict) and isinstance(x.get("request"),dict)
                  and x["request"].get("method")==EXPECTED_METHOD]
        require(len(requests)==len(expectations),
                "MISSING_OR_EXTRA_TOOL_CALLS_"+side)
        require(len({x["request"]["id"] for x in requests})==len(expectations),
                "DUPLICATE_REQUEST_ID_"+side)
        observations=r.get("scenario_observations")
        require(isinstance(observations,dict)
                and set(observations)==set(expectations),
                "MISSING_OR_EXTRA_CONSUMER_SCENARIO_"+side)
        events=[]
        for (scenario,tool),pair in zip(expectations.items(),requests):
            verdict=classify_tool_wire(pair,tool,observations[scenario])
            events.append({
              "scenario":scenario,"upstream_original_version":side,
              "request_id":pair["request"]["id"],
              "tool_name":tool,"classification":verdict,
              "original_wire_is_error":pair["response"].get("result",{}).get("isError"),
              "consumer_outcome":observations[scenario]["outcome"],
            })
        before_after[side]={"events":events,
                            "git_blob":r["upstream_original_source_git_blob"],
                            "source_sha256":r.get("upstream_original_source_sha256"),
                            "wire_sha256":sha(data)}
        totals[side]={
          "application_errors_as_success":sum(
            x["classification"]=="APPLICATION_ERROR_AS_SUCCESS_CONFIRMED_IN_CONTROLLED_RUN"
            for x in events),
          "application_errors_correctly_propagated":sum(
            x["classification"]=="APPLICATION_ERROR_PROPAGATED"
            for x in events),
          "normal_successes":sum(
            x["classification"]=="NORMAL_SUCCESS_PRESERVED_STATUS"
            for x in events),
          "jsonrpc_errors_preserved":sum(
            x["classification"]=="JSONRPC_ERROR_PRESERVED"
            for x in events),
        }
    require(totals["before"]["application_errors_as_success"]==2,
            "ORIGINAL_FALSE_SUCCESSES_NOT_GROUNDED")
    require(totals["after"]["application_errors_as_success"]==0,
            "FIXED_FALSE_SUCCESSES_STILL_PRESENT")
    require(totals["after"]["application_errors_correctly_propagated"]==2,
            "FIXED_ERROR_PROPAGATION_NOT_GROUNDED")
    require(totals["before"]["normal_successes"]==3
            and totals["after"]["normal_successes"]==3,
            "NORMAL_CONTROL_REGRESSION")
    require(totals["before"]["jsonrpc_errors_preserved"]==1
            and totals["after"]["jsonrpc_errors_preserved"]==1,
            "JSONRPC_ERROR_CONTROL_REGRESSION")
    return {
       "schema":"risu-b37-independent-of-source-static-native-error-auditor-v1",
       "evidence_class":"ORIGINAL_EXTERNAL_CLIENT_CODE_PLUS_CONTROLLED_FIRST_PARTY_SERVER",
       "first_look_static_B37_result":"MISSED",
       "original_source_provenance":"pinned before-after Git commits and blobs verified in collector",
       "wire_pair_integrity":"sha256 plus matching JSON-RPC IDs and tool names",
       "independent_remote_execution_attested":False,
       "user_authority_attested":False,
       "signed_execution_attested":False,
       "original_external_MCP_server_executed":False,
       "source_algorithm_source_inspection_required":False,
       "false_positive_population_rate":"UNMEASURED",
       "totals":totals,"before_after":before_after,
    }


def main():
    folder=Path(__file__).resolve().parent/"out"
    file=folder/"B37_ORIGINAL_KITAGENT_NATIVE_BEFORE_AFTER.json"
    record=json.loads(file.read_text(encoding="utf-8"))
    data={
       "before":(folder/"KITAGENT_BEFORE_ORIGINAL_STDIO.jsonl").read_bytes(),
       "after":(folder/"KITAGENT_AFTER_ORIGINAL_STDIO.jsonl").read_bytes(),
    }
    proof=audit_collected_execution(record,data)
    output=folder/"B37_RUNTIME_ERROR_SEMANTICS_AUDIT.json"
    output.write_text(json.dumps(proof,sort_keys=True,indent=2,ensure_ascii=False)+"\n",
                      encoding="utf-8")
    print(json.dumps(proof["totals"],sort_keys=True))
    print("B37_RUNTIME_ERROR_SEMANTICS_EVIDENCE_VERIFIED")
    print("B37_RUNTIME_AUDIT_SHA256="+sha(output.read_bytes()))


if __name__=="__main__":
    main()
