#!/usr/bin/env python3
"""P6-B38 opt-in, source-independent native MCP wire-to-consumer contract auditor.

Research-only. Input: original JSON-RPC request/response and an explicitly
recorded consumer observation plus a preregistered channel contract. Never
runs or imports target code, phones home, loads credentials or infers intent.
Each finding requires positive observations; an absent observation is
INCOMPLETE, never a confirmed information-loss bug.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


class IncompleteEvidence(ValueError):
    """Missing/unreliable original evidence; never score as correct or wrong."""


def _must(cond: bool, reason: str) -> None:
    if not cond:
        raise IncompleteEvidence("B38_INCOMPLETE_" + reason)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _text(content: list) -> str:
    return "\n".join(
        x["text"] for x in content if isinstance(x, dict)
        and x.get("type") == "text" and isinstance(x.get("text"), str)
    )


def _media_hashes(content: list) -> list:
    hashes=[]
    for x in content:
        if not isinstance(x, dict):
            raise IncompleteEvidence("B38_INCOMPLETE_CONTENT_BLOCK_NOT_OBJECT")
        if x.get("type") in ("image", "audio"):
            _must(isinstance(x.get("data"),str),
                  "MISSING_ORIGINAL_INLINE_MEDIA_DATA")
            # Compare original encoded base64 representation. Do not copy
            # pictures or audio into the resulting small audit report.
            hashes.append({"type":x["type"],"base64_sha256":
                           digest(x["data"].encode("ascii"))})
    return hashes


def evaluate(wire: dict, observation: dict, contract: dict) -> dict:
    """Require native request ID, call name, mode and explicit observed fields.

    Contract must be independent of detector output. Modes:
      text: "none" | "exact"
      structured: "none" | "exact"
      media: "none" | "exact"
      status: true (required)
    "none" explicitly means NOT under test, never a clean channel score.
    """
    req=wire.get("request")
    resp=wire.get("response")
    _must(isinstance(req,dict) and isinstance(resp,dict),"WIRE_PAIR_MISSING")
    _must(req.get("jsonrpc")=="2.0" and req.get("method")=="tools/call",
          "NOT_NATIVE_TOOL_CALL")
    _must(type(req.get("id")) in (int,str),"MISSING_REQUEST_ID")
    _must(resp.get("jsonrpc")=="2.0" and resp.get("id")==req["id"],
          "ID_MISMATCH")
    _must(isinstance(req.get("params"),dict)
          and isinstance(req["params"].get("name"),str)
          and req["params"]["name"],"MISSING_NATIVE_TOOL_NAME")
    _must(isinstance(observation,dict),"OBSERVATION_MISSING")
    _must(isinstance(contract,dict) and contract.get("status") is True,
          "MISSING_EXPLICIT_STATUS_CONTRACT")
    tool=req["params"]["name"]
    if "tool" in observation:
        _must(observation["tool"]==tool,"OBSERVED_TOOL_IDENTITY_MISMATCH")
    if "request_id" in observation:
        _must(observation["request_id"]==req["id"],
              "OBSERVED_REQUEST_IDENTITY_MISMATCH")
    modes={k:contract.get(k,"none") for k in ("text","structured","media")}
    _must(all(v in ("exact","none") for v in modes.values()),
          "UNSUPPORTED_CONTRACT_MODE")
    observed_outcome=observation.get("outcome")
    _must(observed_outcome in ("success","tool_error","jsonrpc_error"),
          "MISSING_OBSERVED_OUTCOME")
    findings=[]
    checks={}
    if "error" in resp:
        err=resp["error"]
        _must(isinstance(err,dict)
              and type(err.get("code")) is int
              and isinstance(err.get("message"),str),
              "BAD_JSONRPC_ERROR")
        checks["native_kind"]="jsonrpc_error"
        if observed_outcome!="jsonrpc_error":
            findings.append("JSONRPC_ERROR_MISCLASSIFIED")
        else:
            _must(isinstance(observation.get("error_text"),str),
                  "JSONRPC_ERROR_TEXT_NOT_OBSERVED")
            if err["message"] not in observation["error_text"]:
                findings.append("JSONRPC_ERROR_REASON_LOST")
        # Application-level content is not present in a JSON-RPC error.
        return {
          "tool":tool,"request_id":req["id"],"native_kind":"jsonrpc_error",
          "classification":"DISCREPANCY" if findings else "OBSERVED_CONTRACT_PRESERVED",
          "findings":findings,"channels_tested":["status"],
          "contract":contract,"checks":checks,
          "original_upstream_executed":None,
        }
    result=resp.get("result")
    _must(isinstance(result,dict),"MCP_RESULT_MISSING")
    content=result.get("content")
    _must(isinstance(content,list),"MCP_CONTENT_MISSING_OR_NONLIST")
    _must(all(isinstance(x,dict) for x in content),"MCP_CONTENT_ITEM_NOT_DICT")
    native_error=result.get("isError",False)
    _must(type(native_error) is bool,"NON_BOOLEAN_IS_ERROR")
    native_kind="tool_error" if native_error else "success"
    checks["native_kind"]=native_kind
    if observed_outcome!=native_kind:
        findings.append("APPLICATION_ERROR_AS_SUCCESS" if
                        native_kind=="tool_error" and observed_outcome=="success"
                        else "MCP_STATUS_MISCLASSIFIED")
    channels_tested=["status"]
    if modes["text"]=="exact":
        channels_tested.append("text")
        native=_text(content)
        _must("text" in observation
              and isinstance(observation["text"],str),
              "TEXT_PROJECTION_UNOBSERVED")
        checks["native_text_sha256"]=digest(native.encode("utf-8"))
        checks["observed_text_sha256"]=digest(observation["text"].encode("utf-8"))
        if native!=observation["text"]:
            findings.append("MCP_TEXT_CHANGED")
    if modes["structured"]=="exact":
        channels_tested.append("structured")
        _must("structuredContent" in result
              and isinstance(result["structuredContent"],dict),
              "ORIGINAL_STRUCTURED_CHANNEL_UNAVAILABLE")
        _must("structured" in observation,
              "STRUCTURED_CONSUMER_OUTCOME_UNOBSERVED")
        st=observation["structured"]
        _must(st is None or isinstance(st,dict),"BAD_CONSUMER_STRUCTURED_RESULT")
        checks["native_structured_sha256"]=digest(
            json.dumps(result["structuredContent"],sort_keys=True).encode())
        if st!=result["structuredContent"]:
            findings.append("MCP_STRUCTURED_CONTENT_LOST_OR_CHANGED")
    if modes["media"]=="exact":
        channels_tested.append("media")
        native_media=_media_hashes(content)
        _must(native_media,"NO_ORIGINAL_MEDIA_TO_COMPARE")
        _must("media" in observation and isinstance(observation["media"],list),
              "MEDIA_CONSUMER_RESULT_UNOBSERVED")
        checks["native_media_count"]=len(native_media)
        if observation["media"]!=native_media:
            findings.append("MCP_MEDIA_LOST_OR_CHANGED")
    return {
        "tool":tool,"request_id":req["id"],"native_kind":native_kind,
        "classification":"DISCREPANCY" if findings else "OBSERVED_CONTRACT_PRESERVED",
        "findings":findings,"channels_tested":channels_tested,
        "contract":contract,"checks":checks,
        "original_upstream_executed":None,
    }


def audit_record(record:dict) ->dict:
    """One checked record: no implicit pairing between different processes."""
    _must(isinstance(record,dict),"RECORD_NOT_OBJECT")
    _must(isinstance(record.get("wire"),dict),"ORIGINAL_WIRE_MISSING")
    _must(isinstance(record.get("observed"),dict),"OUTCOME_MISSING")
    _must(isinstance(record.get("contract"),dict),"CONTRACT_MISSING")
    r=evaluate(record["wire"],record["observed"],record["contract"])
    declared=record.get("execution_provenance")
    _must(declared in ("ORIGINAL_EXTERNAL_CLIENT_CONTROLLED_SERVER",
                       "ORIGINAL_EXTERNAL_SERVER_CONTROLLED_CLIENT",
                       "CONTROLLED_FIRST_PARTY",
                       "SDK_UNIT_ONLY",
                       "PARSER_ONLY"),
          "EXECUTION_PROVENANCE_UNVERIFIED")
    r["execution_provenance"]=declared
    r["third_party_original_runtime_claim"]=(declared.startswith("ORIGINAL_EXTERNAL"))
    r["source_hash"]=record.get("original_source_git_blob")
    if r["third_party_original_runtime_claim"]:
        _must(isinstance(record.get("original_source_git_blob"),str) and
              len(record["original_source_git_blob"])==40
              and all(c in "0123456789abcdef" for c in record["original_source_git_blob"]),
              "ORIGINAL_SOURCE_GIT_BLOB_MISSING")
        _must(record.get("original_commit_verified") is True,
              "EXTERNAL_ORIGINAL_COMMIT_NOT_VERIFIED")
    r["scope"]="DECLARED_CONSUMER_CHANNELS_ONLY"
    r["native_tool_witness_sha256"]=digest(
        json.dumps(record["wire"],sort_keys=True,separators=(",",":")).encode())
    r["no_population_false_positive_rate_claim"]=True
    return r


def main():
    p=argparse.ArgumentParser(description="Research-only original MCP consumer contract verifier")
    p.add_argument("input",help="JSON file with {wire, observed, contract, execution_provenance}")
    p.add_argument("--output")
    args=p.parse_args()
    src=Path(args.input)
    if not src.is_file() or src.is_symlink() or src.stat().st_size>4*1024*1024:
        raise SystemExit("B38_REFUSED_MISSING_SYMLINK_OR_OVERSIZE_INPUT")
    try:
        out=audit_record(json.loads(src.read_text(encoding="utf-8")))
    except (IncompleteEvidence,ValueError,UnicodeError) as exc:
        out={"schema":"risu-b38-contract-auditor-v1","classification":"INCOMPLETE",
             "reason":str(exc),"no_success_or_failure_claim":True}
    out["schema"]="risu-b38-contract-auditor-v1"
    raw=json.dumps(out,sort_keys=True,indent=2,ensure_ascii=False)+"\n"
    if args.output:
        Path(args.output).write_text(raw,encoding="utf-8")
    print(raw)


if __name__=="__main__":
    main()
