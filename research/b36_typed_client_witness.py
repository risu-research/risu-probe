#!/usr/bin/env python3
"""B36 controlled end-to-end: static source hypothesis vs actual MCP stdio effect.

Controlled first-party test, not independent upstream runtime evidence. The
static detector is imported from a PRE-EXISTING immutable B34 code snapshot.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import sys

from mcp import Client, StdioServerParameters

HERE=Path(__file__).resolve().parent
SERVER=HERE/"b36_native_stdio_server.py"


async def lossy_consumer(client):
    """Intentionally wrong, but real Client -> real MCP stdio call."""
    result=await client.call_tool("rich_result",{})
    return result.content[0]


async def preserving_consumer(client):
    """Normal control: pass through the complete MCP result unmodified."""
    result=await client.call_tool("rich_result",{})
    return result


async def main():
    if len(sys.argv)!=2:
        raise RuntimeError("B36_NEEDS_FROZEN_B34_MODULE_DIRECTORY")
    root=Path(sys.argv[1]).resolve()
    candidate=root/"research"/"b34_channel_projection.py"
    if not candidate.is_file():
        raise RuntimeError("B36_FROZEN_ALGORITHM_MISSING")
    sys.path.insert(0,str(root/"research"))
    from b34_channel_projection import analyze_source
    source=Path(__file__).read_text(encoding="utf-8")
    static=analyze_source(source,"b36_typed_client_witness.py")
    bad=[f for f in static["findings"] if f["function"]=="lossy_consumer"]
    good=[f for f in static["findings"] if f["function"]=="preserving_consumer"]
    if not any(f["rule_id"]=="RSEM102" for f in bad):
        raise RuntimeError("B36_STATIC_DETECTOR_DID_NOT_FIND_FIRST_ONLY")
    if good:
        raise RuntimeError("B36_STATIC_DETECTOR_FALSE_ALARM_ON_PASS_THROUGH")
    client_parameters=StdioServerParameters(
        command=sys.executable,args=[str(SERVER)]
    )
    async with Client(client_parameters,mode="legacy") as client:
        result=await client.call_tool("rich_result",{})
        bad_value=await lossy_consumer(client)
        good_value=await preserving_consumer(client)
        if len(result.content)!=3 or result.structured_content!={
            "item_id":"B36-CONTROL","quantity":17
        }:
            raise RuntimeError("B36_REAL_STDIO_CONTROL_ORIGINAL_RESULT_INCOMPLETE")
        if bad_value!=result.content[0]:
            raise RuntimeError("B36_REAL_STDIO_INTENTIONAL_FIRST_ONLY_CHANGED")
        if len(good_value.content)!=3 or good_value.structured_content!=result.structured_content:
            raise RuntimeError("B36_REAL_STDIO_NORMAL_PASS_THROUGH_FAILED")
    record={
      "schema":"risu-b36-static-source-to-native-stdio-controlled-effect-v1",
      "kind":"CONTROLLED_FIRST_PARTY_PRODUCER_AND_CONSUMER",
      "native_real_stdio":True,
      "original_third_party_upstream_runtime":False,
      "frozen_detector_git_source_blob":"79c8b45901766179c7e39b17969c726a276e543d",
      "frozen_detector_source_sha256":hashlib.sha256(candidate.read_bytes()).hexdigest(),
      "controlled_client_sha256":hashlib.sha256(source.encode()).hexdigest(),
      "controlled_server_sha256":hashlib.sha256(SERVER.read_bytes()).hexdigest(),
      "static_source_hypotheses_for_real_lossy_consumer":bad,
      "static_source_hypotheses_for_real_normal_consumer":good,
      "real_mcp_original_content_blocks":len(result.content),
      "real_mcp_original_structured_content":result.structured_content,
      "real_mcp_first_only_returned_block_type":bad_value.type,
      "real_mcp_first_only_lost_block_count":len(result.content)-1,
      "real_mcp_first_only_lost_structured_channel":True,
      "real_mcp_normal_control_lost_anything":False,
      "no_unseen_external_issues_claimed":True,
      "no_population_false_positive_rate_claim":True,
    }
    out=HERE/"out"
    out.mkdir(exist_ok=True)
    path=out/"B36_STATIC_TO_NATIVE_STDIO_CONTROLLED_EFFECT.json"
    path.write_text(json.dumps(record,indent=2,sort_keys=True,ensure_ascii=False)+"\n")
    print(json.dumps({
      "static_positive_rule_ids":[f["rule_id"] for f in bad],
      "normal_static_candidates":len(good),
      "original_content_blocks":len(result.content),
      "intentional_loss_count":len(result.content)-1,
      "normal_control_ok":True
    },sort_keys=True))
    print("B36_STATIC_HYPOTHESIS_TO_NATIVE_STDIO_CONTROLLED_EFFECT_PASS")


if __name__=="__main__":
    asyncio.run(main())
