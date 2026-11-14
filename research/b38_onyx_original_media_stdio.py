#!/usr/bin/env python3
"""B38 ORIGINAL Onyx client formatter function via real MCP native stdio.

The exact original process_mcp_result function and its ContentBlockTypes enum
are compiled from pinned upstream Git AST nodes; body UNMODIFIED.
Importing Onyx's entire application would require secrets/databases and is
not attempted. SDK 2.3 field spellings may be adapter-normalized explicitly.
This is an ISOLATED ORIGINAL FUNCTION execution, not a full client runtime.
"""
from __future__ import annotations

import ast
import asyncio
from enum import Enum
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import AudioContent, ImageContent, TextResourceContents, CallToolResult

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
UPSTREAM=ROOT/"original"
SERVER=HERE/"b38_media_stdio_peer.py"
OUT=HERE/"out"
FILE="backend/onyx/server/features/mcp/client.py"
SOURCES={
 "before":{"commit":"0a96b123eebebcbda736b3a9690a432883bec443",
           "blob":"46c7f8691baa5fd0344bde6ba3ff3b5746efc26a"},
 "after":{"commit":"e4ea39563c9fef7ba6c8f4d5a664a526ccd8eb3b",
          "blob":"891820ed678e32fac4a2cbaa3b4b418a4b6e498d"},
}
SCENARIOS=("text","multi","image_only","audio_only","structured_only")


class CompatibleImage(ImageContent):
    @property
    def mimeType(self) -> str:
        return getattr(self,"mime_type")


class CompatibleAudio(AudioContent):
    @property
    def mimeType(self) -> str:
        return getattr(self,"mime_type")


def must(cond,code):
    if not cond:raise RuntimeError("B38_ONYX_"+code)


def git(root,*args):
    r=subprocess.run(["git","-C",str(root),*args],text=True,capture_output=True,
                     timeout=40,check=False)
    must(r.returncode==0,"GIT_"+str(args[0]))
    return r.stdout.strip()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def compile_original_pinned_function(side):
    repo=UPSTREAM/side
    ref=SOURCES[side]
    must(git(repo,"rev-parse","HEAD")==ref["commit"],"ORIGINAL_COMMIT_MISMATCH")
    must(git(repo,"rev-parse","HEAD:"+FILE)==ref["blob"],"ORIGINAL_GIT_TREE_MISMATCH")
    p=subprocess.run(["git","-C",str(repo),"cat-file","blob",ref["blob"]],
                     capture_output=True,timeout=40,check=False)
    must(p.returncode==0 and 100<len(p.stdout)<100_000,"ORIGINAL_BLOB_UNAVAILABLE")
    content=p.stdout.decode("utf-8")
    whole=ast.parse(content,filename=FILE)
    selected=[]
    for n in whole.body:
        if isinstance(n,ast.ClassDef) and n.name=="ContentBlockTypes":
            selected.append(n)
        elif isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name=="process_mcp_result":
            selected.append(n)
    must(len(selected)==2,"ORIGINAL_ENUM_AND_FORMATTER_NODES_NOT_FOUND")
    enum_node,fn_node=selected
    must(enum_node.name=="ContentBlockTypes" and fn_node.name=="process_mcp_result",
         "ORIGINAL_AST_IDS_CHANGED")
    # Compile EXACT AST nodes taken from the Git blob, no body edits, no
    # foreign application imports or module-level side effects.
    module=ast.fix_missing_locations(ast.Module(body=selected,type_ignores=[]))
    env={
        "__name__":"b38_original_onyx_"+side,"Enum":Enum,
        "json":json,"CallToolResult":CallToolResult,
        "TextResourceContents":TextResourceContents,
        "ImageContent":ImageContent,"AudioContent":AudioContent,
    }
    exec(compile(module,FILE,"exec"),env)
    must(callable(env["process_mcp_result"]),"ORIGINAL_FORMATTER_NOT_COMPILED")
    return env["process_mcp_result"],sha(p.stdout),(
        enum_node.lineno,fn_node.lineno,fn_node.end_lineno)


def compatible_result(result:CallToolResult):
    """Expose original field spellings without modifying original function.

    Content instances still carry actual values from real official MCP SDK
    stdio response; only field aliases are bridged where SDK versions differ.
    """
    changed=0
    normalized=[]
    for item in result.content:
        if isinstance(item,ImageContent) and not hasattr(item,"mimeType"):
            item=CompatibleImage.model_validate(item.model_dump())
            changed+=1
        elif isinstance(item,AudioContent) and not hasattr(item,"mimeType"):
            item=CompatibleAudio.model_validate(item.model_dump())
            changed+=1
        normalized.append(item)
    st=getattr(result,"structuredContent",None)
    if st is None:
        st=getattr(result,"structured_content",None)
    if st is None and hasattr(result,"model_dump"):
        st=result.model_dump(by_alias=True).get("structuredContent")
    return SimpleNamespace(content=normalized,structuredContent=st),changed


async def run_side(side):
    fn,source_hash,lines=compile_original_pinned_function(side)
    wirefile=OUT/("B38_ONYX_"+side.upper()+"_NATIVE_STDIO.jsonl")
    parameters=StdioServerParameters(
        command=sys.executable,args=[str(SERVER)],
        env={"B38_MEDIA_WIRE_PATH":str(wirefile.resolve())})
    outputs={}
    adjusted=0
    native_content={}
    async with stdio_client(parameters) as (read,write):
        async with ClientSession(read,write) as session:
            await asyncio.wait_for(session.initialize(),timeout=18)
            for tool in SCENARIOS:
                original=await asyncio.wait_for(session.call_tool(tool,{}),timeout=18)
                normalized,count=compatible_result(original)
                adjusted+=count
                rendered=fn(normalized)
                must(isinstance(rendered,str),"ORIGINAL_RESULT_NOT_STRING")
                outputs[tool]=rendered
                native_content[tool]=[
                    {"type":getattr(x,"type",None)}
                    for x in original.content]
    must(wirefile.is_file(),"NATIVE_WIRE_MISSING")
    traces=[json.loads(x) for x in wirefile.read_text().splitlines()]
    calls=[x for x in traces if x.get("request",{}).get("method")=="tools/call"]
    must(len(calls)==len(SCENARIOS),"NATIVE_TOOLS_CALL_MISSING")
    for tool,entry in zip(SCENARIOS,calls):
        must(entry["request"]["params"]["name"]==tool,
             "NATIVE_TOOL_ORDER_MISMATCH_"+tool)
        if tool=="image_only":
            must(entry["response"]["result"]["content"][0]["type"]=="image",
                 "ORIGINAL_IMAGE_NOT_SENT")
        if tool=="audio_only":
            must(entry["response"]["result"]["content"][0]["type"]=="audio",
                 "ORIGINAL_AUDIO_NOT_SENT")
    return {
       "side":side,"original_commit":SOURCES[side]["commit"],
       "original_source_git_blob":SOURCES[side]["blob"],
       "original_source_sha256":source_hash,
       "executed_function_source_line_span":list(lines),
       "executed_full_upstream_application_module":False,
       "executed_exact_original_function_AST":True,
       "genuine_MCP_SDK_stdio_call_tool_responses":True,
       "adapter_SDK_field_alias_compatibility_count":adjusted,
       "observed_model_text":outputs,
       "native_block_type_traces":native_content,
       "native_wire_sha256":sha(wirefile.read_bytes()),
       "raw_original_native_wire_file":wirefile.name,
    }


async def main():
    must(SERVER.is_file(),"CONTROLLED_SERVER_MISSING")
    OUT.mkdir(exist_ok=True)
    before=await run_side("before")
    after=await run_side("after")
    a=before["observed_model_text"]
    b=after["observed_model_text"]
    must(a["text"]==b["text"]=="normal result","NORMAL_TEXT_REGRESSION")
    must(a["multi"]==b["multi"]=="first\n\nsecond","MULTIBLOCK_TEXT_REGRESSION")
    must(a["structured_only"]==b["structured_only"]==
         json.dumps({"item_id":"B38","count":17}),
         "STRUCTURED_OUTPUT_REGRESSION")
    must(a["image_only"]=="" and a["audio_only"]=="",
         "ORIGINAL_MEDIA_ONLY_WAS_NOT_EMPTY")
    must(b["image_only"]=="[image omitted: image/png]",
         "REPAIRED_IMAGE_NOTICE_NOT_PRESENT")
    must(b["audio_only"]=="[audio omitted: audio/wav]",
         "REPAIRED_AUDIO_NOTICE_NOT_PRESENT")
    info={
      "schema":"risu-b38-onyx-original-function-native-stdio-v1",
      "upstream_project":"onyx-dot-app/onyx",
      "upstream_fix":"https://github.com/onyx-dot-app/onyx/pull/17157",
      "external_original_function_ast_executed":True,
      "external_original_whole_module_executed":False,
      "original_external_server_executed":False,
      "original_source_body_unchanged":True,
      "sdk_content_values_from_native_actual_stdio":True,
      "SDK_model_field_alias_adapter_declared":True,
      "original_native_image_and_audio_present":True,
      "before_model_visible_media_text_empty":True,
      "after_model_visible_media_notice_present":True,
      "after_media_data_delivered_to_model":False,
      "status_only_B38_generic_detector_not_scored_for_notices":True,
      "normal_text_multi_and_structured_controls_preserved":True,
      "no_population_fpr_claim":True,
    }
    r={"summary":info,"before":before,"after":after}
    path=OUT/"B38_ONYX_ORIGINAL_MEDIA_NOTICE_RESULTS.json"
    path.write_text(json.dumps(r,sort_keys=True,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps(info,sort_keys=True))
    print("B38_ONYX_ORIGINAL_FUNCTION_MEDIA_NOTICE_NATIVE_STDIO_CONFIRMED")
    print("B38_ONYX_RESULT_SHA256="+sha(path.read_bytes()))

if __name__=="__main__":
    asyncio.run(main())
