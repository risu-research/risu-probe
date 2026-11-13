#!/usr/bin/env python3
"""RISU B37 research-only conservative Python source semantic and partial parse.

No imports/execution of target source; no LLM, network, subprocess or user
credentials. A static candidate is always a hypothesis, not a runtime proof.
B37 external original source is embargoed until detector commit is frozen.
"""
from __future__ import annotations

import ast
import json
import re
import textwrap
from pathlib import Path
from typing import Any

from b34_channel_projection import analyze_source as legacy_analyze, _calls_tool, _walk_local

_MAX_SOURCE = 2 * 1024 * 1024
_FUNCTION_START = re.compile(r"^(?P<indent>[ \t]*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(")
_RULES = ("RSEM101", "RSEM102", "RSEM103", "RSEM104", "RSEM105", "RSEM106")


def _mentions_attr(node: ast.AST, var: str, attrs: frozenset[str]) -> bool:
    return any(
        isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
        and n.value.id == var and n.attr in attrs
        for n in ast.walk(node)
    )


def _has_expression_source(node: ast.AST, var: str) -> bool:
    return any(isinstance(n, ast.Name) and n.id == var
               for n in ast.walk(node))


def _is_mcp_tool(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        (isinstance(d, ast.Call) and (
             isinstance(d.func, ast.Attribute) and d.func.attr == "tool"
             or isinstance(d.func, ast.Name) and d.func.id in {"tool", "mcp_tool"}
        )) or isinstance(d, ast.Attribute) and d.attr == "tool"
        for d in fn.decorator_list
    )


def _wrapped_json_tool(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[dict[str, Any]]:
    """RSEM106: string return annotation + JSON-encoding of object-shaped data.

    This is a source-hypothesis about SDK output shape, not an error on its own.
    """
    if not _is_mcp_tool(fn) or fn.returns is None:
        return []
    if ast.unparse(fn.returns) not in {"str", "builtins.str"}:
        return []
    for node in _walk_local(fn):
        if not isinstance(node, ast.Return) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        if not (isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "json" and call.func.attr == "dumps"
                and call.args):
            continue
        arg = call.args[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            continue
        return [{
            "rule_id":"RSEM106", "line":node.lineno, "column":node.col_offset,
            "function":fn.name,
            "classification":"SOURCE_HYPOTHESIS",
            "mechanism":"MCP-exposed tool annotated as str pre-encodes a structured value with json.dumps; the SDK may wrap JSON as a string inside an additional result envelope.",
        }]
    return []


def _generic_error_raise(stmt: ast.AST, var: str) -> list[ast.Raise]:
    """Identify discarded tool-error messages on an error guard, without guessing."""
    out=[]
    for x in ast.walk(stmt):
        if not isinstance(x, ast.Raise) or x.exc is None:
            continue
        ex=x.exc
        if not (isinstance(ex, ast.Call) and
                isinstance(ex.func,(ast.Name,ast.Attribute))):
            continue
        if isinstance(ex.func,ast.Name):
            name=ex.func.id
        else:
            name=ex.func.attr
        if name not in {"ValueError","RuntimeError","Exception","ToolError"}:
            continue
        if not ex.args or not all(isinstance(v,ast.Constant) for v in ex.args):
            continue
        if _has_expression_source(ex,var):
            continue
        out.append(x)
    return out


def _error_status_discarded(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[dict[str, Any]]:
    found=[]
    nodes=list(_walk_local(fn))
    for var in sorted(_calls_tool(fn)):
        is_error=frozenset(("isError","is_error"))
        content_fields=frozenset(("content","structured_content","structuredContent"))
        # Don't flag a simple transport passthrough returning the original result.
        returns_original=any(isinstance(n,ast.Return) and isinstance(n.value,ast.Name)
                             and n.value.id==var for n in nodes)
        if returns_original:
            continue
        for node in nodes:
            if isinstance(node, ast.If) and _mentions_attr(node.test,var,is_error):
                for body in node.body:
                    if (_mentions_attr(body,var,content_fields)
                            or _has_expression_source(body,var)):
                        # The condition itself is not considered part of the
                        # branch body. An explicit error-payload read is a safe
                        # negative witness, even if it is not a proof.
                        continue
                    for ex in _generic_error_raise(body,var):
                        found.append({
                            "rule_id":"RSEM104","line":ex.lineno,"column":ex.col_offset,
                            "function":fn.name,"classification":"SOURCE_HYPOTHESIS",
                            "mechanism":"A tool's error flag triggers a constant exception, discarding the original MCP error payload and recovery details.",
                        })
        status_handled=any(_mentions_attr(n,var,is_error) for n in nodes)
        if status_handled:
            continue
        # A projected return of content, without reading the tool's error
        # status, can conflate success and isError=true. Restrict to a direct
        # return with explicit projection and a known call_tool result.
        for n in nodes:
            if isinstance(n,ast.Return) and n.value is not None:
                if _mentions_attr(n.value,var,frozenset(("content",))):
                    found.append({
                        "rule_id":"RSEM105","line":n.lineno,
                        "column":n.col_offset,"function":fn.name,
                        "classification":"SOURCE_HYPOTHESIS",
                        "mechanism":"Consumer returns a projection of MCP content without inspecting isError/is_error; failures can be presented as successful content.",
                    })
    return found


def _extra_rules(tree: ast.AST, relative_path: str) -> list[dict[str, Any]]:
    found=[]
    for fn in ast.walk(tree):
        if not isinstance(fn,(ast.FunctionDef,ast.AsyncFunctionDef)):
            continue
        for result in _wrapped_json_tool(fn) + _error_status_discarded(fn):
            result["path"]=relative_path
            found.append(result)
    return found


def _complete_source(source: str, path: str) -> dict[str, Any]:
    tree=ast.parse(source,filename=path)
    legacy=legacy_analyze(source,path)
    found=list(legacy["findings"])+_extra_rules(tree,path)
    unique={(x["path"],x["line"],x["rule_id"]):x for x in found}
    return {
        "schema":"risu-b37-readonly-source-semantic-v1",
        "scope":"PYTHON_AST_READONLY", "source_path":path,
        "coverage":"COMPLETE_AST",
        "source_hypotheses_only":True,"third_party_code_executed":False,
        "rules":list(_RULES),
        "findings":sorted(unique.values(),key=lambda x:(x["line"],x["rule_id"])),
        "parse_error":None,
        "recovered_functions":None,
        "incomplete_regions":0,
    }


def _recover_functions(source: str,path: str,err: SyntaxError) -> dict[str, Any]:
    """Salvage self-contained def blocks, never claim the module was parsed.

    Only lexical def boundaries whose own block parses are analyzed. We do not
    overwrite source lines and do not invent imports or runtime context. If
    the syntax-invalid region lies within a candidate function, it is omitted.
    """
    lines=source.splitlines(keepends=True)
    starts=[]
    for i,line in enumerate(lines):
        m=_FUNCTION_START.match(line)
        if m is not None:
            starts.append((i,len(m.group("indent").expandtabs(8))))
    found=[]
    recovered=0
    failed=0
    for i,indent in starts:
        j=i+1
        while j<len(lines):
            line=lines[j]
            if not line.strip():
                j+=1
                continue
            leading=len(line)-len(line.lstrip(" \t"))
            if leading<=indent and not line.lstrip().startswith("#"):
                break
            j+=1
        snippet=textwrap.dedent("".join(lines[i:j]))
        try:
            tree=ast.parse(snippet,filename=path)
        except (SyntaxError,ValueError,RecursionError):
            failed+=1
            continue
        recovered+=1
        # The legacy analyzer works only on this successfully parsed block,
        # with line numbers translated back to the true original source.
        local=legacy_analyze(snippet,path)
        xs=list(local["findings"])+_extra_rules(tree,path)
        for x in xs:
            x["line"]+=i
            x["analysis_coverage"]="PARTIAL_RECOVERED_FUNCTION"
            found.append(x)
    unique={(x["path"],x["line"],x["rule_id"]):x for x in found}
    return {
        "schema":"risu-b37-readonly-source-semantic-v1",
        "scope":"PYTHON_AST_READONLY",
        "source_path":path,
        "coverage":"PARTIAL_AST" if recovered else "UNVERIFIED_NO_RECOVERABLE_FUNCTIONS",
        "source_hypotheses_only":True,"third_party_code_executed":False,
        "rules":list(_RULES),
        "findings":sorted(unique.values(),key=lambda x:(x["line"],x["rule_id"])),
        "parse_error":{"line":err.lineno,"offset":err.offset,"message":err.msg},
        "recovered_functions":recovered,
        "incomplete_regions":max(1,failed),
        "whole_module_scanned":False,
        "negative_claims_prohibited":True,
    }


def analyze_source(source: str,relative_path: str="<source>") -> dict[str, Any]:
    if len(source.encode("utf-8"))>_MAX_SOURCE:
        return {"schema":"risu-b37-readonly-source-semantic-v1",
                "coverage":"UNVERIFIED_SIZE_LIMIT","findings":[],
                "source_path":relative_path,"source_hypotheses_only":True}
    try:
        return _complete_source(source,relative_path)
    except SyntaxError as ex:
        return _recover_functions(source,relative_path,ex)
    except (RecursionError,ValueError) as ex:
        return {"schema":"risu-b37-readonly-source-semantic-v1",
                "coverage":"UNVERIFIED_PARSE_ERROR",
                "reason":type(ex).__name__,
                "findings":[],"source_path":relative_path,
                "source_hypotheses_only":True}


def main():
    import argparse
    p=argparse.ArgumentParser(description="P6-B37 research-only conservative source analysis")
    p.add_argument("source")
    p.add_argument("--path",default=None)
    args=p.parse_args()
    src=Path(args.source)
    if not src.is_file() or src.is_symlink():
        raise SystemExit("B37_UNVERIFIED_MISSING_OR_SYMLINK_SOURCE")
    data=src.read_bytes()
    try:
        text=data.decode("utf-8")
    except UnicodeError:
        raise SystemExit("B37_UNVERIFIED_NON_UTF8_SOURCE") from None
    print(json.dumps(analyze_source(text,args.path or src.name),
                     sort_keys=True,ensure_ascii=False))


if __name__=="__main__":
    main()
