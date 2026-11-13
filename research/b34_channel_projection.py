#!/usr/bin/env python3
"""P6-B34 development-only MCP result-channel projection analysis.

Narrow, read-only, single-file Python AST analysis. No target imports, no
project execution, no network, no LLM calls. The result is a source hypothesis,
NEVER proof of a real MCP consumer failure. No project/issue-specific rules.

Designed against the five B34 training cases. B35 original source must not
be viewed or used to change these rules before the first B35 evaluation.
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Iterator, Any

MAX_SOURCE_BYTES = 2 * 1024 * 1024
STRUCTURED_FIELDS = frozenset(("structured_content", "structuredContent"))
MCP_ERROR_FIELDS = frozenset(("isError", "is_error"))


def _walk_local(fn: ast.AST) -> Iterator[ast.AST]:
    """Visit a function body but never attribute nested defs to outer scopes."""
    todo = list(reversed(getattr(fn, "body", [])))
    while todo:
        node = todo.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                             ast.ClassDef)):
            continue
        yield node
        todo.extend(reversed(list(ast.iter_child_nodes(node))))


def _functions(tree: ast.AST) -> Iterator[ast.AST]:
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield n


def _attr_on(node: ast.AST, var: str, attrs: set[str] | frozenset[str]) -> bool:
    return isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and (
        node.value.id == var and node.attr in attrs
    )


def _calls_tool(fn: ast.AST) -> set[str]:
    found: set[str] = set()
    for n in _walk_local(fn):
        if not isinstance(n, (ast.Assign, ast.AnnAssign)):
            continue
        value = n.value
        if isinstance(value, ast.Await):
            value = value.value
        if not isinstance(value, ast.Call):
            continue
        caller = value.func
        if not isinstance(caller, ast.Attribute) or caller.attr not in (
            "call_tool", "callTool", "execute_tool", "executeToolCall"
        ):
            continue
        targets = n.targets if isinstance(n, ast.Assign) else [n.target]
        for target in targets:
            if isinstance(target, ast.Name):
                found.add(target.id)
    # A consumer helper that accepts a typed MCP result is also in scope.
    for arg in list(getattr(getattr(fn, "args", None), "posonlyargs", [])) + list(
        getattr(getattr(fn, "args", None), "args", [])
    ):
        if arg.annotation is None:
            continue
        if "CallToolResult" in ast.unparse(arg.annotation):
            found.add(arg.arg)
    return found


def _structured_read(nodes: list[ast.AST], var: str) -> bool:
    for n in nodes:
        if _attr_on(n, var, STRUCTURED_FIELDS):
            return True
        if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name) and (
            n.value.id == var and isinstance(n.slice, ast.Constant)
            and n.slice.value in STRUCTURED_FIELDS
        ):
            return True
        if not isinstance(n, ast.Call):
            continue
        if isinstance(n.func, ast.Name) and n.func.id == "getattr" and len(n.args) >= 2:
            if isinstance(n.args[0], ast.Name) and n.args[0].id == var and (
                isinstance(n.args[1], ast.Constant) and n.args[1].value in STRUCTURED_FIELDS
            ):
                return True
        if isinstance(n.func, ast.Attribute) and n.func.attr == "get" and (
            isinstance(n.func.value, ast.Name) and n.func.value.id == var
        ) and n.args and isinstance(n.args[0], ast.Constant) and (
            n.args[0].value in STRUCTURED_FIELDS
        ):
            return True
    return False


def _content_read(nodes: list[ast.AST], var: str) -> list[ast.Attribute]:
    return [
        n for n in nodes if isinstance(n, ast.Attribute)
        and _attr_on(n, var, frozenset(("content",)))
    ]


def _returns_unmodified(nodes: list[ast.AST], var: str) -> bool:
    return any(
        isinstance(n, ast.Return) and isinstance(n.value, ast.Name)
        and n.value.id == var for n in nodes
    )


def _has_error_context(loop: ast.For | ast.AsyncFor, parents: dict[int, ast.AST]) -> bool:
    child: ast.AST = loop
    while id(child) in parents:
        node = parents[id(child)]
        if isinstance(node, ast.If) and any(
            isinstance(k, ast.Attribute) and k.attr in MCP_ERROR_FIELDS
            for k in ast.walk(node.test)
        ):
            # Only skip positive/error handling branches, not the else branch.
            if child in node.body:
                return True
        child = node
    return False


def _is_content_iteration(n: ast.AST, var: str) -> bool:
    return any(_attr_on(k, var, frozenset(("content",))) for k in ast.walk(n))


def _mentions_item(node: ast.AST, item: str) -> bool:
    return any(isinstance(x, ast.Name) and x.id == item for x in ast.walk(node))


def _text_only_filter(loop: ast.For | ast.AsyncFor) -> bool:
    """A strict structural witness: a loop with only a text-filtered branch.

    Don't flag general loops and don't flag an explicit non-text fallback.
    """
    if not isinstance(loop.target, ast.Name):
        return False
    item = loop.target.id
    guarded = []
    for stmt in loop.body:
        if isinstance(stmt, ast.If):
            references_text = any(
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name) and n.func.id == "hasattr"
                and len(n.args) >= 2 and isinstance(n.args[0], ast.Name)
                and n.args[0].id == item and isinstance(n.args[1], ast.Constant)
                and n.args[1].value == "text"
                for n in ast.walk(stmt.test)
            ) or any(
                isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
                and n.value.id == item and n.attr == "text"
                for n in ast.walk(stmt.test)
            )
            if references_text:
                guarded.append(stmt)
    if not guarded:
        return False
    for g in guarded:
        if g.orelse and any(_mentions_item(stmt, item) for stmt in g.orelse):
            return False
        for stmt in loop.body:
            if stmt is g:
                continue
            if _mentions_item(stmt, item):
                # A non-text fallback uses the same block after the text branch.
                return False
    return True


def _first_block_reads(nodes: list[ast.AST], var: str) -> list[ast.Subscript]:
    out = []
    for node in nodes:
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
            if node.slice.value != 0:
                continue
            if _attr_on(node.value, var, frozenset(("content",))):
                out.append(node)
    return out


def analyze_source(source: str, relative_path: str = "<source>") -> dict[str, Any]:
    tree = ast.parse(source, filename=relative_path)
    findings = []
    for fn in _functions(tree):
        nodes = list(_walk_local(fn))
        if not nodes:
            continue
        names = _calls_tool(fn)
        if not names:
            continue
        for var in sorted(names):
            content = _content_read(nodes, var)
            if not content:
                continue
            # A distinct read of structured_content is a clear negative witness
            # for channel-only source projection, but not proof of preservation.
            if not _structured_read(nodes, var) and not _returns_unmodified(nodes, var):
                # For the channel-only rule, anchor on the primary projection
                # of the MCP content into an independently returned result.
                projections = [
                    n for n in content if any(
                        isinstance(p, ast.Return) and n in ast.walk(p)
                        for p in nodes if isinstance(p, ast.Return)
                    )
                ]
                if projections:
                    first = min(projections, key=lambda n: (n.lineno, n.col_offset))
                    findings.append({
                        "rule_id": "RSEM101", "line": first.lineno,
                        "column": first.col_offset,
                        "function": getattr(fn, "name", ""),
                        "path": relative_path, "variable": var,
                        "classification": "SOURCE_HYPOTHESIS",
                        "mechanism": "MCP result content is projected into a new returned result without inspecting the independent structured-content channel.",
                    })
            for sub in _first_block_reads(nodes, var):
                findings.append({
                    "rule_id": "RSEM102", "line": sub.lineno,
                    "column": sub.col_offset,
                    "function": getattr(fn, "name", ""), "path": relative_path,
                    "variable": var, "classification": "SOURCE_HYPOTHESIS",
                    "mechanism": "Only the first content block is indexed, which can silently omit later blocks.",
                })
            parents = {}
            for parent in ast.walk(fn):
                for child in ast.iter_child_nodes(parent):
                    parents[id(child)] = parent
            for n in nodes:
                if not isinstance(n, (ast.For, ast.AsyncFor)):
                    continue
                if not _is_content_iteration(n.iter, var):
                    continue
                if _has_error_context(n, parents):
                    continue
                if not _text_only_filter(n):
                    continue
                findings.append({
                    "rule_id": "RSEM103", "line": n.lineno,
                    "column": n.col_offset,
                    "function": getattr(fn, "name", ""), "path": relative_path,
                    "variable": var, "classification": "SOURCE_HYPOTHESIS",
                    "mechanism": "MCP result content is iterated through a text-only guarded branch with no non-text block handling.",
                })
    unique = {
        (f["path"], f["line"], f["rule_id"]): f for f in findings
    }
    return {
        "schema": "risu-b34-source-channel-projection-v0",
        "scope": "PYTHON_AST_READONLY_SINGLE_SOURCE",
        "source_path": relative_path,
        "source_hypotheses_only": True,
        "third_party_code_executed": False,
        "rules": ["RSEM101", "RSEM102", "RSEM103"],
        "findings": sorted(unique.values(), key=lambda f: (f["line"], f["rule_id"])),
    }


def main() -> int:
    p = argparse.ArgumentParser(description="B34 source-only MCP result channel audit")
    p.add_argument("source")
    p.add_argument("--path", default=None, help="Display path; never used for rule selection")
    args = p.parse_args()
    path = Path(args.source)
    if not path.is_file() or path.is_symlink():
        raise SystemExit("B34_REFUSED_UNREADABLE_OR_SYMLINKED_SOURCE")
    data = path.read_bytes()
    if len(data) > MAX_SOURCE_BYTES or b"\x00" in data:
        raise SystemExit("B34_REFUSED_BINARY_OR_OVERSIZE_SOURCE")
    try:
        report = analyze_source(data.decode("utf-8"), args.path or path.name)
    except (SyntaxError, UnicodeError, ValueError, RecursionError) as exc:
        raise SystemExit("B34_UNVERIFIED_PARSE_ERROR " + type(exc).__name__) from exc
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
