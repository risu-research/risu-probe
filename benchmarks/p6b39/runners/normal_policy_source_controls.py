#!/usr/bin/env python3
"""B39 N3/N4 policy-scope controls using actual upstream function bodies.

N3 is AST-isolated and N4 imports the entire unchanged upstream redaction module,
with a synthetic typed Pydantic model replacing the non-executed Appwrite SDK.
Neither test has native MCP wire. Both must be excluded from the primary FPR.
"""
from __future__ import annotations
import argparse
import ast
import importlib.util
import json
import sys
import types
from pathlib import Path

def n3(original: Path) -> dict:
    tree = ast.parse(original.read_text(encoding="utf-8"), filename=str(original))
    funcs = [node for node in tree.body if isinstance(node, ast.FunctionDef)
             and node.name == "truncate_tool_output"]
    assert len(funcs) == 1
    namespace = {}
    compiled = compile(ast.Module(body=funcs, type_ignores=[]), str(original), "exec")
    exec(compiled, namespace)
    trunc = namespace["truncate_tool_output"]
    base = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 30
    assert trunc(base, 0) == base
    assert trunc("small", 5) == "small"
    assert trunc(base, 1000) == base
    out = trunc(base, 30)
    assert len(out.encode("utf-8")) <= 120
    assert "truncated" in out
    uni = trunc("🌟日本語🪷" * 400, 25)
    assert len(uni.encode("utf-8")) <= 100
    assert "truncated" in uni
    return {
        "case": "N3",
        "upstream": "xxynet/KiraAI",
        "original_commit": "c69b8eab5e89cb09201723e48dcefb83164b7bd6",
        "original_source_blob": "cdb1833c8593d45b724fe5c6daddacfde04bacff",
        "evidence_level": "ORIGINAL_SOURCE_FUNCTION_AST_ISOLATED",
        "native_mcp_wire": False,
        "primary_fpr_eligible": False,
        "contract": "DECLARED_BUDGET; NOT EXACT_RAW_TEXT",
        "controls": ["zero_budget_unbounded", "small_untouched", "large_unbounded",
                     "truncation_with_notice_under_budget", "unicode_boundary_under_budget"],
        "all_controls_passed": True,
    }

def n4(original: Path) -> dict:
    # The real unchanged source imports SDK models; replace ONLY the import
    # target with a synthetic typed model to avoid real credentials/network.
    from pydantic import BaseModel, Field
    appwrite = types.ModuleType("appwrite_console")
    models = types.ModuleType("appwrite_console.models")
    class SyntheticModel(BaseModel):
        api_key: str = Field(alias="apiKey", json_schema_extra={"format": "password"})
        label: str
    models.SyntheticModel = SyntheticModel
    appwrite.models = models
    sys.modules["appwrite_console"] = appwrite
    sys.modules["appwrite_console.models"] = models
    spec = importlib.util.spec_from_file_location("b39_real_upstream_redaction", original)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    dummy = "SYNTHETIC_NOT_A_REAL_SECRET"
    masked, fields = module.redact(SyntheticModel(apiKey=dummy, label="visible"))
    assert fields == ["apiKey"], fields
    assert masked["apiKey"] == "[redacted]"
    assert masked["label"] == "visible"
    assert masked["apiKeyFingerprint"] == module.fingerprint(dummy)
    assert dummy not in json.dumps(masked)
    raw, raw_fields = module.redact_payload({"apiKey": dummy, "label": "visible"})
    assert raw_fields == ["apiKey"]
    assert raw["apiKey"] == "[redacted]"
    assert raw["label"] == "visible"
    empty, empty_fields = module.redact(SyntheticModel(apiKey="", label="visible"))
    assert empty_fields == []
    assert empty["apiKey"] == ""
    assert "reveal_secrets=true" in module.note(fields)
    return {
        "case": "N4",
        "upstream": "appwrite/mcp",
        "original_commit": "96d0278df4a2c0917c894d2b25138235e3963488",
        "original_source_blob": "4c35901707211c917c8850e03026efb3280ed611",
        "evidence_level": "ORIGINAL_SOURCE_MODULE_WITH_SYNTHETIC_SDK_MODEL",
        "native_mcp_wire": False,
        "primary_fpr_eligible": False,
        "contract": "DECLARED_REDACTION; NOT EXACT_RAW_TEXT",
        "controls": ["typed_secret_masked", "fingerprint_matches_synthetic",
                     "other_field_preserved", "raw_secret_name_masked",
                     "empty_secret_preserved", "explicit_reveal_secrets_notice"],
        "all_controls_passed": True,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("n3_source", type=Path)
    parser.add_argument("n4_source", type=Path)
    parser.add_argument("output", type=Path)
    a = parser.parse_args()
    out = {"schema": "risu-b39-original-policy-functions-v1",
           "source_code_modified": False,
           "native_protocol_audit": False,
           "fpr_numerator_or_denominator_contribution": 0,
           "cases": [n3(a.n3_source), n4(a.n4_source)]}
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(out, sort_keys=True, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"cases": [x["case"] for x in out["cases"]],
                      "all_passed": True, "primary_fpr_eligible": False}))

if __name__ == "__main__":
    main()
