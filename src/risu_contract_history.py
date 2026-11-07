"""RISU Probe P4-T: explicit, hash-linked MCP schema / operator-policy history.

This is a comparison of recorded declarations, not proof of runtime fidelity or
of independently negotiated legal contracts. Standard-library only.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

FORMAT = "risu-contract-snapshot-v1"
DIFF_FORMAT = "risu-contract-diff-v1"
MAX_BYTES = 5_000_000


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_json(path: str | Path) -> Any:
    path = Path(path)
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("JSON input exceeds maximum permitted size")
    return json.loads(path.read_text(encoding="utf-8"))


def read_json_or_jsonl(path: str | Path) -> list[Any]:
    text = Path(path).read_text(encoding="utf-8")
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise ValueError("Schema input too large")
    try:
        return [json.loads(text)]
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]


def resolve_schema(messages: list[Any], tool: str | None) -> tuple[dict, str]:
    """Use exact tools/list output, or explicitly label an independent schema file."""
    candidates: list[tuple[dict, str]] = []
    for m in messages:
        if not isinstance(m, dict):
            continue
        roots = [m]
        if isinstance(m.get("result"), dict):
            roots.append(m["result"])
        for root in roots:
            if isinstance(root.get("tools"), list):
                for entry in root["tools"]:
                    if isinstance(entry, dict) and isinstance(entry.get("outputSchema"), dict):
                        if tool is None or entry.get("name") == tool:
                            candidates.append((entry["outputSchema"], "recorded-tools-list"))
            if isinstance(root.get("outputSchema"), dict):
                if tool is None or root.get("name") in (None, tool):
                    candidates.append((root["outputSchema"], "schema-file"))
            if "properties" in root and isinstance(root.get("properties"), dict):
                candidates.append((root, "schema-file"))
    if len(candidates) != 1:
        raise ValueError(f"Expected exactly one matching outputSchema, got {len(candidates)}; specify --tool")
    schema, source = candidates[0]
    if not isinstance(schema.get("properties"), dict):
        raise ValueError("Expected object outputSchema with properties")
    _flatten(schema)  # fail closed on malformed schema
    return copy.deepcopy(schema), source


def _flatten(schema: dict) -> dict[str, dict]:
    """Flatten declared object properties. No inferred $ref, oneOf or runtime behavior."""
    result: dict[str, dict] = {}
    def visit(node: Any, path: str, parent_required: bool) -> None:
        if not isinstance(node, dict):
            raise ValueError(f"Invalid schema at {path}")
        props = node.get("properties", {})
        required = node.get("required", [])
        if not isinstance(props, dict) or not isinstance(required, list) or any(not isinstance(x, str) for x in required):
            raise ValueError(f"Malformed properties or required at {path}")
        if len(required) != len(set(required)) or not set(required).issubset(props):
            raise ValueError(f"required refers to absent/duplicate properties at {path}")
        for name, child in props.items():
            if not isinstance(name, str) or not isinstance(child, dict):
                raise ValueError(f"Invalid declared property {path}")
            key = path + "/" + name.replace("~", "~0").replace("/", "~1")
            is_required = name in required
            typ = child.get("type")
            if typ is not None and not isinstance(typ, (str, list)):
                raise ValueError(f"Invalid type at {key}")
            if isinstance(typ, list) and (not typ or any(not isinstance(t, str) for t in typ)):
                raise ValueError(f"Invalid type list at {key}")
            result[key] = {"type": typ, "required_local": is_required,
                           "reachable_required": parent_required and is_required}
            if "properties" in child:
                visit(child, key, parent_required and is_required)
    visit(schema, "", True)
    return result


def _policy_rules(raw: Any) -> dict[str, dict]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("Operator policy must be an object")
    rules: dict[str, dict] = {}
    if "cases" in raw:
        cases = raw["cases"]
        if not isinstance(cases, list):
            raise ValueError("P4-S policy cases must be an array")
        seen_cases: set[str] = set()
        for case in cases:
            if not isinstance(case, dict):
                raise ValueError("Invalid P4-S policy case")
            case_id = case.get("case_id")
            tool = case.get("tool")
            if not isinstance(case_id, str) or not case_id or case_id in seen_cases or not isinstance(tool,str) or not tool:
                raise ValueError("Invalid/duplicate policy case or missing tool")
            seen_cases.add(case_id)
            obligations = case.get("obligations")
            if not isinstance(obligations, list):
                raise ValueError("P4-S case obligations must be an array")
            for row in obligations:
                if not isinstance(row, dict) or not isinstance(row.get("id"),str) or not row["id"]:
                    raise ValueError("P4-S obligation requires an id")
                key = case_id+"::"+row["id"]
                if key in rules:
                    raise ValueError("Duplicate P4-S case obligation: "+key)
                rules[key] = {"case_id":case_id,"tool":tool,**copy.deepcopy(row)}
        return rules
    if "rules" not in raw and "obligations" not in raw:
        raise ValueError("Unrecognized policy layout; refusing to silently ignore obligations")
    rows = raw.get("rules", raw.get("obligations"))
    if not isinstance(rows, list):
        raise ValueError("Operator policy rules must be an array")
    for idx, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError("Invalid operator rule")
        key = row.get("id") or row.get("rule_id") or row.get("source_path") or row.get("path")
        if not isinstance(key, str) or not key:
            raise ValueError(f"Rule {idx} needs an id or path for stable matching")
        if key in rules:
            raise ValueError(f"Duplicate operator rule {key}")
        rules[key] = copy.deepcopy(row)
    return rules


def create_snapshot(schema_path: str, policy_path: str | None, version: str,
                    tool: str | None, previous_path: str | None = None) -> dict:
    if not version.strip():
        raise ValueError("Version label required")
    schema, provenance = resolve_schema(read_json_or_jsonl(schema_path), tool)
    policy = read_json(policy_path) if policy_path else None
    _policy_rules(policy)
    previous = load_snapshot(previous_path) if previous_path else None
    body = {
        "format": FORMAT, "version": version, "tool": tool,
        "source_kind": provenance, "schema": schema, "operator_policy": policy,
        "input_sha256": {"schema": hashlib.sha256(Path(schema_path).read_bytes()).hexdigest(),
                         "operator_policy": hashlib.sha256(Path(policy_path).read_bytes()).hexdigest() if policy_path else None},
        "previous_snapshot_sha256": previous["snapshot_sha256"] if previous else None,
        "trust_notice": "Recorded or supplied declarations; neither live deployment evidence nor a signed supplier contract.",
    }
    body["snapshot_sha256"] = digest(body)
    return body


def load_snapshot(path: str | Path) -> dict:
    obj = read_json(path)
    if not isinstance(obj, dict) or obj.get("format") != FORMAT:
        raise ValueError("Wrong snapshot format")
    recorded = obj.get("snapshot_sha256")
    if not isinstance(recorded, str) or digest({k:v for k,v in obj.items() if k != "snapshot_sha256"}) != recorded:
        raise ValueError("Snapshot content hash mismatch")
    if not isinstance(obj.get("version"), str) or not obj["version"]:
        raise ValueError("Snapshot version missing")
    _flatten(obj["schema"])
    _policy_rules(obj["operator_policy"])
    return obj


def diff_snapshots(old: dict, new: dict) -> dict:
    if old.get("tool") != new.get("tool"):
        raise ValueError("Cannot compare different tool identities")
    a, b = _flatten(old["schema"]), _flatten(new["schema"])
    events: list[dict] = []
    impacts: list[dict] = []
    for path in sorted(a.keys() | b.keys()):
        before, after = a.get(path), b.get(path)
        if before is None:
            kind = "NEW_REQUIRED_FIELD" if after["required_local"] else "NEW_OPTIONAL_FIELD"
            events.append({"kind":kind,"path":path,"before":None,"after":after,"potential_breaking":after["required_local"]})
        elif after is None:
            events.append({"kind":"FIELD_REMOVED","path":path,"before":before,"after":None,"potential_breaking":True})
        else:
            if before["type"] != after["type"]:
                events.append({"kind":"TYPE_CHANGED","path":path,"before":before["type"],"after":after["type"],"potential_breaking":True})
            if before["required_local"] != after["required_local"]:
                kind = "OPTIONAL_TO_REQUIRED" if after["required_local"] else "REQUIRED_TO_OPTIONAL"
                events.append({"kind":kind,"path":path,"before":before["required_local"],"after":after["required_local"],"potential_breaking":after["required_local"]})
            if before["reachable_required"] != after["reachable_required"] and before["required_local"] == after["required_local"]:
                impacts.append({"kind":"INHERITED_REQUIREDNESS_IMPACT","path":path,
                                "before":before["reachable_required"],"after":after["reachable_required"]})
    op_a, op_b = _policy_rules(old["operator_policy"]), _policy_rules(new["operator_policy"])
    policy_events: list[dict] = []
    for rule in sorted(op_a.keys() | op_b.keys()):
        left, right = op_a.get(rule), op_b.get(rule)
        if left is None:
            policy_events.append({"kind":"OPERATOR_RULE_ADDED","rule_id":rule,"after":right})
        elif right is None:
            policy_events.append({"kind":"OPERATOR_RULE_REMOVED","rule_id":rule,"before":left})
        else:
            for attribute in sorted(left.keys() | right.keys()):
                if left.get(attribute) != right.get(attribute):
                    policy_events.append({"kind":"OPERATOR_RULE_ATTRIBUTE_CHANGED","rule_id":rule,
                                          "attribute":attribute,"before":left.get(attribute),"after":right.get(attribute)})
    potential = [x for x in events if x["potential_breaking"]]
    report = {
        "format": DIFF_FORMAT, "from_version": old["version"], "to_version": new["version"],
        "from_sha256": old["snapshot_sha256"], "to_sha256": new["snapshot_sha256"],
        "same_tool": True, "publisher_schema_events": events,
        "inherited_effects_not_independent_changes": impacts,
        "operator_policy_events": policy_events,
        "potential_breaking_changes": potential,
        "summary": {"direct_schema_events":len(events),"inherited_effects":len(impacts),
                    "operator_policy_events":len(policy_events),"potential_breaking":len(potential)},
        "limitation": "Potential compatibility impact only. No observed upgrade, causal data loss, or legal breach is proven.",
    }
    return report


def timeline(paths: list[str]) -> dict:
    if len(paths) < 2:
        raise ValueError("Timeline requires at least two snapshots")
    snapshots = [load_snapshot(path) for path in paths]
    for idx, (a, b) in enumerate(zip(snapshots, snapshots[1:]), 1):
        if b["previous_snapshot_sha256"] != a["snapshot_sha256"]:
            raise ValueError(f"Broken chronology/hash link at transition {idx}")
        if b["version"] == a["version"]:
            raise ValueError(f"Duplicate consecutive version label at {idx}")
    return {"format":"risu-contract-timeline-v1", "verified_hash_links":len(snapshots)-1,
            "versions":[{"version":s["version"],"sha256":s["snapshot_sha256"],"source_kind":s["source_kind"]} for s in snapshots],
            "transitions":[diff_snapshots(a,b)["summary"] for a,b in zip(snapshots,snapshots[1:])],
            "limitation":"Hashes verify internal sequence integrity, not independent provenance or deployment order."}


def _write(path: str, result: dict) -> None:
    out = Path(path)
    if out.exists():
        raise ValueError("Refusing to overwrite an existing output file")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",encoding="utf-8")


def cli(argv: list[str] | None = None) -> int:
    p=argparse.ArgumentParser(prog="risu-probe contract-history",description="Compare recorded MCP outputSchema and user-supplied operator policies")
    sub=p.add_subparsers(dest="operation",required=True)
    snap=sub.add_parser("snapshot")
    snap.add_argument("--schema",required=True)
    snap.add_argument("--tool")
    snap.add_argument("--policy")
    snap.add_argument("--version",required=True)
    snap.add_argument("--previous")
    snap.add_argument("--out",required=True)
    diff=sub.add_parser("diff")
    diff.add_argument("old")
    diff.add_argument("new")
    diff.add_argument("--out")
    diff.add_argument("--fail-on-potential-breaking",action="store_true")
    timeline_p=sub.add_parser("timeline")
    timeline_p.add_argument("snapshots",nargs="+")
    timeline_p.add_argument("--out")
    args=p.parse_args(argv)
    try:
        if args.operation=="snapshot":
            result=create_snapshot(args.schema,args.policy,args.version,args.tool,args.previous)
            _write(args.out,result)
        elif args.operation=="diff":
            result=diff_snapshots(load_snapshot(args.old),load_snapshot(args.new))
            if args.out:_write(args.out,result)
            else: print(json.dumps(result,ensure_ascii=False,indent=2))
            return 1 if args.fail_on_potential_breaking and result["summary"]["potential_breaking"] else 0
        else:
            result=timeline(args.snapshots)
            if args.out:_write(args.out,result)
            else:print(json.dumps(result,ensure_ascii=False,indent=2))
        return 0
    except (OSError,ValueError,TypeError,KeyError,IndexError,json.JSONDecodeError) as e:
        print(f"CONTRACT_HISTORY_ERROR: {e}",file=__import__('sys').stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(cli())
