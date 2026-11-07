"""Independent, dependency-free audit of the P6-B2 source and diagnostic scores."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from evaluate import freeze_check,git_blob,calculate,ISSUE_MATCHED_RULES,FROZEN_MANIFEST_SHA256

def audit(manifest_path:Path, report_path:Path, source_dir:Path)->dict:
    raw=manifest_path.read_bytes()
    assert hashlib.sha256(raw).hexdigest()==FROZEN_MANIFEST_SHA256,"FROZEN_MANIFEST_CHANGED"
    manifest=json.loads(raw)
    freeze_check(manifest)
    report=json.loads(report_path.read_bytes())
    assert report["schema"]=="risu-p6b2-frozen-independent-audit-v1"
    assert report["manifest_sha256"]==hashlib.sha256(raw).hexdigest()
    assert report["product_source_commit"]==manifest["source_product_commit"]
    assert report["target_source_executed"] is False
    assert report["raw_production_api_called"] is False
    frozen={c["id"]:c for c in manifest["cases"]}
    rows=report["results"]
    assert set(c["id"] for c in rows)==set(frozen) and len(rows)==7
    for row in rows:
        reference=frozen[row["id"]]
        for key in ("issue","repo","commit","git_blob","path","label","family","split"):
            assert row[key]==reference[key],("frozen label changed",row["id"],key)
        src=source_dir/("case-"+row["id"])/("original"+Path(row["path"]).suffix)
        assert src.is_file() and not src.is_symlink()
        original=src.read_bytes()
        assert len(original) <= 300_000
        assert git_blob(original)==reference["git_blob"]
        assert row["source_sha256"]==hashlib.sha256(original).hexdigest()
        scan=row["scan"]
        if row["label"]=="unsupported":
            assert scan["status"]=="UNSUPPORTED_LANGUAGE"
            assert scan["findings"]==[] and scan["parsed"]==0
            assert row["issue_status"]=="UNSUPPORTED"
        else:
            assert scan["status"] in ("NO_STATIC_FINDINGS","STATIC_WARNINGS","UNVERIFIED_SOURCE")
            assert scan["parsed"]==1 and scan["unverified"]==0
            assert scan["returncode"]==0
            assert scan["finding_count"]==len(scan["findings"])
            assert len({(f["rule_id"],f["line"]) for f in scan["findings"]})==len(scan["findings"])
            for f in scan["findings"]:
                assert f["verdict"]=="SUSPECTED_LOSS"
                assert f["rule_id"] in ("RPY201","RPY202","RPY203","RPY204")
        matchers=ISSUE_MATCHED_RULES[row["family"]]
        detected=any(f["rule_id"] in matchers for f in scan["findings"])
        assert row["issue_specific_capability"] is bool(matchers)
        assert row["issue_matched_detection"] is detected
        assert row["issue_status"]==("UNSUPPORTED" if row["label"]=="unsupported" else
                "DETECTED" if detected else "NOT_DETECTED_WITHOUT_ISSUE_RULE")
    assert report["metrics"]==calculate(rows)
    assert report["metrics"]["independent_known_defects"]==2
    return {"status":"PASS","cases":len(rows),"score":report["metrics"],
            "manifest_sha256":report["manifest_sha256"],
            "claim":"Two holdout, official source-level bugs; zero detected with current issue rule set. No source execution or live customer API."}

def main()->None:
    p=argparse.ArgumentParser()
    p.add_argument("--manifest",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    p.add_argument("--source-root",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    result=audit(a.manifest,a.report,a.source_root)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("P6B2_FROZEN_INDEPENDENT_AUDIT",result["status"],result["score"],flush=True)

if __name__=="__main__":
    main()
