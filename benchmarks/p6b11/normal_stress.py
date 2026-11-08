"""Seeded B11 normal/output-injection stress against the *unchanged* B10 rule engine.

The generator labels positive and normal cases from construction, not by the
detector's output. Synthetic only; never a population specificity estimate.
"""
from __future__ import annotations
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import re
import tempfile

from risu_display_fidelity import verify_display_fidelity

SEED=20261108
NORMAL={"markdown-literal":400,"code-copy":400,"json-string-special":300}
INJECTED=200
TOKENS=[
    "A*p*", "_identifier_", "[label](path)", "<literal>", "abc\\xyz",
    "a`b", "x|y", "서울", "東京", "emoji🙂", "#header", "foo_bar_baz",
    "a**b", "literal &amp;", "x~~y", "file.name", "path/to/file",
    "MCP: value preserved", "2026-11-08", "a+b",
]

def span(text:str)->str:
    runs=[len(x.group()) for x in re.finditer(r"`+",text)]
    fence="`"*(max([0,*runs])+1)
    pad=" " if (text.startswith("`") or text.endswith("`")) else ""
    return fence+pad+text+pad+fence

def escaped(text:str)->str:
    return re.sub(r'([\\`*_{}\[\]()#+\-.!|<>])',r'\\\1',text)

def cases():
    rng=random.Random(SEED)
    items=[]
    for mode,number in NORMAL.items():
        for i in range(number):
            token=TOKENS[(i*7+rng.randrange(len(TOKENS)))%len(TOKENS)]
            if mode=="markdown-literal":
                raw=token+" #"+str(i) if i%3 else token
                # Entity decoding and struck-through Markdown must stay inside code.
                rendered=(escaped(raw) if i%2==0 and "&" not in raw and "~~" not in raw
                          else span(raw))
            elif mode=="code-copy":
                raw=(token if i%4 else "simple 123")+" #"+str(i)
                rendered=span(raw)
            else:
                choice=i%6
                raw=(
                    "row\n"+str(i) if choice==0 else
                    "" if choice==1 else
                    " "+str(i)+" " if choice==2 else
                    "col\t"+str(i) if choice==3 else
                    "cr\r\n"+str(i) if choice==4 else
                    "u\u2028"+str(i)
                )
                rendered=span(json.dumps(raw,ensure_ascii=False))
            items.append({"mode":mode,"raw":raw,"rendered":rendered,"kind":"normal"})
    for i in range(INJECTED):
        mode=tuple(NORMAL)[i%len(NORMAL)]
        raw="TEST_ORIGINAL_"+str(i)
        if mode=="json-string-special":
            raw="row\n"+str(i)
            rendered=span(json.dumps("CORRUPTED\n"+str(i)))
        elif mode=="markdown-literal":
            rendered=span("TEST_CHANGED_"+str(i))
        else:
            rendered=span("TEST_CHANGED_"+str(i))
        items.append({"mode":mode,"raw":raw,"rendered":rendered,"kind":"injected"})
    # Deterministic reorder ensures faults are not always in the last shard.
    rng.shuffle(items)
    return items

def evaluate(out:Path):
    out.mkdir(parents=True,exist_ok=True)
    items=cases()
    assert len(items)==sum(NORMAL.values())+INJECTED
    seen={key:Counter() for key in ("markdown-literal","code-copy","json-string-special")}
    issues=[]
    file_digests=[]
    with tempfile.TemporaryDirectory(prefix="risu-b11-normal-") as tmp:
        root=Path(tmp)
        for shard_no,begin in enumerate(range(0,len(items),40),1):
            sub=items[begin:begin+40]
            messages=[]
            for i,v in enumerate(sub,1):
                name="normal_"+v["mode"].replace("-","_")
                # Each source result is a separate synthetic JSON-RPC call
                # using exactly the same declared relation as the frozen product.
                messages += [
                  {"jsonrpc":"2.0","id":i,"method":"tools/call",
                   "params":{"name":name,"arguments":{}}},
                  {"jsonrpc":"2.0","id":i,"result":{"isError":False,
                   "structuredContent":{"value":v["raw"]},
                   "content":[{"type":"text","text":"**value:** "+v["rendered"]},
                              {"type":"text","text":"Unrelated **bold** and [docs](https://example.test)"}]}}
                ]
            path=root/("corpus_"+str(shard_no)+".jsonl")
            path.write_text("".join(json.dumps(m,ensure_ascii=False)+"\n" for m in messages),encoding="utf-8")
            file_digests.append(hashlib.sha256(path.read_bytes()).hexdigest())
            for mode in NORMAL:
                idx=[i for i,x in enumerate(sub,1) if x["mode"]==mode]
                if not idx:continue
                name="normal_"+mode.replace("-","_")
                contract={"schema":"risu-display-fidelity-contract-v1","rules":[{
                  "id":"b11_"+mode.replace("-","_"),
                  "tool":name,"pointer":"/value","line_prefix":"**value:** ",
                  "mode":mode,"is_error":False
                }]}
                # Replaying one mode per subshard avoids false matches from
                # any other mode's rule; report count, not only the aggregate.
                report=verify_display_fidelity(path,contract)
                actual=report["summary"]
                if actual["applicable_assertions"]!=len(idx):
                    raise RuntimeError("Unaccounted synthetic assertions in frozen checker")
                findings={v["line"]//2 for v in report["findings"]}
                # Request=2*i-1; response=2*i. Verify exact injection labels.
                for pos in idx:
                    case=sub[pos-1]
                    detected=pos in findings
                    seen[mode][case["kind"]]+=1
                    if case["kind"]=="normal" and detected:
                        seen[mode]["normal_false_positive"]+=1
                        issues.append({"shard":shard_no,"item":pos,"kind":"NORMAL_FALSE_POSITIVE","mode":mode})
                    if case["kind"]=="injected" and not detected:
                        seen[mode]["injected_miss"]+=1
                        issues.append({"shard":shard_no,"item":pos,"kind":"INJECTED_MISS","mode":mode})
                if actual["unverified"]:
                    seen[mode]["unverified"]+=actual["unverified"]
                    issues.append({"shard":shard_no,"kind":"UNVERIFIED","mode":mode,
                                   "count":actual["unverified"]})
    summary={
      "normal_total":sum(v["normal"] for v in seen.values()),
      "normal_false_positive":sum(v["normal_false_positive"] for v in seen.values()),
      "injected_total":sum(v["injected"] for v in seen.values()),
      "injected_missed":sum(v["injected_miss"] for v in seen.values()),
      "unverified":sum(v["unverified"] for v in seen.values()),
    }
    result={
      "schema":"risu-p6b11-frozen-detector-seeded-normal-score-v1",
      "baseline_detector_git_blob":"8bc96f64eba96a314479dfaea17af46b38e1ad0a",
      "seed":SEED,"source":"SYNTHETIC_DETERMINISTIC_NORMATIVE_CONSTRUCTION",
      "summary":summary,
      "per_mode":{name:dict(counts) for name,counts in seen.items()},
      "trace_shard_sha256":file_digests,
      "anomalies":issues[:100],
      "limits":"Deterministic generator supplies expected labels; a conditional sample audit only, not random real-world specificity or false-positive population estimate.",
    }
    (out/"normal_stress_score.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k not in ("trace_shard_sha256","anomalies")},indent=2))
    return result

if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("out",type=Path)
    a=p.parse_args()
    res=evaluate(a.out)
    if res["summary"]!={"normal_total":1100,"normal_false_positive":0,
          "injected_total":200,"injected_missed":0,"unverified":0}:
        raise SystemExit("Frozen normal corpus has visible quality failures; score JSON retained")
