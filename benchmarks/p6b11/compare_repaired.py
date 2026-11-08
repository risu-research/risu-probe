"""B11 regression comparison: permanently preserve B10 50 false positives.

The original B11 corpus is development after observation; an extra purposive,
prelisted Unicode and Markdown challenge is separately tagged post-discovery.
"""
from __future__ import annotations
import json
from pathlib import Path
import random

import normal_stress as baseline
from risu_display_fidelity_b11 import verify_display_fidelity as next_checker

CHALLENGE_SEED=61120261108

def challenge_cases():
    rng=random.Random(CHALLENGE_SEED)
    cases=[]
    for i in range(640):
        if i<200:
            mode="markdown-literal"
            values=[
                "Literal  separator", "Unicode   separator", "Unicode   separator",
                "A*p* is literal", "x\\y", "`two`", "_identifier_",
                "plain &copy;", "日本語", "emoji🙂 [A](B)", "a**b",
            ]
            raw=values[i%len(values)]+"-"+str(i)
            rendered=baseline.span(raw)
        elif i<400:
            mode="code-copy"
            raw=[
                "cursor_[value]*", "a`b", "route/path/to/item", "_hidden_",
                "[link](url)", "한글\u200d문자열", "mix € €", "NUL_LITERAL",
            ][i%8]+"-"+str(i)
            rendered=baseline.span(raw)
        else:
            mode="json-string-special"
            raw=[
                "row\u0085"+str(i), "row\u2028"+str(i),
                "row\u2029"+str(i), "row\r\n"+str(i),
                "row\n"+str(i), " "+str(i)+" ",
                "", "col\t"+str(i),
            ][i%8]
            rendered=baseline.span(json.dumps(raw,ensure_ascii=False))
        cases.append({"mode":mode,"raw":raw,"rendered":rendered,"kind":"normal"})
    for i in range(120):
        mode=("markdown-literal","code-copy","json-string-special")[i%3]
        raw="original-"+str(i)+("\u2028" if i%3==2 else "")
        if mode=="json-string-special":
            raw+="\nline"
            rendered=baseline.span(json.dumps("CHANGED-"+str(i)+"\nline",ensure_ascii=False))
        else:
            rendered=baseline.span("CHANGED-"+str(i))
        cases.append({"mode":mode,"raw":raw,"rendered":rendered,"kind":"injected"})
    rng.shuffle(cases)
    return cases

def run(out:Path):
    out.mkdir(parents=True,exist_ok=True)
    register=json.loads(Path("benchmarks/p6b11/followup_challenge_prelock.json").read_text())
    assert register["challenger_seed"]==CHALLENGE_SEED
    assert register["challenger_normal_count"]==640
    assert register["challenger_injected_count"]==120
    original=baseline.evaluate(out/"frozen_B10_replay")
    if original["summary"]!={"normal_total":1100,"normal_false_positive":50,
        "injected_total":200,"injected_missed":0,"unverified":0}:
        raise RuntimeError("Historical original B11 B10 frozen baseline changed")
    baseline.verify_display_fidelity=next_checker
    repaired=baseline.evaluate(out/"same_corpus_DEVELOPMENT")
    if repaired["summary"]!={"normal_total":1100,"normal_false_positive":0,
        "injected_total":200,"injected_missed":0,"unverified":0}:
        raise RuntimeError("New B11 repaired engine failed previously exposed development corpus")
    baseline.NORMAL={"markdown-literal":200,"code-copy":200,"json-string-special":240}
    baseline.INJECTED=120
    baseline.SEED=CHALLENGE_SEED
    baseline.cases=challenge_cases
    challenger=baseline.evaluate(out/"post_discovery_challenge")
    if challenger["summary"]!={"normal_total":640,"normal_false_positive":0,
        "injected_total":120,"injected_missed":0,"unverified":0}:
        raise RuntimeError("Newly prelisted post-discovery challenge exposed problems")
    for path,score,role in [
        (out/"same_corpus_DEVELOPMENT"/"normal_stress_score.json",repaired,"DEVELOPMENT_REPLAY_AFTER_50_BASELINE_FPS"),
        (out/"post_discovery_challenge"/"normal_stress_score.json",challenger,"PURPOSIVE_POST_DISCOVERY_CHALLENGE_NOT_POPULATION_GENERALIZATION"),
    ]:
        score.pop("baseline_detector_git_blob",None)
        score["schema"]="risu-p6b11-repaired-new-checker-score-v1"
        score["engine_role"]="SIDE_BY_SIDE_B11_EXPERIMENTAL_PREVIEW_NOT_B10_BASELINE"
        score["dataset_role"]=role
        score["actual_detector"]="risu_display_fidelity_b11"
        path.write_text(json.dumps(score,indent=2,sort_keys=True)+"\n")
    summary={
      "schema":"risu-p6b11-honest-original-and-repaired-audit-v1",
      "original_frozen_B10_score":original["summary"],
      "same_corpus_B11_development_replay":repaired["summary"],
      "separate_post_discovery_challenge":challenger["summary"],
      "observation":"Frozen B10 text line extraction mistakenly splits raw Unicode LS in valid Markdown inline code span; side-by-side B11 uses only CR LF as physical line boundaries",
      "claims":"Previous score not erased or retrospectively called clean. Repaired set and new purposive challenge are not random ecosystem false positive estimates.",
    }
    (out/"comparison_score.json").write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
    print(json.dumps(summary,indent=2,sort_keys=True))
if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("out",type=Path)
    a=p.parse_args()
    run(a.out)
