#!/usr/bin/env python3
"""No labels from the source version are trusted; summarize observed outcomes."""
from pathlib import Path
import json
P=Path(__file__).resolve().parent
r={k:json.loads((P/'results'/f'{k}.json').read_text()) for k in ['before','after']}
statuses={variant:{z['operation']:z['classification'] for z in item['results']} for variant,item in r.items()}
expected={
 'before':{'PutObject':'MISSING_GUARD_CANDIDATE','CompleteMultipartUpload':'MISSING_GUARD_CANDIDATE','CopyObject':'MISSING_GUARD_CANDIDATE'},
 'after':{'PutObject':'STRUCTURALLY_GUARDED','CompleteMultipartUpload':'STRUCTURALLY_GUARDED','CopyObject':'MISSING_GUARD_CANDIDATE'},
}
assert statuses==expected,(statuses,expected)
mutants=json.loads((P/'results'/'mutants.json').read_text())
assert len(mutants)>=20
assert all(z['status']!='STRUCTURALLY_GUARDED' for z in mutants)
summary={'schema':'risu.condition-effect-v07.evaluation','classification':statuses,
 'mutations':{'count':len(mutants),'overconfident_positive':sum(z['status']=='STRUCTURALLY_GUARDED' for z in mutants),
 'abstain':sum(z['status']=='ABSTAIN' for z in mutants),
 'missing_guard_candidate':sum(z['status']=='MISSING_GUARD_CANDIDATE' for z in mutants)},
 'known_external_bugs_not_original_discoveries':True,'novelty_assessed':'INSUFFICIENT_FOR_PLDI_CORE_CONTRIBUTION',
 'confidence':'bounded historical source and hand-selected mutations only'}
(P/'results'/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print('CONDITION_EFFECT_V07_PASS',json.dumps(summary,sort_keys=True))
