"""Manipulate PUBLIC synthetic real stdio fixture copies, never remote traffic.

Altered files are not genuine third-party defects; their expected outcomes are
independently audited.
"""
from __future__ import annotations
import argparse, copy, hashlib, json, subprocess
from pathlib import Path

CANARY='P6B5_SYNTHETIC_VALUE_NEVER_ECHO_SECRET'

def run(source:Path,out:Path,cli:Path)->None:
    raw=source.read_bytes()
    rows=[json.loads(x) for x in raw.splitlines()]
    assert len(rows)==11 and rows[0].get('method')=='initialize'
    assert rows[1]['result']['protocolVersion']=='2025-11-25'
    assert rows[3].get('method')=='tools/list'
    assert rows[4]['id']==101 and rows[4]['result']['tools']
    assert rows[6]['id']==102 and rows[8]['id']==103 and rows[10]['id']==104
    assert rows[10]['result'].get('isError') is True
    out.mkdir(parents=True,exist_ok=True)
    records=[]
    for name,expected,extra in [
        ('normal',[],[]),
        ('missing',['RMC501'],[]),
        ('wrong_type',['RMC502'],[]),
        ('invalid_schema',['RMC503'],[]),
        ('legacy_root',['RMC504'],[]),
        ('truncated',[],['MISSING_RESPONSE']),
        ('declared_protocol_conflict',[],['PROTOCOL_VERSION_CONFLICT']),
    ]:
        modified=copy.deepcopy(rows)
        if name=='missing':modified[6]['result'].pop('structuredContent')
        elif name=='wrong_type':modified[6]['result']['structuredContent']={'value':CANARY}
        elif name=='invalid_schema':
            modified[4]['result']['tools'][0]['outputSchema']={
                'type':'object','properties':{'value':{'type':'invalid-analyzer-type'}}}
        elif name=='legacy_root':
            modified[4]['result']['tools'][0]['outputSchema']={
                '$defs':{'Node':{'type':'object','additionalProperties':{'type':'integer'}}},
                '$ref':'#/$defs/Node'}
        elif name=='truncated':
            modified=[x for x in modified if x.get('id')!=103 or 'result' not in x]
        path=out/(name+'.jsonl')
        path.write_text(''.join(json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n' for x in modified))
        command=[str(cli),'verify-mcp-trace',str(path),'--format','json']
        if name=='declared_protocol_conflict':command+=['--protocol-version','2026-07-28']
        result=subprocess.run(command,capture_output=True,text=True,timeout=30)
        if result.returncode!=0:
            raise RuntimeError('RISU processing failure for synthetic control '+name+': '+result.stderr[-300:])
        report=json.loads(result.stdout)
        (out/(name+'_report.json')).write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
        records.append({'name':name,'expected_rules':expected,'expected_unverified':extra,
                        'input_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                        'report_sha256':hashlib.sha256((out/(name+'_report.json')).read_bytes()).hexdigest()})
    (out/'mutation_manifest.json').write_text(json.dumps({
        'schema':'risu-p6b5-public-mutations-v1',
        'source_sha256':hashlib.sha256(raw).hexdigest(),'cases':records,
        'origin':'PUBLIC_OWN_SYNTHETIC_TRANSFORMS_NOT_EXTERNAL_DEFECTS'
    },sort_keys=True,indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--cli',type=Path,required=True)
    a=p.parse_args();run(a.source,a.out,a.cli)
