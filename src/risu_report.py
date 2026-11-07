"""Deterministic, source-minimizing output formats for RISU Probe.

A SARIF location identifies the *test definition*, not a confirmed faulty source line.
No raw API response bodies are included in generated reports.
"""
from __future__ import annotations

import json
from pathlib import Path

RULES = {
    'LOSS': ('RISU001', 'Lost machine-readable data', 'error'),
    'INVENTED': ('RISU002', 'Unsupported machine-readable claim', 'error'),
    'LOSS_AND_INVENTED': ('RISU003', 'Lost and invented data', 'error'),
    'UNSTABLE_SOURCE': ('RISU004', 'Source changed during probe', 'warning'),
    'ERROR': ('RISU005', 'Probe could not complete', 'error'),
    'MISSING_TOOL': ('RISU006', 'MCP tool missing from catalog', 'error'),
    'INVALID_CATALOG': ('RISU007', 'Invalid MCP tools/list result', 'error'),
    'INPUT_REQUIRED': ('RISU008', 'MCP tool result is awaiting input', 'warning'),
}


def to_sarif(report: dict, *, case_file: str='risu-probe.json') -> dict:
    from risu_decision import decide
    spec={
        'FAIL':('RISU201','Actionable failure or incomplete inspection','error'),
        'REVIEW':('RISU202','Potential compatibility problem requires review','warning'),
        'DEFERRED':('RISU203','MCP tool is awaiting input','note'),
    }
    rules=[{'id':code,'name':state,'shortDescription':{'text':title},
            'defaultConfiguration':{'level':level}}
           for state,(code,title,level) in spec.items()]
    findings=[]
    for item in report.get('results',[]):
        decision=item.get('decision_v1') or decide(item,report.get('decision_policy','calibrated'))
        state=decision['outcome']
        if state not in spec:continue
        code,_,level=spec[state]
        finding={'ruleId':code,'level':level,
                 'message':{'text':f"{item.get('id','?')}: {state} ({decision['reason']}); legacy={item.get('verdict','unknown')}"},
                 'locations':[{'physicalLocation':{'artifactLocation':{'uri':case_file}}}],
                 'properties':{'caseId':item.get('id'),'decision':state,
                               'decisionReason':decision['reason'],
                               'legacyVerdict':item.get('verdict'),
                               'bodyRecovery':decision['body_recovery'],
                               'machineCarrier':decision['machine_carrier'],
                               'locationKind':'test-definition-only'}}
        if item.get('baseline') in ('known','new'):
            finding['baselineState']='unchanged' if item['baseline']=='known' else 'new'
        findings.append(finding)
    return {'version':'2.1.0',
            '$schema':'https://json.schemastore.org/sarif-2.1.0.json',
            'runs':[{'tool':{'driver':{'name':'RISU Probe',
                                      'version':report.get('version','unknown'),
                                      'informationUri':'https://github.com/risu-research/openapi-mcp-problem-semantics',
                                      'rules':rules}},
                     'results':findings}]}

def to_markdown(report: dict) -> str:
    from risu_decision import decide
    lines=['# RISU Probe report','',
           '| Case | Decision | Legacy verdict | Body evidence | Reason |',
           '| --- | --- | --- | --- | --- |']
    esc=lambda value:str(value).replace('|',r'\|').replace('\n',' ')
    for item in report.get('results',[]):
        d=item.get('decision_v1') or decide(item,report.get('decision_policy','calibrated'))
        tag=(' [known]' if item.get('baseline')=='known' else
             ' [new]' if item.get('baseline')=='new' else '')
        lines.append(f"| {esc(item.get('id','?'))} | {d['outcome']}{tag} | {esc(item.get('verdict','?'))} | {d['body_recovery']} | {d['reason']} |")
    lines.extend(['','Policy: '+str(report.get('decision_policy','calibrated')),
                  'Decisions: '+str(report.get('decision_summary',{})),
                  'Cases checked: '+str(len(report.get('results',[]))),
                  '', '> Legacy carrier findings are independent of calibrated claims about body loss. No raw API bodies are included.'])
    return '\n'.join(lines)+'\n'

def emit(report: dict, fmt: str, case_file: str) -> str:
    if fmt == 'json':
        return json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if fmt == 'sarif':
        return json.dumps(to_sarif(report, case_file=case_file), ensure_ascii=False, indent=2) + '\n'
    if fmt == 'markdown':
        return to_markdown(report)
    raise ValueError('unknown output format')
