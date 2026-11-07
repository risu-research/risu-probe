"""Unified P0 classification for CLI, SARIF, Markdown, and CI.

Legacy verdict is deliberately retained; decision_v1 is evidence-calibrated.
REVIEW never means preservation proved. A strict-carrier violation is not
automatically proof that the response body has been destroyed.
"""
from __future__ import annotations
POLICIES=('calibrated','strict-carrier')
OPS_FAILURES={'ERROR','INVALID_CATALOG','MISSING_TOOL','UNSTABLE_SOURCE'}
LEGACY_FAILURES={'LOSS','LOSS_AND_INVENTED','INVENTED'}

def decide(item:dict,policy:str='calibrated')->dict:
    if policy not in POLICIES:
        raise ValueError('unknown policy')
    legacy=item.get('verdict','ERROR')
    ev=item.get('evidence_v1') or {}
    carrier=ev.get('machine_carrier','NONE_CERTIFIED')
    recovery=ev.get('body_recovery','NOT_ASSESSED')
    flag=ev.get('error_flag')
    status=ev.get('http_status')
    if legacy in OPS_FAILURES:
        outcome,reason='FAIL','INSPECTION_INCOMPLETE'
    elif legacy=='INPUT_REQUIRED' or recovery=='DEFERRED':
        outcome,reason='DEFERRED','AWAITING_TOOL_RESULT'
    elif item.get('inventions') or legacy=='INVENTED':
        outcome,reason='FAIL','UNSUPPORTED_RETRY_CLAIM'
    elif flag in ('ERROR_FLAG_LOST','SPURIOUS_ERROR_FLAG'):
        outcome,reason='FAIL',flag
    elif recovery=='PROVEN_TRUNCATED_PREVIEW':
        outcome,reason='FAIL','OBSERVED_CLIPPED_PREVIEW'
    elif policy=='strict-carrier' and legacy in LEGACY_FAILURES:
        outcome,reason='FAIL','STRICT_CARRIER_CONTRACT_VIOLATION'
    elif legacy=='NOT_APPLICABLE':
        outcome,reason='NOT_APPLICABLE','OUT_OF_SCOPE'
    elif recovery=='EXACT_MACHINE' and carrier in (
        'STRUCTURED_CONTENT_EXACT','STRUCTURED_ENVELOPE_EXACT'):
        outcome,reason='PASS','STRUCTURED_BODY_CONFIRMED'
    elif recovery=='EXACT_MACHINE':
        outcome,reason='REVIEW',(
            'METADATA_ONLY_CARRIER' if carrier=='METADATA_ONLY_EXACT'
            else 'TYPED_RESOURCE_ONLY')
    elif recovery=='EXACT_JSON_TEXT':
        outcome,reason='REVIEW','EXACT_JSON_TEXT_ONLY'
    elif recovery=='UNVERIFIED_TEXT':
        outcome,reason='REVIEW','UNVERIFIED_TEXT'
    elif recovery=='NO_EXACT_CARRIER_OBSERVED':
        outcome,reason='REVIEW','NO_EXACT_CARRIER_CERTIFIED'
    elif recovery=='NOT_ASSESSED' and ev.get('reason')=='CONSUMER_SCOPED_CHECK':
        outcome,reason='REVIEW','NEEDS_EXPLICIT_CONSUMER_WITNESS'
    elif legacy=='PRESERVED' and not ev:
        outcome,reason='REVIEW','NO_CALIBRATED_EVIDENCE'
    elif legacy in LEGACY_FAILURES:
        outcome,reason='REVIEW','LOSS_NOT_INDEPENDENTLY_PROVEN'
    else:
        outcome,reason='REVIEW','INSUFFICIENT_EVIDENCE'
    if outcome in ('PASS','REVIEW') and status in (
        'MACHINE_STATUS_CONFLICT','TEXT_STATUS_CONFLICT'):
        outcome,reason='FAIL','EXPLICIT_HTTP_STATUS_CONFLICT'
    return {'schema':'risu-decision-v1','policy':policy,
            'outcome':outcome,'reason':reason,
            'level':('error' if outcome=='FAIL' else
                     'warning' if outcome=='REVIEW' else
                     'note' if outcome=='DEFERRED' else 'none'),
            'legacy_verdict':legacy,
            'body_recovery':recovery,'machine_carrier':carrier,
            'error_flag':flag or 'NOT_ASSESSED',
            'http_status':status or 'NOT_ASSESSED'}

def apply(report:dict,policy:str='calibrated')->dict:
    if policy not in POLICIES:raise ValueError('unknown policy')
    for item in report.get('results',[]):
        item['decision_v1']=decide(item,policy)
    report['decision_policy']=policy
    report['decision_summary']={x:sum(i['decision_v1']['outcome']==x
                                     for i in report['results'])
                                for x in ('PASS','REVIEW','FAIL','DEFERRED','NOT_APPLICABLE')}
    return report

def blocks(item:dict,*,fail_review:bool=False)->bool:
    outcome=(item.get('decision_v1') or decide(item))['outcome']
    return outcome=='FAIL' or (fail_review and outcome in ('REVIEW','DEFERRED'))

def any_blocking(report:dict,*,fail_review:bool=False,new_only:bool=False)->bool:
    return any(blocks(item,fail_review=fail_review) and
               (not new_only or item.get('baseline')!='known'
                or item.get('verdict') in OPS_FAILURES)
               for item in report.get('results',[]))
