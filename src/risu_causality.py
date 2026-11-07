"""P4-J evidence gate: developer assertion never proves HTTP -> MCP causation.

A stronger claim requires an independently configured Ed25519 verifier trust root,
exact capture-file hashes, and an independently signed cross-boundary observation
receipt. A signature authenticates the selected recorder's claim; it cannot
establish that the recorder is honest, physically independent, or correct.

The verifier has no network, subprocess or model calls and emits no raw values.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

SCHEMA='risu-boundary-observer-receipt-v1'
TRUST='risu-boundary-trust-store-v1'
DIGEST=re.compile('[0-9a-f]{64}\\Z')
KEYID=re.compile('[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\\Z')
CALL_KIND=['MCP_REQUEST','HTTP_REQUEST','HTTP_RESPONSE','MCP_RESPONSE']


def canonical(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,
                      separators=(',',':'),allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sha_bytes(value):return hashlib.sha256(value).hexdigest()


def _read_json(path,limit=1_000_000):
    from risu_capture import loads, _read
    value=_read(path)
    if len(value)>limit:raise ValueError('causal witness/trust store exceeds limit')
    return loads(value.decode('utf-8'))


def _file_binding(directory,witness):
    from risu_capture import _read
    expected={'capture.har','mcp.jsonl','pairs.json'}
    binding=witness.get('file_sha256')
    if not isinstance(binding,dict) or set(binding)!=expected:
        raise ValueError('causal witness requires exact three capture-file hashes')
    for name in expected:
        h=binding[name]
        if not isinstance(h,str) or not DIGEST.fullmatch(h):
            raise ValueError('invalid witness capture hash')
        if sha_bytes(_read(directory/name))!=h:
            raise ValueError('causal witness capture bytes changed or mismatched')


def _trust_verify(witness, trust_file, capture_dir):
    if trust_file is None:
        return False,'NO_EXTERNAL_TRUST_ROOT'
    trust_file=Path(trust_file)
    if trust_file.is_symlink() or not trust_file.is_file():
        raise ValueError('trusted recorder key file must be a nonsymlink regular file')
    try:
        trust_file.resolve().relative_to(capture_dir.resolve())
    except ValueError:pass
    else:raise ValueError('trusted recorder key must be selected outside untrusted capture directory')
    trust=_read_json(trust_file,100_000)
    if not isinstance(trust,dict) or trust.get('schema')!=TRUST:
        raise ValueError('invalid external causal trust-store schema')
    keys=trust.get('trusted_recorders')
    if not isinstance(keys,list) or not 1<=len(keys)<=20:raise ValueError('invalid trusted recorder inventory')
    sig=witness.get('signature')
    if not isinstance(sig,dict) or set(sig)!={'algorithm','key_id','value_base64'} or sig['algorithm']!='Ed25519':
        raise ValueError('unsupported causal observer signature')
    keyid=sig.get('key_id')
    if not isinstance(keyid,str) or not KEYID.fullmatch(keyid):
        raise ValueError('invalid causal observer key id')
    matching=[x for x in keys if isinstance(x,dict) and x.get('key_id')==keyid]
    if len(matching)!=1:raise ValueError('causal observer signing key is not independently trusted')
    key=matching[0]
    if key.get('issuer')!=witness.get('issuer') or key.get('observer_kind')!='BOUNDARY_RECORDER_V1':
        raise ValueError('causal witness issuer or observer scope not authorized')
    try:
        public=base64.b64decode(key['ed25519_public_key_base64'],validate=True)
        signature=base64.b64decode(sig['value_base64'],validate=True)
    except (KeyError,TypeError,ValueError) as exc:raise ValueError('invalid causal signature/key base64') from exc
    if len(public)!=32 or len(signature)!=64:raise ValueError('invalid Ed25519 signature or key lengths')
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        raise ValueError('trusted witness verification requires cryptography package') from exc
    statement={k:v for k,v in witness.items() if k!='signature'}
    try:Ed25519PublicKey.from_public_bytes(public).verify(signature,canonical(statement))
    except (InvalidSignature,ValueError) as exc:raise ValueError('causal witness signature verification FAILED') from exc
    return True,'TRUSTED_BOUNDARY_RECORDER_SIGNATURE'


def _id(value):
    from risu_capture import _id as native_id
    return native_id(value)


def _frames(directory):
    from risu_capture import _jsonl
    frames=_jsonl(directory,'mcp.jsonl')
    request={};response={}
    for row in frames:
        if row.get('jsonrpc')!='2.0' or 'id' not in row:continue
        i=_id(row['id'])
        if row.get('method')=='tools/call':
            if i in request:raise ValueError('duplicate call in observed evidence')
            request[i]=row
        elif 'result' in row or 'error' in row:
            if i in response:raise ValueError('duplicate response in observed evidence')
            response[i]=row
    return request,response


def _header(req,name):
    h=req.get('headers',[])
    if not isinstance(h,list):raise ValueError('invalid witnessed HTTP headers')
    values=[x.get('value') for x in h if isinstance(x,dict) and str(x.get('name','')).lower()==name.lower()]
    if len(values)!=1 or not isinstance(values[0],str):
        raise ValueError('causal request correlation header missing, duplicated or malformed')
    return values[0]


def _verify_links(directory,witness,cases):
    from risu_capture import _jsonfile
    har=_jsonfile(directory,'capture.har')
    pairs=_jsonfile(directory,'pairs.json')
    links=witness.get('links')
    if not isinstance(links,list) or not 1<=len(links)<=50:
        raise ValueError('causal witness must contain 1-50 witnessed links')
    requests,responses=_frames(directory)
    origpairs={p['case_id']:p for p in pairs['pairs']}
    allowed={x['id']:x for x in cases}
    confirmed=set()
    for link in links:
        if not isinstance(link,dict):raise ValueError('invalid witnessed link')
        if set(link)!={'case_id','http_entry','mcp_call_id','tool','trace_token_sha256','events'}:
            raise ValueError('incomplete or extra causal witness link fields')
        case_id=link['case_id']
        if not isinstance(case_id,str) or case_id in confirmed or case_id not in origpairs or case_id not in allowed:
            raise ValueError('unknown, duplicated or unmatched witnessed case')
        p=origpairs[case_id]
        for name in ('http_entry','tool','mcp_call_id'):
            if type(p.get(name)) is not type(link.get(name)) or p[name]!=link[name]:
                raise ValueError('witness pair differs from captured MCP/HTTP pairing')
        idx=p['http_entry'];mid=_id(p['mcp_call_id'])
        try:
            req=requests[mid];result=responses[mid];entry=har['log']['entries'][idx]
        except (KeyError,IndexError,TypeError) as exc:
            raise ValueError('witness references missing real protocol events') from exc
        if 'error' in result or req['params']['name']!=p['tool']:
            raise ValueError('causal witness references non-tool response')
        args=req['params'].get('arguments')
        if not isinstance(args,dict) or not isinstance(args.get('risu_trace_token'),str):
            raise ValueError('missing shared trace token in observed MCP call')
        token=args['risu_trace_token']
        if not 16<=len(token)<=128 or not re.fullmatch('[A-Za-z0-9_-]+',token):
            raise ValueError('bad correlation token')
        if _header(entry['request'],'X-RISU-Trace-Token')!=token:
            raise ValueError('MCP and HTTP boundary observations do not share a token')
        if sha_bytes(token.encode())!=link['trace_token_sha256']:
            raise ValueError('correlation token digest changed')
        # Exact originally recorded events and *their order* are attested by the recorder.
        expected=[req,entry['request'],entry['response'],result]
        events=link['events']
        if not isinstance(events,list) or len(events)!=4:
            raise ValueError('witness must attest four ordered execution boundaries')
        prev=-1
        for kind,original,event in zip(CALL_KIND,expected,events):
            if not isinstance(event,dict) or set(event)!={'kind','sequence','sha256'}:
                raise ValueError('invalid causal boundary event')
            seq=event['sequence']
            if event['kind']!=kind or type(seq) is not int or seq<=prev or seq<0:
                raise ValueError('out-of-order or wrong causal boundary event')
            if event['sha256']!=digest(original):
                raise ValueError('signed witness mismatches HTTP/MCP boundary contents')
            prev=seq
        confirmed.add(case_id)
    return confirmed


def verify(directory,trust_file,cases):
    directory=Path(directory)
    witness_file=directory/'causal_witness.json'
    if not witness_file.exists():
        return set(),'NO_INDEPENDENT_RUNTIME_WITNESS'
    witness=_read_json(witness_file)
    if not isinstance(witness,dict) or witness.get('schema')!=SCHEMA:
        raise ValueError('invalid causal witness document')
    if witness.get('observer_kind')!='BOUNDARY_RECORDER_V1' or not isinstance(witness.get('session_id'),str):
        raise ValueError('causal witness missing recognized recorder/session fields')
    _file_binding(directory,witness)
    attested,why=_trust_verify(witness,trust_file,directory)
    if not attested:return set(),why
    return _verify_links(directory,witness,cases),why


def gate(report,payload,capture_dir=None,trust_file=None):
    native=capture_dir is not None
    observations=payload.get('cases') if isinstance(payload,dict) else None
    if native and (not isinstance(observations,list) or len(observations)!=len(report['results'])):
        raise ValueError('causal evidence gate mismatched capture case counts')
    trusted,reason=verify(capture_dir,trust_file,observations) if native else (set(),'SAVED_OBSERVATIONS_NOT_INDEPENDENTLY_BOUND')
    verdicts=[]
    for result in report['results']:
        case_id=result['id'];legacy=result.get('verdict')
        trust='TRUSTED_BOUNDARY_OBSERVER' if case_id in trusted else 'DEVELOPER_DECLARED_ONLY'
        if legacy in ('LOSS','LOSS_AND_INVENTED','INVENTED'):
            outcome='CONFIRMED_LOSS' if case_id in trusted else 'CONDITIONAL_MISMATCH'
        elif legacy=='PRESERVED':
            outcome='WITNESSED_NO_LOSS_IN_OBSERVED_FIELDS' if case_id in trusted else 'CONDITIONAL_MATCH'
        else:outcome='INSUFFICIENT_EVIDENCE'
        item={'id':case_id,'legacy_verdict':legacy,'causal_level':trust,
              'outcome':outcome,'reason':reason if case_id not in trusted else 'SIGNED_CORRELATED_FOUR_BOUNDARY_TRACE',
              'scope':'OBSERVED_HTTP_TO_MCP_ONLY'}
        result['causal_v1']=item
        verdicts.append(item)
    counts={x:sum(v['outcome']==x for v in verdicts) for x in (
        'CONFIRMED_LOSS','CONDITIONAL_MISMATCH','CONDITIONAL_MATCH',
        'WITNESSED_NO_LOSS_IN_OBSERVED_FIELDS','INSUFFICIENT_EVIDENCE')}
    return {'schema':'risu-causal-evidence-gate-v1','trust_root':'EXTERNAL_OPERATOR_CONFIGURED' if trust_file else 'NONE',
        'witness_reason':reason,'summary':counts,'cases':verdicts,
        'boundary':'Only signed, independently trusted same-execution HTTP/MCP boundary records allow CONFIRMED_LOSS. The signer is trusted by the operator; a signature by itself cannot prove recorder honesty, independent operation, or real-world vendor behavior. Legacy PASS/FAIL and verdicts are retained for compatibility but have no causal-proof authority.'}


def render_summary(summary):
    lines=['Causal Evidence Gate | only verified independent runtime witnesses justify confirmed findings']
    for item in summary['cases']:
        lines.append('%s: %s | link=%s | raw=%s' % (
            item['id'],item['outcome'],item['causal_level'],item['legacy_verdict']))
    lines.append('Authoritative proof-gated summary: '+str(summary['summary']))
    lines.append('Scope: signer is trusted by operator; standalone hashes and developer pairs do not prove causality.')
    return '\n'.join(lines)+'\n'
