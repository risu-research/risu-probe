"""B26 independent audit; intentionally imports no RISU service or test harness.

Replays resource-state claims from actual SQLite pages, checks cryptographic
signatures and exact bytes, and refuses hidden/incomplete cases. Does not
replace verification of the Linux runner identity or external provider.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sqlite3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

EXPECTED={
 'no_grant':422,
 'forged_issuer_signature':403,
 'stolen_grant_wrong_client_key':403,
 'compromised_client_other_object':403,
 'compromised_client_other_bytes':403,
 'compromised_client_other_method':403,
 'owner_issued_future_grant':403,
 'owner_issued_expired_grant':403,
 'consumed_grant_replay':409,
 'fresh_grant_stale_prestate':409,
 'replay_after_resource_server_restart':409}

def demand(ok,why):
    if not ok:raise ValueError(why)
def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def b64(s):
    data=base64.b64decode(s,validate=True)
    demand(base64.b64encode(data).decode()==s,'Noncanonical base64 in recorded attestation')
    return data

def verify(result, db):
    demand(result['schema']=='risu-b26-real-posix-http-sqlite-resource-side-effect-v1',
           'Unexpected provenance schema')
    identities=[result[x] for x in ('issuer_uid','resource_service_uid','agent_uid','attacker_uid')]
    demand(all(type(x) is int for x in identities) and len(set(identities))==4,
           'Fixture principal identities are not distinct')
    demand(result['resource_db_file_owner_uid']==result['resource_service_uid'] and
           result['resource_db_file_mode']=='0o600' and
           result['resource_service_data_dir_mode']=='0o700',
           'Actual fixture protected resource permission evidence missing')
    demand(result['posix_agent_access']=={
        'resource_db_read':'DENIED_BY_POSIX_DAC',
        'resource_db_write':'DENIED_BY_POSIX_DAC',
        'owner_issuer_private_key':'DENIED_BY_POSIX_DAC'},
        'Real untrusted OS uid could access resource DB or issuer secret')
    demand(result['root_fixture_administrator_outside_attacker_model'] is True and
           result['real_external_service_owner']=='NOT_TESTED' and
           result['real_independent_human_authorization']=='NOT_TESTED',
           'Trust boundary overstated in run evidence')
    g=result['owner_grant'];p=g['policy'];e=result['successful_request_envelope'];q=e['request']
    pub=b64(result['issuer_public_key_b64'])
    demand(len(pub)==32 and p['audience']=='risu-b26-local-owner-resource-service-a' and
           p['issuer']=='risu-b26-posix-owner-issuer' and p['resource']=='alpha' and
           p['method']=='REPLACE' and p['url_path']=='/effect',
           'Signed grant wrong target')
    demand(g==e['grant'],'Successful request not backed by exact issuer grant')
    Ed25519PublicKey.from_public_bytes(pub).verify(
        b64(g['signature']),b'RISU-B26-ISSUER-V1\x00'+canonical(p))
    holder=b64(p['subject_public_key']);demand(len(holder)==32,'Invalid holder public key')
    demand(q['grant_sha256']==sha(canonical(g)) and q['resource']=='alpha' and
           q['desired_value']=='alpha-authorized' and q['method']=='REPLACE',
           'Holder request differs from original scope')
    Ed25519PublicKey.from_public_bytes(holder).verify(
        b64(e['proof_signature']),b'RISU-B26-HOLDER-V1\x00'+canonical({
          'grant_sha256':sha(canonical(g)),'request':q}))
    demand(p['expected_pre_sha256']==sha(b'alpha-original') and
           p['desired_sha256']==sha(b'alpha-authorized'),
           'Unexpected signed pre/post bytes')
    with sqlite3.connect(f'file:{Path(db).resolve()}?mode=ro',uri=True) as conn:
        values=dict(conn.execute('SELECT resource,value FROM resources ORDER BY resource'))
        spent=[x[0] for x in conn.execute('SELECT nonce FROM used ORDER BY nonce')]
        request_ids=[x[0] for x in conn.execute('SELECT request_id FROM used')]
    demand(values=={'alpha':'alpha-authorized','beta':'beta-protected'},
           'Actual SQLite data does not match the approved effect')
    demand(spent==[p['nonce']] and request_ids==[q['request_id']],
           'Actual SQLite transaction nonce / request does not match approval')
    demand(result['actual_after']=={'resources':values,'used_nonces':spent} and
           result['expected_before']=={'resources':{'alpha':'alpha-original',
           'beta':'beta-protected'},'used_nonces':[]},
           'Live states disagree with independently opened database')
    events=result['cases']
    demand(type(events) is list and len(events)==13 and
           len({z['case'] for z in events})==13,
           'Missing or repeated exercise case')
    observed={z['case']:z['http_status'] for z in events}
    demand(all(type(status) is int for status in observed.values()),
           'Invalid recorded HTTP outcomes')
    for case,http in EXPECTED.items():
        demand(observed.get(case)==http,f'Negative bypass test mismatch: {case}')
    race=[observed.get(f'concurrent_same_grant_{i}') for i in range(2)]
    demand(sorted(race)==[200,409],'Owner nonce one-time transaction not proven')
    demand(result['number_of_http_requests']==13 and
           result['number_of_successful_writes']==1 and
           result['number_of_failed_client_requests']==12,
           'Recorded cardinality unsupported')
    demand(result['expected_authorized_commit_hash']==sha(values['alpha'].encode()),
           'Authorized bytes hash mismatch')
    return {
      'schema':'risu-b26-independent-direct-sqlite-crypto-evidence-audit-v1',
      'conclusion':'PASS',
      'source_is_not_imported_from_product':True,
      'verified_real_os_uids':identities,
      'approved_resource':'alpha',
      'other_resource_unchanged':'beta',
      'verified_issuer_signature':True,
      'verified_subject_proof':True,
      'actual_sqlite_sha256':sha(Path(db).read_bytes()),
      'actual_object_sha256':sha(values['alpha'].encode()),
      'server_consumed_nonces':1,
      'successful_effects':1,
      'denied_http_attacks':12,
      'root_admin_bypass':'OUTSIDE_TESTED_THREAT_MODEL',
      'third_party_human':'NOT_TESTED',
      'upstream_mcp_vulnerability':'NOT_TESTED'
    }

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--result',required=True)
    parser.add_argument('--db',required=True)
    parser.add_argument('--out',required=True)
    p=parser.parse_args()
    report=verify(json.loads(Path(p.result).read_text()),p.db)
    Path(p.out).write_bytes(canonical(report)+b'\n')
    print('RISU_B26_INDEPENDENT_DIRECT_SQLITE_CRYPTO_AUDIT_PASS',json.dumps(report,sort_keys=True))
