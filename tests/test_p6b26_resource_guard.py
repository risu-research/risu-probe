"""B26 narrow authorization property tests; do not count as independent users."""
import base64
import copy
import json
from pathlib import Path
import os
import secrets
import sys
import tempfile
import time
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import risu_mcp_resource_guard as m

class ResourceSideRefusal(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/'owner.db'
        m.setup_db(self.db)
        self.issuer=m.Ed25519PrivateKey.generate()
        self.holder=m.Ed25519PrivateKey.generate()
        self.issuer_pub=m.public_key(self.issuer)
        self.now=int(time.time())
        self.policy={'schema':m.GRANT_SCHEMA,'audience':m.AUDIENCE,'issuer':m.ISSUER,
           'resource':'alpha','subject_public_key':m.public_key(self.holder),
           'method':'REPLACE','url_path':'/effect',
           'expected_pre_sha256':m.digest(b'alpha-original'),
           'desired_sha256':m.digest(b'alpha-authorized'),
           'nonce':secrets.token_hex(32),'not_before':self.now-2,
           'expires_at':self.now+60}
        self.grant=m.issue(self.policy,self.issuer)
        self.request={'schema':m.PROOF_SCHEMA,'resource':'alpha',
          'method':'REPLACE','url_path':'/effect','desired_value':'alpha-authorized',
          'request_id':secrets.token_hex(32),
          'grant_sha256':m.digest(m.canonical(self.grant))}
    def envelope(self):
        return m.proof(self.grant,self.request,self.holder)
    def denied(self,env,code=None, now=None):
        with self.assertRaises(m.Denied) as ctx:
            m.apply(self.db,env,self.issuer_pub,now=now if now is not None else self.now)
        if code:self.assertEqual(ctx.exception.code,code)
        self.assertEqual(m.audit_state(self.db)['resources']['alpha'],'alpha-original')
        self.assertEqual(m.audit_state(self.db)['resources']['beta'],'beta-protected')
        self.assertEqual(len(m.audit_state(self.db)['used_nonces']),0)
    def test_authorized_effect_atomic_exact_object(self):
        ok=m.apply(self.db,self.envelope(),self.issuer_pub,now=self.now)
        self.assertEqual(ok['status'],'APPLIED')
        self.assertEqual(m.audit_state(self.db)['resources'],{
           'alpha':'alpha-authorized','beta':'beta-protected'})
    def test_forged_issuer_denied(self):
        g=copy.deepcopy(self.grant)
        g['signature']=m.encode(b'\x00'*64)
        q=copy.deepcopy(self.request);q['grant_sha256']=m.digest(m.canonical(g))
        self.denied(m.proof(g,q,self.holder),'INVALID_OWNER_ISSUER_SIGNATURE')
    def test_stolen_grant_wrong_sender_denied(self):
        self.denied(m.proof(self.grant,self.request,m.Ed25519PrivateKey.generate()),
                    'INVALID_SUBJECT_PROOF')
    def test_wrong_object_even_with_legitimate_holder_signature_denied(self):
        q=copy.deepcopy(self.request);q['resource']='beta'
        self.denied(m.proof(self.grant,q,self.holder),'OBJECT_OR_METHOD_NOT_AUTHORIZED')
    def test_wrong_content_even_with_legitimate_holder_denied(self):
        q=copy.deepcopy(self.request);q['desired_value']='alpha-unapproved'
        self.denied(m.proof(self.grant,q,self.holder),'CONTENT_NOT_AUTHORIZED_BY_OWNER')
    def test_wrong_method_denied(self):
        q=copy.deepcopy(self.request);q['method']='DELETE'
        self.denied(m.proof(self.grant,q,self.holder),'UNSUPPORTED_CLIENT_ACTION')
    def test_extra_payload_key_denied(self):
        env=self.envelope();env['override']=True
        self.denied(env,'INVALID_ENVELOPE_FIELDS')
    def test_wrong_nonce_signature_denied(self):
        env=self.envelope();env['grant']['policy']['nonce']='0'*64
        self.denied(env,'INVALID_OWNER_ISSUER_SIGNATURE')
    def test_wrong_audience_denied_even_if_issuer_signed(self):
        q=copy.deepcopy(self.policy);q['audience']='other-server'
        g={'policy':q,'signature':m.encode(self.issuer.sign(m.GRANT_DOMAIN+m.canonical(q)))}
        r=copy.deepcopy(self.request);r['grant_sha256']=m.digest(m.canonical(g))
        self.denied(m.proof(g,r,self.holder),'GRANT_WRONG_AUDIENCE_OR_SCOPE')
    def test_expired_owner_issuer_permission_denied(self):
        self.policy['not_before']=self.now-100;self.policy['expires_at']=self.now-2
        self.grant=m.issue(self.policy,self.issuer)
        self.request['grant_sha256']=m.digest(m.canonical(self.grant))
        self.denied(self.envelope(),'OWNER_GRANT_EXPIRED_OR_FUTURE')
    def test_future_dated_permission_denied(self):
        self.policy['not_before']=self.now+10;self.policy['expires_at']=self.now+60
        self.grant=m.issue(self.policy,self.issuer)
        self.request['grant_sha256']=m.digest(m.canonical(self.grant))
        self.denied(self.envelope(),'OWNER_GRANT_EXPIRED_OR_FUTURE')
    def test_noncannonical_base64_denied(self):
        with self.assertRaises(m.Denied):m.b64_decode('abcd\n',32)
    def test_duplicate_json_keys_denied(self):
        with self.assertRaises(m.Denied):m.strict_json(b'{"a":1,"a":2}')
    def test_replay_survives_new_database_connection(self):
        env=self.envelope()
        m.apply(self.db,env,self.issuer_pub,now=self.now)
        with self.assertRaises(m.Denied) as ctx:
            m.apply(self.db,env,self.issuer_pub,now=self.now)
        self.assertEqual(ctx.exception.code,'OWNER_NONCE_ALREADY_CONSUMED')
        self.assertEqual(len(m.audit_state(self.db)['used_nonces']),1)
    def test_stale_prestate_fresh_nonce_denied(self):
        m.apply(self.db,self.envelope(),self.issuer_pub,now=self.now)
        self.policy['nonce']=secrets.token_hex(32)
        self.grant=m.issue(self.policy,self.issuer)
        self.request['grant_sha256']=m.digest(m.canonical(self.grant))
        with self.assertRaises(m.Denied) as ctx:
            m.apply(self.db,self.envelope(),self.issuer_pub,now=self.now)
        self.assertEqual(ctx.exception.code,'OWNER_EXPECTED_PRESTATE_MISMATCH')
        self.assertEqual(len(m.audit_state(self.db)['used_nonces']),1)
    def test_no_grant_no_server_effect(self):
        self.denied({'request':self.request},'INVALID_ENVELOPE_FIELDS')

if __name__=='__main__':unittest.main()
