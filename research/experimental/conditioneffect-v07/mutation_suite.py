#!/usr/bin/env python3
"""Predeclared failure modes for bounded source-shape checker, plus evidence tampering."""
from pathlib import Path
import json, subprocess, tempfile, shutil
from verify_certificate import check
P=Path(__file__).resolve().parent
SRC=P/'external'/'after'
CASES={
  'wrong_request_bucket':('handler_object.go','bucket := chi.URLParam(r, "bucket")','bucket := "unrelated"'),
  'wrong_request_key':('handler_object.go','key := objectKey(r)','key := "unrelated"'),
  'mutate_key_after_guard':('handler_object.go','obj := &Object{','key = "unrelated"\n\tobj := &Object{'),
  'mutate_object_key_before_commit':('handler_object.go','stamp, aerr := h.beginVersion(r.Context(), b, obj, obj.LastModified)','obj.Key = "unrelated"\n\tstamp, aerr := h.beginVersion(r.Context(), b, obj, obj.LastModified)'),
  'remove_lock_defer':('handler_object.go','defer h.objectLocks.Lock(objectStoreKey(bucket, key))()', 'defer func() {}()'),
  'lock_wrong_bucket':('handler_object.go','objectStoreKey(bucket, key)', 'objectStoreKey("wrong-bucket", key)'),
  'lock_wrong_key':('handler_object.go','objectStoreKey(bucket, key)', 'objectStoreKey(bucket, "wrong-key")'),
  'guard_wrong_key':('handler_object.go','h.checkConditionalWrite(r.Context(), cond, bucket, key)', 'h.checkConditionalWrite(r.Context(), cond, bucket, "wrong-key")'),
  'guard_wrong_bucket':('handler_object.go','h.checkConditionalWrite(r.Context(), cond, bucket, key)', 'h.checkConditionalWrite(r.Context(), cond, "wrong-bucket", key)'),
  'lose_active_condition':('handler_object.go','if cond.active() {','if false {'),
  'replace_guard_function':('handler_object.go','h.checkConditionalWrite(r.Context(), cond, bucket, key)', 'h.checkSomethingElse(r.Context(), cond, bucket, key)'),
  'effect_before_guard':('handler_object.go','if cond.active() {','h.store.putObjectMeta(r.Context(), obj)\n\tif cond.active() {'),
  'new_go_statement':('handler_object.go','if cond.active() {','go func() { _ = bucket }()\n\tif cond.active() {'),
  'clear_parse_error_before_exit':('handler_object.go','cond, aerr := parseConditionalWrite(r)', 'cond, aerr := parseConditionalWrite(r)\n\taerr = nil'),
  'drop_condition_error_return':('handler_object.go','protocol.WriteXMLError(w, r, aerr)\n\t\treturn\n\t}\n\tif cond.active()', 'protocol.WriteXMLError(w, r, aerr)\n\t}\n\tif cond.active()'),
  'flip_if_match':('conditional_write.go','if !etagMatches(current.ETag, c.ifMatch) {','if etagMatches(current.ETag, c.ifMatch) {'),
  'flip_if_none_match':('conditional_write.go','if c.ifNoneMatch && current != nil {','if c.ifNoneMatch && current == nil {'),
  'disable_helper_check':('conditional_write.go','return c.evaluate(key, current)','return nil'),
  'helper_skip_lookup':('conditional_write.go','current, aerr := h.store.lookupObjectMeta(ctx, bucket, key)','current, aerr := (*Object)(nil), (*protocol.AWSError)(nil)'),
  'copy_guard_only':('handler_object.go','func (h *Handler) CopyObject(w http.ResponseWriter, r *http.Request) {','func (h *Handler) CopyObject(w http.ResponseWriter, r *http.Request) {\n if cond.active() { defer h.objectLocks.Lock(objectStoreKey(destBucket,destKey))() }'),
}
if not (P/'cextract').is_file():
    subprocess.run(['go','build','-o',str(P/'cextract'),str(P/'cextract.go')],check=True)
observations=[]
with tempfile.TemporaryDirectory() as temp:
 for name,(filename,old,new) in CASES.items():
    td=Path(temp)/name;td.mkdir()
    for source in SRC.glob('*.go'): shutil.copy2(source,td/source.name)
    target=td/filename
    raw=target.read_text()
    if old not in raw:raise AssertionError(f'{name}: target missing')
    target.write_text(raw.replace(old,new,1))
    out=td/'record.json'
    p=subprocess.run([str(P/'cextract'),'-src',str(td),'-out',str(out)],capture_output=True,text=True)
    if p.returncode:
        result={'mutation':name,'status':'PARSE_ERROR','detail':p.stderr[:250]}
    else:
        d=json.loads(out.read_text())
        record=next(x for x in d['results'] if x['operation']=='PutObject')
        result={'mutation':name,'status':record['classification'],'detail':record['reason']}
        if name=='copy_guard_only':
            record=next(x for x in d['results'] if x['operation']=='CopyObject')
            result['status']=record['classification'];result['detail']=record['reason']
        try:check(td,d);result['independent_verifier']='ACCEPT'
        except ValueError as e:result['independent_verifier']='REJECT: '+str(e)
    observations.append(result)
    print(name,result['status'],result.get('independent_verifier',''),result['detail'][:100])
(p:=P/'results'/'mutants.json').write_text(json.dumps(observations,indent=2)+'\n')
false_positive=[x['mutation'] for x in observations if x['status']=='STRUCTURALLY_GUARDED']
print('MUTATION_COUNT',len(CASES),'OVERCONFIDENT',false_positive)
if false_positive:raise AssertionError('overconfident structural certification: '+str(false_positive))

# Integrity challenge: forge a good certificate to claim CopyObject is safe.
cert=json.loads((P/'results'/'after.json').read_text())
for op in cert['results']:
    if op['operation']=='CopyObject':op['classification']='STRUCTURALLY_GUARDED'
try:check(SRC,cert)
except ValueError:print('FORGED_CERTIFICATE_REJECTED')
else:raise AssertionError('forged certificate accepted')
