#!/usr/bin/env python3
"""Independently recompute ConditionEffect *structural* obligations.

This verifier is deliberately small and uses different implementation machinery
(source text and balanced-brace extraction, not Go's AST). It is not a semantic
proof of Go execution or a proof that called storage primitives are correct.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys


def balanced(source, start):
    begin = source.find('{', start)
    if begin < 0: raise ValueError('missing function open brace')
    depth = 0
    for i in range(begin, len(source)):
        if source[i] == '{': depth += 1
        if source[i] == '}':
            depth -= 1
            if depth == 0: return source[begin + 1:i]
    raise ValueError('unterminated block')


def extract_fn(source, name):
    if name == 'CopyObject' or name == 'PutObject' or name == 'CompleteMultipartUpload':
        pattern = r'func\s*\(h\s+\*Handler\)\s+' + name + r'\s*\('
    else: pattern = r'func\b[^\n]*\b' + name + r'\s*\('
    match = re.search(pattern, source)
    return balanced(source, match.start()) if match else None


def classify(original, operation, helpers_present):
    content = original['handler_multipart.go'] if operation == 'CompleteMultipartUpload' else original['handler_object.go']
    fn = extract_fn(content, operation)
    if fn is None: return 'ABSTAIN'
    if fn.count('commitVersion(') != 1: return 'ABSTAIN'
    if 'Bucket:' not in fn or 'Key:' not in fn: return 'ABSTAIN'
    if 'parseConditionalWrite(r)' not in fn: return 'MISSING_GUARD_CANDIDATE'
    # This is an independently implemented *conservative* review of Go source.
    active = re.search(r'if\s+cond\.active\(\)\s*\{', fn)
    if not active: return 'ABSTAIN'
    conditional = balanced(fn, active.start())
    expected_bucket = 'destBucket' if operation == 'CopyObject' else 'bucket'
    expected_key = 'destKey' if operation == 'CopyObject' else 'key'
    locked = 'defer h.objectLocks.Lock(objectStoreKey(' + expected_bucket + ', ' + expected_key + '))()'
    checked = 'h.checkConditionalWrite(r.Context(), cond, '+expected_bucket+', '+expected_key+')'
    if locked not in conditional or checked not in conditional: return 'ABSTAIN'
    if conditional.index(locked) > conditional.index(checked): return 'ABSTAIN'
    after_cond = fn.index('commitVersion(')
    if after_cond < active.start() or not helpers_present: return 'ABSTAIN'
    if fn.count('parseConditionalWrite(r)') != 1: return 'ABSTAIN'
    if 'return' not in conditional[conditional.index(checked):]: return 'ABSTAIN'
    if not re.search(r'if\s+aerr\s*!=\s*nil\s*\{',fn[:active.start()]):return 'ABSTAIN'
    return 'STRUCTURALLY_GUARDED'


def check(directory, certificate):
    source = {p.name:p.read_text() for p in directory.glob('*.go')}
    claimed = certificate['source_sha256']
    if set(source) != set(claimed): raise ValueError('file-set differs')
    for f, txt in source.items():
        if hashlib.sha256(txt.encode()).hexdigest() != claimed[f]:
            raise ValueError('digest mismatch '+f)
    audited_helper = 'aa3eb220eb504c8eb042b57fa166991ac05b4b237c5ce4c459781e37fb695fb5'
    helpers_present = (claimed.get('conditional_write.go') == audited_helper and
                       all(name in source.get('conditional_write.go','')
                           for name in ('parseConditionalWrite','lookupObjectMeta','etagMatches',
                                        'errPreconditionFailed','errNoSuchKey')))
    observed = {r['operation']:r for r in certificate['results']}
    if set(observed) != {'PutObject','CompleteMultipartUpload','CopyObject'}: raise ValueError('operation set')
    for op,record in observed.items():
        recomputed = classify(source, op, helpers_present)
        asserted = record['classification']
        if asserted not in ('ABSTAIN','MISSING_GUARD_CANDIDATE','STRUCTURALLY_GUARDED'):
            raise ValueError('invalid classification')
        # A conservative abstention is always allowed; an assertion is not.
        if asserted != 'ABSTAIN' and recomputed != asserted:
            raise ValueError(f'{op} certificate says {asserted}; independent source review says {recomputed}')
        if asserted == 'STRUCTURALLY_GUARDED':
            needed = {'request_target_bound','parses_condition','parse_error_stops_write',
                      'guarded_check_and_keyed_lock','check_precedes_commit',
                      'helper_semantic_shape','no_known_pre_guard_effect'}
            for obligation in needed:
                if record.get('obligations',{}).get(obligation) is not True:
                    raise ValueError('missing positive proof obligation: '+obligation)
        for site in (record.get('sites') or []):
            fname=site['file']; number=site['line']
            if fname not in source: raise ValueError('unrecognized site file '+fname)
            lines=source[fname].splitlines()
            if number < 1 or number > len(lines): raise ValueError('site out of bounds')
            label=site['description']
            expected = 'commitVersion' if 'effect site' in label else 'parseConditionalWrite' if 'parse conditional' in label else 'Lock' if 'keyed deferred lock' in label else 'checkConditionalWrite'
            if expected not in lines[number-1]:
                # The Go AST site for condition parser is the entire statement;
                # test exact text here, all current implementations fit.
                raise ValueError('witness line invalid '+str(site))
    return True


if __name__ == '__main__':
    p=argparse.ArgumentParser()
    p.add_argument('source_dir');p.add_argument('certificate')
    a=p.parse_args()
    try:
        record=json.loads(pathlib.Path(a.certificate).read_text())
        check(pathlib.Path(a.source_dir),record)
    except Exception as e:
        print('INDEPENDENT_CERTIFICATE_REJECT',type(e).__name__,str(e))
        sys.exit(1)
    print('INDEPENDENT_CERTIFICATE_ACCEPT structural-only; external effects not proved')
