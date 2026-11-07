"""Deterministic, bounded, deletion-based reproducer minimizer.

We guarantee local 1-minimality under the declared deletion operators when
minimize(...).minimality == "ONE_MINIMAL_DELETIONS". We do NOT claim a
globally shortest counterexample or a real upstream replay if only the
recorded adapter model has been evaluated.
"""
from __future__ import annotations
import copy
import json
from typing import Callable,Any
from risu_evidence import _bounded_shape

MAX_CHECKS=1000
MAX_PAYLOAD_BYTES=256_000

class MinimizationError(ValueError):pass

def canonical(value:Any)->str:
    return json.dumps(value,sort_keys=True,ensure_ascii=False,
                      separators=(',',':'),allow_nan=False)

def _paths(node,path=()):
    if isinstance(node,dict):
        for key in sorted(node):
            yield path+(key,)
            yield from _paths(node[key],path+(key,))
    elif isinstance(node,list):
        for i in range(len(node)):
            yield path+(i,)
            yield from _paths(node[i],path+(i,))

def _delete(node,path):
    obj=copy.deepcopy(node)
    cursor=obj
    for step in path[:-1]:
        cursor=cursor[step]
    if isinstance(cursor,dict):
        del cursor[path[-1]]
    else:
        del cursor[path[-1]]
    return obj

def _candidates(obj):
    previous=canonical(obj)
    for path in _paths(obj):
        candidate=_delete(obj,path)
        updated=canonical(candidate)
        if len(updated)<len(previous):
            yield candidate,path

def minimize(original:Any,oracle:Callable[[Any],bool],*,max_checks:int=MAX_CHECKS)->dict:
    if not callable(oracle) or not 1<=max_checks<=MAX_CHECKS:
        raise MinimizationError('INVALID_ORACLE_OR_BUDGET')
    try:original_bytes=len(canonical(original).encode('utf-8'))
    except (ValueError,TypeError,OverflowError,RecursionError):
        raise MinimizationError('BODY_NOT_FINITE_JSON') from None
    if not _bounded_shape(original):
        raise MinimizationError('SOURCE_SHAPE_EXCEEDS_LIMITS')
    if original_bytes>MAX_PAYLOAD_BYTES:
        raise MinimizationError('SOURCE_EXCEEDS_256KB')
    checks=1
    if oracle(original) is not True:
        raise MinimizationError('INITIAL_COUNTEREXAMPLE_NOT_REPRODUCED')
    current=copy.deepcopy(original)
    accepted=0
    while checks<max_checks:
        changed=False
        for candidate,path in _candidates(current):
            if checks>=max_checks:break
            checks+=1
            if oracle(candidate) is True:
                current=candidate
                accepted+=1
                changed=True
                break
        if not changed:break
    # Independent pass proving no single subtree deletion preserves failure.
    remaining=list(_candidates(current))
    locally_minimal=True
    if checks+len(remaining)>max_checks:
        locally_minimal=False
    else:
        for candidate,_ in remaining:
            checks+=1
            if oracle(candidate) is True:
                locally_minimal=False
                break
    return {'minimal':current,
            'original_bytes':original_bytes,
            'minimal_bytes':len(canonical(current).encode('utf-8')),
            'checks':checks,'accepted_deletions':accepted,
            'single_deletion_candidates_remaining':len(remaining),
            'minimality':('ONE_MINIMAL_DELETIONS' if locally_minimal
                          else 'INCOMPLETE_BUDGET_OR_SEARCH'),
            'boundary':'Proven only for explicitly tested recursive key/array deletion operators; no global-minimum claim'}
