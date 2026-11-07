"""Explicit consumer-observed subcontracts for RISU Probe.

Pointers are RFC 6901 JSON pointers. A consumer contract narrows the claim to
specified source fields, never to an unqualified 'all data preserved' assertion.
"""
from __future__ import annotations


class ContractError(ValueError):
    pass


def segments(pointer: str) -> tuple[str, ...]:
    if not isinstance(pointer, str) or not pointer.startswith('/') or len(pointer) > 512:
        raise ContractError('JSON Pointer must begin with / and be at most 512 chars')
    parts = pointer[1:].split('/')
    if len(parts) > 64:
        raise ContractError('JSON Pointer has too many segments')
    out = []
    for part in parts:
        i = 0
        while i < len(part):
            if part[i] == '~':
                if i+1 >= len(part) or part[i+1] not in '01':
                    raise ContractError('invalid ~ escape in JSON Pointer')
                i += 2
            else:
                i += 1
        out.append(part.replace('~1', '/').replace('~0', '~'))
    return tuple(out)


def resolve(value, pointer: str):
    cur = value
    for part in segments(pointer):
        if isinstance(cur, dict):
            if part not in cur:
                return False, None
            cur = cur[part]
        elif isinstance(cur, list):
            if not part.isdecimal() or (len(part) > 1 and part.startswith('0')):
                return False, None
            idx = int(part)
            if idx >= len(cur):
                return False, None
            cur = cur[idx]
        else:
            return False, None
    return True, cur


def validate_paths(paths):
    if not isinstance(paths, list) or not paths or len(paths)>128:
        raise ContractError('required_paths must be a nonempty array of at most 128 JSON Pointers')
    if not all(isinstance(p, str) for p in paths) or len(set(paths)) != len(paths):
        raise ContractError('required_paths must contain unique JSON Pointer strings')
    for p in paths:
        segments(p)
    return paths
