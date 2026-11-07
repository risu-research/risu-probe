"""P6-A source-tree and rebuilt-wheel fidelity to SHA-pinned verified P5-E source."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import zipfile


def audit(root:Path,wheel:Path,reference:Path|None=None)->dict:
    origin=json.loads((root/'P5E_SOURCE_PROVENANCE.json').read_text())
    expected=origin['modules_sha256']
    assert len(expected)==38 and origin['reference_wheel_sha256']=='56eb547c924c9b89d6d5a9fa760de99df95d7c8d4b872899a3fa70c4e45099d6'
    actual={p.name:sha256(p.read_bytes()).hexdigest() for p in (root/'src').glob('*.py')}
    assert actual==expected, {'missing':sorted(set(expected)-set(actual)), 'extra':sorted(set(actual)-set(expected)), 'changed':[n for n in expected if actual.get(n)!=expected[n]]}
    assert all(b'\r\n' not in (root/'src'/n).read_bytes() for n in expected),'Noncanonical source line endings'
    with zipfile.ZipFile(wheel) as z:
        modules={n:sha256(z.read(n)).hexdigest() for n in z.namelist() if n.endswith('.py')}
        assert modules==expected, {'missing':sorted(set(expected)-set(modules)), 'extra':sorted(set(modules)-set(expected)), 'changed':[n for n in expected if modules.get(n)!=expected[n]]}
        entry=z.read(next(n for n in z.namelist() if n.endswith('/entry_points.txt'))).decode()
        assert 'risu-probe = risu_p5d_cli:main' in entry
        meta=z.read(next(n for n in z.namelist() if n.endswith('/METADATA'))).decode().replace('\r\n','\n')
        assert 'Name: risu-probe-preview\n' in meta
        assert 'Version: 0.9.20.dev0\n' in meta
        assert 'Requires-Dist: PyYAML==6.0.2' in meta or 'Requires-Dist: PyYAML ==6.0.2' in meta
    if reference is not None:
        blob=reference.read_bytes()
        assert sha256(blob).hexdigest()==origin['reference_wheel_sha256'],'Historical evidence artifact sha mismatch'
        with zipfile.ZipFile(reference) as orig:
            assert {n:sha256(orig.read(n)).hexdigest() for n in orig.namelist() if n.endswith('.py')}==expected
    return {'result':'PASS','product_module_count':len(expected),'product_source_sha256':sha256(json.dumps(expected,sort_keys=True).encode()).hexdigest(),
            'built_wheel_sha256':sha256(wheel.read_bytes()).hexdigest(),
            'reference_wheel_verified':reference is not None,'entrypoint':'risu_p5d_cli:main',
            'source_module_bytes_changed':0}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--product',type=Path,required=True);p.add_argument('--wheel',type=Path,required=True)
    p.add_argument('--reference',type=Path);p.add_argument('--out',type=Path)
    a=p.parse_args();report=audit(a.product,a.wheel,a.reference)
    if a.out:
        a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(report,indent=2)+'\n')
    print('P6A_SINGLE_PRODUCT_SOURCE_AND_WHEEL_VERIFIED',json.dumps(report,sort_keys=True),flush=True)
