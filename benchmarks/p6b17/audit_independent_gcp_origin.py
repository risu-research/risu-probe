"""Independent B17 original source provenance audit (no B17 product imports).

Audit provider-verified Git commit, blob bytes, static literal Tool schema,
original two native JSON-RPC calls, and source-bound product report. No
synthetic mutation is ever counted as a real external upstream defect.
"""
from __future__ import annotations
import argparse,ast,hashlib,json,subprocess
from pathlib import Path

REPO='GoogleCloudPlatform/mcp-python-sdk-grpc-poc'
REV='cedc20fdc8fdf22fc8b411a3947ae03c71cbc926'
SOURCE='examples/servers/structured_output_lowlevel.py'
BLOB='7f102ff8b5e09b6df64b6b9c0fd913ac25f709f5'
TOOL='get_weather'
EXPECTED=['RISU_B17_SYNTHETIC_ALPHA','RISU_B17_SYNTHETIC_BETA']


def required(condition,why):
    if not condition:raise ValueError(why)


def read(path):
    return json.loads(path.read_text('utf-8'))


def digest(value):
    return hashlib.sha256(value).hexdigest()


def source_schema(content):
    tree=ast.parse(content.decode('utf-8'))
    matches=[]
    for node in ast.walk(tree):
        if not isinstance(node,ast.Call):continue
        func=node.func
        if not isinstance(func,ast.Attribute) or func.attr!='Tool':continue
        if not isinstance(func.value,ast.Name) or func.value.id!='types':continue
        kws={k.arg:k.value for k in node.keywords}
        if 'name' not in kws or 'outputSchema' not in kws:continue
        if ast.literal_eval(kws['name'])==TOOL:matches.append(ast.literal_eval(kws['outputSchema']))
    required(len(matches)==1,'Original literal tool schema absent or ambiguous')
    return matches[0]


def extract(artifact:Path,checkout:Path,provider:Path):
    orig=artifact/'.b17-original'
    identity=read(orig/'origin.json')
    trace=(orig/'original_stdio.jsonl').read_bytes()
    calls=read(orig/'call_log.json')
    contract=read(orig/'contract.json')
    result=read(orig/'origin_firstpass.json')
    remote=read(provider)
    required(identity['status']=='CAPTURED_ORIGINAL','Original source execution incomplete')
    required(identity['repository']==REPO and identity['full_revision']==REV,'Wrong original publisher pin')
    required(identity['calls_captured']==2 and len(calls)==2,'Original two calls missing')
    required(identity['trace_sha256']==digest(trace)==result['trace_sha256'],
             'Original transcript hash disconnected from first pass')
    required(remote['schema']=='risu-b17-independent-provider-tree-check-v1'
             and remote['remote_api_tree_matches_git_checkout'] is True,
             'No independent original provider evidence')
    required(remote['github_remote_repository']==REPO
             and remote['revision']==REV
             and remote['remote_git_tree_blob_sha1']==BLOB
             and remote['local_git_tree_blob_sha1']==BLOB,
             'Remote GitHub tree disagrees with checkout source')
    original=subprocess.check_output(['git','-C',str(checkout),'cat-file','blob',BLOB])
    required(hashlib.sha1(b'blob '+str(len(original)).encode()+bytes([0])+original).hexdigest()==BLOB,
             'Git object SHA computation does not match source')
    required(digest(original)==remote['original_source_file_sha256'],
             'Source SHA256 does not match original provider proof')
    true_schema=source_schema(original)
    msgs=[json.loads(line) for line in trace.splitlines()]
    original_requests={x['id']:(i,x) for i,x in enumerate(msgs,1)
            if x.get('method')=='tools/call' and 'id' in x}
    original_responses={x['id']:(i,x) for i,x in enumerate(msgs,1)
            if 'id' in x and x.get('method') is None}
    lists=[(i,x['result']) for i,x in enumerate(msgs,1)
           if type(x.get('result')) is dict and type(x['result'].get('tools')) is list]
    required(len(lists)==1,'Original source advertised ambiguous catalogs')
    page,listed=lists[0]
    descs=[x for x in listed['tools'] if x.get('name')==TOOL]
    required(len(descs)==1 and descs[0].get('outputSchema')==true_schema,
             'Actual original catalog does not match literal source')
    original_samples=[]
    for index,city in enumerate(EXPECTED):
        rid=20+index
        i,request=original_requests[rid]
        j,response=original_responses[rid]
        required(page<i<j,'Source catalog was not established before call')
        required(request['params']['name']==TOOL and
                 request['params']['arguments']=={'city':city},
                 'Source original input changed from prelock')
        cr=calls[index]
        required(cr['request_line']==i and cr['response_line']==j
                 and cr['original_response_id']==rid,'Derived call spans differ')
        result_value=response.get('result')
        required(type(result_value) is dict and result_value.get('isError') is not True,
                 'Original native source returned an execution error')
        v=result_value.get('structuredContent')
        required(type(v) is dict,'Real server did not send structuredContent')
        for key in true_schema['required']:
            required(key in v,'Required publisher output absent')
            kind=true_schema['properties'][key]['type']
            value=v[key]
            ok={'integer':type(value) is int,'number':type(value) in (int,float),
                'string':type(value) is str,'boolean':type(value) is bool}.get(kind,False)
            required(ok,'Original result type violates publisher outputSchema')
        original_samples.append({'call_id':rid,'request_line':i,'response_line':j,
           'type_valid':True,'source_schema_sha256':digest(json.dumps(
               true_schema,sort_keys=True,separators=(',',':')).encode())})
    totals=result['summary']
    required(totals['matched_obligations']==2 and
             totals['SOURCE_CORROBORATED_PASS']==2 and
             totals['SOURCE_CORROBORATED_MISMATCH']==0 and
             totals['QUARANTINED_SOURCE_CONFLICT']==0,
             'Frozen product first pass no longer agrees with original evidence')
    required(all(x['source_level']=='SOURCE_DECLARATION_CORROBORATED'
                 for x in result['checks']),'First pass source grade unsupported')
    return {'schema':'risu-b17-independently-cross-audited-gcp-original-v1',
      'publisher':REPO,'full_revision':REV,
      'source_blob_sha1':BLOB,'source_file_sha256':digest(original),
      'original_trace_sha256':digest(trace),
      'independently_verified_github_remote_tree':True,
      'provider_commit_signature_verification':'SEE_SEPARATE_PROVIDER_SIGNED_COMMIT_EVIDENCE',
      'native_source_deployments':1,'native_original_calls':2,
      'source_catalog_contract_matches':2,
      'source_correlated_original_output_contracts_passed':2,
      'first_pass_original_bugs_confirmed':0,
      'original_call_evidence':original_samples,
      'claim_boundary':'Source Git commit/tree/file and same-session MCP declaration corroborated, not cryptographic identity of the running process. A passing example server is not a positive defect detection.'}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--artifact',required=True,type=Path)
    p.add_argument('--checkout',required=True,type=Path)
    p.add_argument('--provider-proof',required=True,type=Path)
    p.add_argument('--out',required=True,type=Path)
    a=p.parse_args()
    result=extract(a.artifact,a.checkout,a.provider_proof)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+chr(10))
    print('B17_INDEPENDENT_ORIGINAL_PUBLISHER_CROSS_AUDIT',json.dumps({
       'calls':result['native_original_calls'],
       'source_matches':result['source_catalog_contract_matches'],
       'confirmed_bugs':result['first_pass_original_bugs_confirmed']},sort_keys=True))

if __name__=='__main__':
    main()
