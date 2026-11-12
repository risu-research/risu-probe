"""B19 immutable upstream PyPI signed-release acquisition and original Git code checks.

Uses PyPI's PEP-740 Integrity API, exact published wheel sha256, official
pypi-attestations cryptographic verification, and pinned GitHub commit blobs.
The publish attestation authenticates publication, not hermetic wheel build.
"""
from __future__ import annotations
import argparse,base64,hashlib,json,os,subprocess,sys,urllib.request
from pathlib import Path
from urllib.parse import urlparse
import zipfile

SERVER_REPO="modelcontextprotocol/servers"
SOURCE="src/git/src/mcp_server_git/server.py"
MAX_WHEEL=1000000
MAX_META=2000000


def sha(x):return hashlib.sha256(x).hexdigest()
def git_blob_sha(x):
    return hashlib.sha1(b"blob "+str(len(x)).encode()+bytes([0])+x).hexdigest()

def fetch(url,maxsize=MAX_META,accept=None):
    domain=urlparse(url).hostname
    if domain not in ("pypi.org","api.github.com","files.pythonhosted.org"):
        raise RuntimeError("Untrusted artifact host")
    headers={"User-Agent":"RISU-P6B19-independent-publisher-signed-release"}
    if accept:headers["Accept"]=accept
    if domain=="api.github.com" and os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"]="Bearer "+os.environ["GITHUB_TOKEN"]
    req=urllib.request.Request(url,headers=headers)
    with urllib.request.urlopen(req,timeout=35) as r:
        length=int(r.headers.get("Content-Length","0"))
        if length>maxsize:raise RuntimeError("Publisher response too large")
        data=r.read(maxsize+1)
    if len(data)>maxsize:raise RuntimeError("Publisher response too large")
    return data

def write_json(path,data):
    path.write_text(json.dumps(data,indent=2,sort_keys=True,ensure_ascii=False)+chr(10),encoding="utf-8")

def attestation_record(provenance,wheel,commit):
    bundles=provenance.get("attestation_bundles",[])
    if not bundles or not isinstance(bundles,list):
        raise RuntimeError("No signed PyPI provenance bundles")
    found=[]
    for bundle in bundles:
        for item in bundle.get("attestations",[]):
            encoded=item.get("envelope",{}).get("statement")
            if type(encoded) is not str:continue
            payload=json.loads(base64.b64decode(encoded,validate=True))
            if not any(v.get("name")==wheel["filename"] and
              v.get("digest",{}).get("sha256")==wheel["digests"]["sha256"]
              for v in payload.get("subject",[])):continue
            if payload.get("predicateType")=="https://docs.pypi.org/attestations/publish/v1":
                cert=item.get("verification_material",{}).get("certificate")
                if type(cert) is not str:continue
                # Signature is verified separately by upstream pypi-attestations
                # cryptographic CLI, not by merely decoding this statement.
                found.append({
                  "publisher_identity_json":bundle.get("publisher",{}),
                  "certificate_der_sha256":sha(base64.b64decode(cert,validate=True)),
                  "signed_subject_wheel_sha256":wheel["digests"]["sha256"],
                  "statement_type":payload.get("_type"),"predicate_type":payload["predicateType"]})
    if not found:raise RuntimeError("No wheel-bound PyPI publish attestation statement")
    return found

def acquire(freeze,root):
    frozen=json.loads(freeze.read_text("utf-8"))
    assert frozen["schema"]=="risu-p6b19-signed-official-before-after-freeze-v1"
    if root.exists():raise RuntimeError("Never overwrite acquired official publisher wheels")
    root.mkdir(parents=True)
    for item in frozen["versions"]:
        destination=root/item["id"]
        destination.mkdir()
        api=f"https://pypi.org/pypi/mcp-server-git/{item['version']}/json"
        index=json.loads(fetch(api))
        matches=[x for x in index.get("urls",[]) if x.get("filename")==item["wheel"]]
        if len(matches)!=1:raise RuntimeError("Official signed wheel not found at exact version")
        wheel=matches[0]
        if wheel.get("digests",{}).get("sha256")!=item["wheel_sha256"]:
            raise RuntimeError("Exact upstream wheel digest changed since preregistration")
        if urlparse(wheel["url"]).hostname!="files.pythonhosted.org":
            raise RuntimeError("Official wheel URL is not PyPI file store")
        original=fetch(wheel["url"],MAX_WHEEL)
        if sha(original)!=item["wheel_sha256"]:
            raise RuntimeError("Retrieved wheel hash differs from frozen signed publication")
        (destination/item["wheel"]).write_bytes(original)
        write_json(destination/"original_pypi_metadata.json",{
            "filename":item["wheel"],"version":item["version"],
            "download_url":wheel["url"],"wheel_sha256":sha(original),
            "pypi_index_url":api,"upload_time":wheel.get("upload_time_iso_8601"),
            "yanked":wheel.get("yanked")})
        integrity=(f"https://pypi.org/integrity/mcp-server-git/{item['version']}/"
                    +item["wheel"]+"/provenance")
        provenance=json.loads(fetch(integrity,MAX_META,
                  "application/vnd.pypi.integrity.v1+json"))
        proof=attestation_record(provenance,wheel,item["source_commit"])
        write_json(destination/"original_pypi_integrity_provenance.json",provenance)
        write_json(destination/"publisher_attestation_statement_metadata.json",{
            "schema":"risu-b19-decoded-original-pypi-attestation-statements-v1",
            "publisher_repo_expected":SERVER_REPO,
            "source_commit_expected":item["source_commit"],
            "pypi_endpoint":integrity,
            "attestation_statements":proof})
        # Pin source to actual original GitHub commit tree, independently of
        # the distribution's tool self-reported version.
        git_url=("https://api.github.com/repos/"+SERVER_REPO+"/contents/"+SOURCE+
                "?ref="+item["source_commit"])
        external=json.loads(fetch(git_url,MAX_META,"application/vnd.github+json"))
        if external.get("sha")!=item["server_git_blob_sha1"]:
            raise RuntimeError("External publisher original Git tree blob not pinned source")
        source=base64.b64decode(external["content"])
        if git_blob_sha(source)!=item["server_git_blob_sha1"]:
            raise RuntimeError("Publisher Git source object content hash differs")
        with zipfile.ZipFile(destination/item["wheel"]) as z:
            packaged=z.read("mcp_server_git/server.py")
        if source!=packaged:raise RuntimeError("Signed published source code differs from pinned Git commit")
        (destination/"original_publisher_server_source.py.txt").write_bytes(source)
        record={
            "schema":"risu-b19-wheel-upstream-git-source-v1",
            "wheel_sha256":sha(original),
            "upstream_git_commit":item["source_commit"],
            "upstream_server_git_blob_sha1":item["server_git_blob_sha1"],
            "original_source_code_sha256":sha(source),
            "installed_code_sha256":None,
            "wheel_code_matches_original_git_source_bytes":True,
            "installed_code_matches_signed_wheel_bytes":False,
            "verified_publisher_source_path":SOURCE
        }
        write_json(destination/"source_code_equivalence.json",record)
        print("B19_SIGNED_UPSTREAM_ACQUIRED",item["id"],
            item["version"],sha(original),item["server_git_blob_sha1"])


def attest(freeze,root,exe):
    frozen=json.loads(freeze.read_text("utf-8"))
    for item in frozen["versions"]:
        dest=root/item["id"]
        index=json.loads((dest/"original_pypi_metadata.json").read_text("utf-8"))
        original_wheel=dest/item["wheel"]
        if sha(original_wheel.read_bytes())!=item["wheel_sha256"]:
            raise RuntimeError("Wheel modified before signature verification")
        cmd=[exe,"verify","pypi","--repository",
             "https://github.com/modelcontextprotocol/servers",index["download_url"]]
        verify=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
           check=False,timeout=180)
        (dest/"original_cryptographic_attestation_cli.log").write_bytes(
            b"STDOUT\n"+verify.stdout[:6000]+b"\nSTDERR\n"+verify.stderr[:6000])
        if verify.returncode!=0:
            raise RuntimeError("PyPI upstream publish cryptographic attestation did not verify: "+item["id"])
        proof=json.loads((dest/"publisher_attestation_statement_metadata.json").read_text("utf-8"))
        pubs=proof.get("attestation_statements",[])
        if len(pubs)<1:raise RuntimeError("Missing verified publisher signed wheel subject")
        # Publisher commit is independently cross-checked against GitHub tree
        # bytes and the actual wheel source; not inferred from a free-form README.
        record={
            "schema":"risu-b19-upstream-pypi-publish-attestation-v1",
            "verified_by_pypi_attestations_cli":True,
            "publishing_repository":SERVER_REPO,
            "publishing_commit":item["source_commit"],
            "publishing_workflow":".github/workflows/release.yml",
            "package_version":item["version"],
            "wheel_filename":item["wheel"],
            "wheel_sha256":item["wheel_sha256"],
            "attestation_predicate_type":pubs[0]["predicate_type"],
            "certificate_der_sha256":pubs[0]["certificate_der_sha256"],
            "pypi_trusted_publisher_identity_record":pubs[0]["publisher_identity_json"],
            "verification_method":"pypi-attestations verify pypi --repository=https://github.com/modelcontextprotocol/servers <official-pypi-file-url>",
            "limitation":"Official PyPI PEP740 publish attestation signs publisher workflow's upload subject. Build-process completeness and loaded Python module identity require independent separate source and runtime evidence."
        }
        write_json(dest/"publish_attestation_verified.json",record)
        print("B19_UPSTREAM_PUBLISH_SIGNATURE_CRYPTOGRAPHICALLY_VERIFIED",item["version"],item["wheel_sha256"])


def installed(freeze,root,venvs):
    frozen=json.loads(freeze.read_text("utf-8"))
    for item in frozen["versions"]:
        d=root/item["id"]
        py=venvs/item["id"]/"bin/python"
        code=("import json,importlib.util,importlib.metadata,pathlib,hashlib;"
          "s=importlib.util.find_spec('mcp_server_git.server');"
          "p=pathlib.Path(s.origin);"
          "v=importlib.metadata.version('mcp-server-git');"
          "print(json.dumps({'path':str(p.resolve()),'version':v,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}))")
        r=subprocess.run([str(py),"-I","-c",code],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=True)
        obj=json.loads(r.stdout.decode("utf-8"))
        if obj["version"]!=item["version"]:raise RuntimeError("Installed version not frozen publisher version")
        site=venvs/item["id"]
        if not Path(obj["path"]).is_relative_to(site.resolve()):
            raise RuntimeError("Original Python module loaded outside frozen isolated venv")
        record=json.loads((d/"source_code_equivalence.json").read_text("utf-8"))
        if obj["sha256"]!=record["original_source_code_sha256"]:
            raise RuntimeError("Installed module bytes differ from upstream signed wheel")
        record["installed_code_sha256"]=obj["sha256"]
        record["installed_code_matches_signed_wheel_bytes"]=True
        record["original_installed_module_absolute_path"]=obj["path"]
        write_json(d/"source_code_equivalence.json",record)
        print("B19_INSTALLED_ORIGINAL_SIGNED_UPSTREAM_MODULE",item["id"],
              item["version"],obj["sha256"])


def main():
    p=argparse.ArgumentParser()
    p.add_argument("phase",choices=("acquire","attest","installed"))
    p.add_argument("--freeze",required=True,type=Path)
    p.add_argument("--root",required=True,type=Path)
    p.add_argument("--venvs",type=Path)
    p.add_argument("--verifier",default="pypi-attestations")
    a=p.parse_args()
    if a.phase=="acquire":acquire(a.freeze,a.root)
    elif a.phase=="attest":attest(a.freeze,a.root,a.verifier)
    elif a.phase=="installed":
        if not a.venvs:raise ValueError("--venvs required")
        installed(a.freeze,a.root,a.venvs)

if __name__=="__main__":main()
