"""Independent B19 audit: upstream-signed PyPI originals vs native hidden effects.

No import of the frozen RISU product, no exploitation tooling. This auditor
re-parses original 4-session JSON-RPC bytes and publisher certificates, source
objects and original benign marker witness. The actual cryptographic signature
verifier is run independently by CI (pypi-attestations CLI).
"""
from __future__ import annotations
import argparse,base64,hashlib,json,zipfile
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import ExtensionOID,ObjectIdentifier


def digest(value):return hashlib.sha256(value).hexdigest()
def require(x,why):
    if not x:raise ValueError(why)
def read(path):return json.loads(Path(path).read_text("utf-8"))
def blob(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+bytes([0])+raw).hexdigest()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()


def audit(root:Path, independent_signatures:dict | None =None):
    f=read(root/"benchmarks/p6b19/FROZEN_PUBLISHER_WHEELS_REAL_GIT_REPAIR.json")
    require(f["schema"]=="risu-p6b19-signed-official-before-after-freeze-v1","Wrong frozen cohort")
    require(f["issue"]["id"]=="GHSA-6hqx-gqrx-c5r2","Wrong public fixed bug identity")
    metadata={}
    responses={}
    refs={}
    for v in f["versions"]:
        ident,version=v["id"],v["version"]
        r=root/".b19-official"/ident
        wheel=r/v["wheel"]
        raw=wheel.read_bytes()
        require(digest(raw)==v["wheel_sha256"],"Official wheel differs from predeclared published digest")
        with zipfile.ZipFile(wheel) as z:
            server=z.read("mcp_server_git/server.py")
        original_source=(r/"original_publisher_server_source.py.txt").read_bytes()
        require(server==original_source and blob(server)==v["server_git_blob_sha1"],
                "Published actual Python module differs from pinned Git source")
        equiv=read(r/"source_code_equivalence.json")
        require(equiv["installed_code_matches_signed_wheel_bytes"] is True and
                equiv["wheel_code_matches_original_git_source_bytes"] is True and
                equiv["installed_code_sha256"]==equiv["original_source_code_sha256"]==digest(server),
                "Original installed code not same as signed publisher wheel")
        pub=read(r/"publisher_attestation_statement_metadata.json")
        claim=read(r/"publish_attestation_verified.json")
        prov=read(r/"original_pypi_integrity_provenance.json")
        bundles=prov["attestation_bundles"]
        require(len(bundles)>=1,"Missing publisher-signed PyPI provenance")
        found=[]
        for bundle in bundles:
            identity=bundle.get("publisher",{})
            require(identity.get("kind")=="GitHub" and
                    identity.get("repository")=="modelcontextprotocol/servers" and
                    identity.get("workflow")=="release.yml" and
                    identity.get("environment")=="release",
                    "Publish attestation's trusted publisher differs from original")
            for att in bundle["attestations"]:
                statement=json.loads(base64.b64decode(att["envelope"]["statement"]))
                subjects=statement.get("subject",[])
                if statement.get("predicateType")!="https://docs.pypi.org/attestations/publish/v1":
                    continue
                if not any(s["name"]==v["wheel"] and
                           s["digest"]["sha256"]==v["wheel_sha256"] for s in subjects):
                    continue
                cert_data=base64.b64decode(att["verification_material"]["certificate"])
                cert=x509.load_der_x509_certificate(cert_data)
                san=cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                uris=san.get_values_for_type(x509.UniformResourceIdentifier)
                expected_prefix="https://github.com/modelcontextprotocol/servers/.github/workflows/release.yml@refs/tags/"
                require(len(uris)==1 and uris[0].startswith(expected_prefix),
                        "Signed GitHub workflow SAN does not match expected publisher")
                src_sha=cert.extensions.get_extension_for_oid(
                   ObjectIdentifier("1.3.6.1.4.1.57264.1.3")).value.value.decode("ascii")
                require(src_sha==v["source_commit"],"Signed X509 provenance commit differs from original source")
                require(digest(cert_data)==claim["certificate_der_sha256"],
                        "Signed provenance certificate changed")
                found.append({"publisher_cert_sha256":digest(cert_data),
                    "signed_publisher_git_commit":src_sha,
                    "publisher_sigstore_san":uris[0],
                    "publisher_predicate_type":statement["predicateType"]})
        require(len(found)==1,"Expected exactly one signed PyPI publication statement for wheel")
        require(claim["verified_by_pypi_attestations_cli"] is True and
                claim["wheel_sha256"]==v["wheel_sha256"],"Missing real official PyPI signature check")
        if independent_signatures is not None:
            verify=independent_signatures.get(ident)
            require(type(verify) is dict and
                verify.get("cryptographic_verification_success") is True and
                verify.get("wheel_sha256")==v["wheel_sha256"],
                "Separate independent upstream signature verification missing")
        pins=read(r/"original_pypi_metadata.json")
        require(pins["wheel_sha256"]==v["wheel_sha256"] and
                pins["version"]==version,"Frozen original wheel metadata mismatch")
        deps=(r/"installed_dependencies.txt").read_text("utf-8").splitlines()
        normal=[line for line in deps if not line.lower().startswith("mcp-server-git")]
        refs[ident]=normal
        for case in ("CONFIGURED","NORMAL"):
            folder=root/".b19-native-firstpass"/ident/case
            witness=read(folder/"original_effect_witness.json")
            trace=(folder/"original_stdio.jsonl").read_bytes()
            require(witness["status"]=="CAPTURED_ORIGINAL_NATIVE" and
                    witness["trace_sha256"]==digest(trace) and
                    witness["source_version"]==version and
                    witness["release_wheel_sha256"]==v["wheel_sha256"] and
                    witness["installed_source_sha256"]==digest(server),
                    "Original runtime capture source/provenance mismatch")
            require(witness["isolated_python_runtime"] is True and
                    witness["injected_config"] is (case=="CONFIGURED") and
                    witness["marker_before"] is False and
                    witness["marker_content_valid"] is True,
                    "Synthetic benign side effect witness invalid or preexisting")
            require(type(witness["process_pid"]) is int and witness["process_pid"]>0
                    and witness["negotiated_protocol"]=="2025-11-25",
                    "Native MCP session or live process evidence missing")
            require(witness["serverInfo"]["version"]==version,
                    "Actual original MCP process reports different installed package")
            lines=[json.loads(x) for x in trace.splitlines()]
            require(all(x.get("jsonrpc")=="2.0" for x in lines),"Non-MCP original trace")
            request=[x for x in lines if x.get("method")=="tools/call"]
            require(len(request)==1 and request[0]["id"]==20 and
                request[0]["params"]=={"name":"git_status",
                "arguments":{"repo_path":witness["repository_path"]}},
                "Wrong source-native tool or additional request")
            listing=[x for x in lines if x.get("id")==2 and type(x.get("result")) is dict]
            require(len(listing)==1 and
                 any(z.get("name")=="git_status" for z in listing[0]["result"]["tools"]),
                 "No original same-session MCP advertised git_status")
            tool_result=[x for x in lines if x.get("id")==20 and type(x.get("result")) is dict]
            require(len(tool_result)==1 and
                tool_result[0]["result"].get("isError") is False and
                witness["tool_result_iserror"] is False and
                witness["tool_status_text_present"] is True,
                "Tool error incorrectly counted as successful fixed/buggy read")
            content=tool_result[0]["result"]["content"]
            require(len(content)==1 and content[0]["type"]=="text" and
                "Repository status:" in content[0]["text"],"Original Git status text missing")
            responses[(ident,case)]=digest(canonical(tool_result[0]["result"]))
            marker=bool(witness["marker_after"])
            expect=(ident=="VULNERABLE" and case=="CONFIGURED")
            require(marker is expect,"Public upstream repair behavior differs from predeclared expected")
            require(witness["marker_trigger_count"]==(1 if expect else 0),
                    "Wrong number of benign synthetic script invocations")
            metadata[(ident,case)]={
                "native_original_wire_sha256":digest(trace),
                "mcp_tool_result_sha256":responses[(ident,case)],
                "publisher_version":version,
                "synthetic_marker_triggered":marker,
                "marker_count":witness["marker_trigger_count"],
                "publisher_source_code_sha256":digest(server),
                "py_process_executable_sha256":witness["process_python_exe_sha256"]
            }
        metadata[(ident,"PUBLISHER")]=found[0]
    require(refs["VULNERABLE"]==refs["FIXED"],
            "Original dependencies were different between before and after")
    output_hashes=set(responses.values())
    require(len(output_hashes)==1,
        "Original responses differed; invisible side-effect equivalence claim unsupported")
    result={
      "schema":"risu-b19-independent-publisher-signed-hidden-effect-audit-v1",
      "original_public_advisory":"GHSA-6hqx-gqrx-c5r2",
      "official_vendor":"modelcontextprotocol/servers",
      "original_pypi_publisher_attested_wheels":2,
      "independent_cryptographic_publisher_verification":independent_signatures is not None,
      "original_native_mcp_calls":4,
      "original_tool_errors":0,
      "normal_controls_passed":2,
      "known_real_security_repair_verified":True,
      "publisher_signed_source_commits_verified_by_x509":2,
      "all_four_original_tool_result_bodies_identical":True,
      "identical_canonical_mcp_result_sha256":next(iter(output_hashes)),
      "observable_side_effect_difference_hidden_from_MCP_result":True,
      "previously_unknown_upstream_defects_found":0,
      "evidence":[{"version":side,"case":case,**metadata[(side,case)]}
                  for side in ("VULNERABLE","FIXED") for case in ("CONFIGURED","NORMAL")],
      "certificate_origins":[{"version":side,**metadata[(side,"PUBLISHER")]}
                 for side in ("VULNERABLE","FIXED")],
      "claims_limits":[
        "The original upstream vulnerability was publicly disclosed Nov 11 2026. This is independent reproduction, not new security discovery.",
        "PEP740 signed PyPI Publish Attestation proves the original publisher workflow uploaded the exact wheel, not a hermetic SLSA build provenance proof.",
        "The original benign marker witness was measured in controlled GitHub CI, but offline JSON data alone cannot cryptographically attest which Python interpreter module ran.",
        "Matching response hashes with divergent externally measured effects proves this selected class is invisible to trace-only response comparisons.",
        "Two releases and one known defect cannot estimate population recall."
      ]}
    return result


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--original",type=Path,required=True)
    p.add_argument("--independent-signatures",type=Path)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    signatures=read(a.independent_signatures) if a.independent_signatures else None
    data=audit(a.original,signatures)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(data,indent=2,sort_keys=True,ensure_ascii=False)+chr(10))
    print("B19_INDEPENDENT_PUBLISHER_SIGNED_KNOWN_REAL_REPAIR",json.dumps({
       "two_signed_wheels":data["original_pypi_publisher_attested_wheels"],
       "native_calls":data["original_native_mcp_calls"],
       "all_response_bodies_equal":data["all_four_original_tool_result_bodies_identical"],
       "real_before_after":data["known_real_security_repair_verified"],
       "new_upstream_defects":data["previously_unknown_upstream_defects_found"]},
       sort_keys=True))


if __name__=="__main__":
    main()
