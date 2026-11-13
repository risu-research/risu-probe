"""User-facing P5-D entrypoint: P5-C unchanged except first-use ergonomics."""
from __future__ import annotations
import sys

def main():
    args=sys.argv[1:]
    if args and args[0]=='verify-mcp-effect-closure':
        from risu_mcp_effect_closure import main as verify_closure
        return verify_closure(args[1:])
    if args and args[0]=='verify-mcp-independent-owner':
        from risu_mcp_independent_owner_evidence import main as verify_independent
        return verify_independent(args[1:])
    if args and args[0]=='verify-mcp-external-authority':
        from risu_mcp_external_authority_certificate import main as verify_external
        return verify_external(args[1:])
    if args and args[0]=='enforce-mcp-resource-side':
        from risu_mcp_resource_guard import cli
        return cli(args[1:])
    if args and args[0]=='enforce-mcp-human-reviewed-write':
        from risu_mcp_human_review_broker import main
        return main()
    if args and args[0]=='enforce-mcp-owner-credential-broker':
        from risu_mcp_owner_credential_broker import cli
        return cli(args[1:])
    if args and args[0]=='enforce-mcp-github-owner':
        from risu_mcp_github_owner import main
        return main()
    if args and args[0]=='enforce-mcp-preflight':
        from risu_mcp_preflight import cli
        return cli(args[1:])
    if args and args[0]=='verify-mcp-effect-authority':
        from risu_mcp_effect_authority import cli
        return cli(args[1:])
    if args and args[0]=='verify-mcp-effects':
        from risu_mcp_effects import cli
        return cli(args[1:])
    if args and args[0]=='compare-signed-mcp-repair':
        from risu_mcp_signed_repair import cli
        return cli(args[1:])
    if args and args[0]=='verify-mcp-runtime':
        from risu_mcp_runtime_origin import cli
        return cli(args[1:])
    if args and args[0]=='verify-mcp-origin':
        from risu_mcp_origin import cli
        return cli(args[1:])
    if args and args[0]=='qualify-mcp-observations':
        from risu_mcp_authority import cli
        return cli(args[1:])
    if args and args[0]=='check-mcp-observations':
        from risu_mcp_observations import cli
        return cli(args[1:])
    if args and args[0]=='check-mcp-cardinality':
        from risu_mcp_cardinality import cli
        return cli(args[1:])
    if args and args[0]=='verify-mcp-trace':
        from risu_mcp_trace import cli
        return cli(args[1:])
    if args and args[0]=='verify-mcp':
        from risu_mcp_replay import cli
        return cli(args[1:])
    if args and args[0]=='doctor':
        from risu_firstuse import doctor_cli
        return doctor_cli(args[1:])
    if args and args[0]=='check':
        from risu_p5c_cli import _is_legacy_project
        if not _is_legacy_project(args[1:]):
            from risu_firstuse import cli
            return cli(args[1:])
    from risu_p5c_cli import main as previous
    return previous()

if __name__=='__main__':raise SystemExit(main())
