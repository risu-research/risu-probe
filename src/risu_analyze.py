"""Analyze saved HTTP/MCP matrices from independent tools, without SDK dependencies."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from risu_report import emit


def _entries(payload):
    if isinstance(payload, dict) and isinstance(payload.get('targets'), list):
        for target in payload['targets']:
            label = str(target.get('target', 'unknown'))[:120]
            if isinstance(target.get('cases'),list):
                for row in target['cases']:
                    yield label, str(row['case'])[:120], row['upstream'],row['mcp_wire']
            elif isinstance(target.get('checks'),list):
                for row in target['checks']:
                    yield label,str(row['check']['id'])[:120], row['source_sample'],row['mcp_sample']
            else:
                raise ValueError('target must contain checks or cases')
    elif isinstance(payload, dict) and isinstance(payload.get('cases'),list):
        for row in payload['cases']:
            yield str(row.get('translator','unknown'))[:120],str(row['id'])[:120],row['source'],row['mcp']
    else:
        raise ValueError('expected a targets matrix or cases array; no real evidence is inferred')


def analyze(payload, profile='json-errors', policy='calibrated'):
    # Import here to let the CLI avoid creating multiple package entrypoints.
    from risu_probe import compare, VERSION, ProbeError
    from risu_decision import apply as apply_decisions
    rows=[]
    for target,case_id,src,mcp in _entries(payload):
        try:
            entry=compare(src,mcp,case_id,error_profile=profile)
        except ProbeError as exc:
            raise ValueError(f'malformed captured observation {target}/{case_id}: {exc}') from exc
        entry['target']=target
        rows.append(entry)
    if not rows or len(rows)>5000:
        raise ValueError('expected 1-5000 saved observations')
    summary={v:sum(x['verdict']==v for x in rows) for v in
             ('PRESERVED','LOSS','INVENTED','LOSS_AND_INVENTED','NOT_APPLICABLE','ERROR','INPUT_REQUIRED')}
    codes={}
    for row in rows:
        for d in row.get('diagnostics',[]):
            codes[d['code']]=codes.get(d['code'],0)+1
    evidence_summary={}
    action_summary={}
    for row in rows:
        evidence=row.get('evidence_v1') or {}
        recovery=evidence.get('body_recovery','NOT_ASSESSED')
        action=evidence.get('recommended_action','NONE')
        evidence_summary[recovery]=evidence_summary.get(recovery,0)+1
        action_summary[action]=action_summary.get(action,0)+1
    return apply_decisions({'tool':'RISU Probe','version':VERSION,'profile':profile,
            'evidence':'captured HTTP/MCP result pairs; no new upstream execution',
            'summary':summary,'diagnostic_summary':codes,
            'evidence_summary':evidence_summary,'action_summary':action_summary,'results':rows},policy)


def main(argv=None):
    p=argparse.ArgumentParser(description='Analyze saved HTTP-to-MCP matrices from multiple translators')
    p.add_argument('matrix',type=Path,help='matrix JSON from real captured calls; 10 MiB maximum')
    p.add_argument('--profile',choices=('problem-only','json-errors'),default='json-errors')
    p.add_argument('--format',choices=('json','text','markdown','sarif'),default='text')
    p.add_argument('--out',type=Path)
    p.add_argument('--recovery',action='store_true',help='include typed fields, text JSON recovery, missing errors and consumer observations (offline; no API calls)')
    p.add_argument('--causal-trust-store',type=Path,help='operator-selected trusted recorder public keys; must be outside the capture directory')
    p.add_argument('--fail-on-confirmed-loss',action='store_true',help='nonzero only when a trusted runtime witness confirms a loss')
    p.add_argument('--fail-on-loss',action='store_true')
    p.add_argument('--semantic-map',type=Path,help='operator-declared mappings, native captures only')
    p.add_argument('--field-coverage',action='store_true',help='count all original JSON leaves and mapping-verified source fields; requires --semantic-map')
    p.add_argument('--array-map',type=Path,help='explicit typed identity joins for observed arrays; requires --field-coverage and --semantic-map')
    p.add_argument('--residual-map',type=Path,help='classify previously-unverified original source leaves using explicitly declared evidence')
    p.add_argument('--obligation-map',type=Path,help='separate observed MCP output schema requirements from operator-selected source field duties')
    p.add_argument('--fail-on-operator-duty',action='store_true',help='exit 1 if an operator-required field is observably not exposed; no publisher breach inferred')
    p.add_argument('--fail-on-schema-duty',action='store_true',help='exit 1 only if a recorded MCP outputSchema-required field is absent or wrong type')
    p.add_argument('--fail-on-unsupported-schema-claim',action='store_true',help='exit 1 when an asserted output-schema duty is not required by the recorded tool schema')
    p.add_argument('--fail-on-residual-contradiction',action='store_true',help='exit 1 when a declared residual transformation is contradicted')
    p.add_argument('--fail-on-residual-nonexposure',action='store_true',help='exit 1 for observed unexposed source envelope fields; not causal loss proof')
    p.add_argument('--fail-on-residual-gap',action='store_true',help='exit 1 when original leaves remain unverified after residual classification')
    p.add_argument('--fail-on-array-contradiction',action='store_true',help='exit 1 for a contradicted declared array identity/field mapping')
    p.add_argument('--fail-on-combined-coverage-gap',action='store_true',help='exit 1 if any original leaf is unverified after validated array matching')
    p.add_argument('--fail-on-coverage-gap',action='store_true',help='exit 1 if any original source leaf lacks a verified declared mapping; requires --field-coverage')
    p.add_argument('--fail-on-semantic-contradiction',action='store_true',help='exit 1 for contradicted declared mappings')
    p.add_argument('--fail-on-review',action='store_true')
    p.add_argument('--policy',choices=('calibrated','strict-carrier'),default='calibrated')
    args=p.parse_args(argv)
    try:
        capture_metadata=None
        if args.matrix.is_dir():
            from risu_capture import load_capture_directory
            payload,capture_metadata=load_capture_directory(args.matrix)
            contents=None
        else:
            if args.matrix.stat().st_size > 10_000_000:
                raise ValueError('matrix exceeds 10 MB input limit')
            contents=args.matrix.read_text(encoding='utf-8')
        if contents is not None and args.recovery:
            from risu_recovery import reject_dupes
            def reject_constant(text):
                raise ValueError('nonfinite JSON constant rejected: '+text)
            payload=json.loads(contents,object_pairs_hook=reject_dupes,parse_constant=reject_constant)
        elif contents is not None:
            payload=json.loads(contents)
        r=analyze(payload,args.profile,args.policy)
        if capture_metadata is not None:
            r['capture_bridge_v1']=capture_metadata
        if args.causal_trust_store is not None and not args.matrix.is_dir():
            raise ValueError('trusted recorder evidence requires an original HAR/MCP capture directory')
        from risu_causality import gate as causal_gate
        r['causal_gate_v1']=causal_gate(r,payload,args.matrix if args.matrix.is_dir() else None,args.causal_trust_store)
        r['legacy_verdicts_are_not_causal_proof']=True
        r['primary_causal_summary']=r['causal_gate_v1']['summary']
        if args.semantic_map is not None:
            if args.format=='sarif':
                raise ValueError('semantic mapping is not supported with SARIF; use JSON, text or markdown')
            from risu_semantics import assess
            r['semantic_mapping_v1']=assess(payload,r,args.matrix if args.matrix.is_dir() else None,args.semantic_map)
        if args.field_coverage:
            if args.semantic_map is None:raise ValueError('--field-coverage requires --semantic-map')
            from risu_coverage import assess_coverage
            r['field_coverage_v1']=assess_coverage(payload,r['semantic_mapping_v1'],args.semantic_map)
        if args.array_map is not None:
            if not args.field_coverage or args.semantic_map is None:
                raise ValueError('--array-map requires --field-coverage and --semantic-map')
            if args.format=='sarif':raise ValueError('array identity mapping is not available for SARIF')
            from risu_arraymatch import assess_arrays, merge_coverage
            r['array_identity_v1']=assess_arrays(payload,args.array_map,args.matrix)
            r['source_coverage_with_arrays_v1']=merge_coverage(
                r['field_coverage_v1'],r['array_identity_v1'],payload,r['semantic_mapping_v1'],args.semantic_map)
        if args.residual_map is not None:
            if args.array_map is None or args.semantic_map is None or not args.field_coverage:
                raise ValueError('--residual-map requires --semantic-map --field-coverage --array-map')
            if args.format=='sarif':raise ValueError('residual classification not supported with SARIF')
            from risu_residual import assess_residual
            r['residual_disposition_v1']=assess_residual(
                payload,r['source_coverage_with_arrays_v1'],args.residual_map,args.matrix)
        if args.obligation_map is not None:
            if args.residual_map is None:raise ValueError('--obligation-map requires --residual-map')
            if args.format=='sarif':raise ValueError('field duty output is not supported in SARIF')
            from risu_obligations import assess_obligations
            r['field_obligations_v1']=assess_obligations(
                payload,r['residual_disposition_v1'],args.obligation_map,args.matrix)
        if args.recovery:
            if args.format=='sarif':
                raise ValueError('--recovery is not supported with SARIF output; use --format json, text or markdown')
            from risu_recovery import analyze_saved
            r['recovery_v1']=analyze_saved(payload,r)
        if args.format=='json':
            rendered=json.dumps(r,ensure_ascii=False,indent=2)+'\n'
        elif args.format in ('markdown','sarif'):
            if args.format=='sarif' and args.matrix.is_dir():
                raise ValueError('native-capture SARIF requires proof-aware severity mapping and is disabled; use JSON or Markdown')
            rendered=emit(r,args.format,case_file=args.matrix.name)
            if args.format=='markdown':
                rendered='## Primary evidence-gated findings\n\n'+str(r['primary_causal_summary'])+'\n\n## Legacy comparator (not causal proof)\n\n'+rendered
            if capture_metadata is not None and args.format=='markdown':
                rendered+='\n*Input: native HAR + MCP JSON-RPC; pairing declared, not independently attested.*\n'
            if args.format=='markdown':
                from risu_causality import render_summary
                rendered+='\n## Causal evidence gate\n\n```text\n'+render_summary(r['causal_gate_v1'])+'```\n'
            if args.semantic_map is not None and args.format=='markdown':
                from risu_semantics import render as render_semantic
                rendered+='\n## Scoped semantic mapping checks (operator-declared)\n\n'+render_semantic(r['semantic_mapping_v1'])+'\n'
            if args.field_coverage and args.format=='markdown':
                from risu_coverage import render as render_coverage
                rendered+='\n## Observed source field coverage (not proof of complete preservation)\n\n'+render_coverage(r['field_coverage_v1'])+'\n'
            if args.array_map is not None and args.format=='markdown':
                from risu_arraymatch import render as render_array
                rendered+='\n## Keyed array identity checks (operator-declared)\n\n'+render_array(r['array_identity_v1'])+'\n'
                rendered+='\n## Combined original source field coverage\n\n'+str(r['source_coverage_with_arrays_v1']['summary'])+'\n'
            if args.residual_map is not None and args.format=='markdown':
                from risu_residual import render as render_residual
                rendered+='\n## Remaining original source fields: remapped, normalized or unexposed\n\n'+render_residual(r['residual_disposition_v1'])+'\n'
            if args.obligation_map is not None and args.format=='markdown':
                from risu_obligations import render as render_obligations
                rendered+='\n## Field importance and requiredness (source verified, policy labeled)\n\n'+render_obligations(r['field_obligations_v1'])+'\n'
            if args.recovery and args.format=='markdown':
                from risu_recovery import render as render_recovery
                rendered+='\n## Recovery Lens (captured evidence only)\n\n```text\n'+render_recovery(r['recovery_v1'])+'```\n'
        else:
            lines=['RISU Probe differential observation (captured responses; no new live calls)']
            if capture_metadata is not None:
                lines.append('Native HAR/MCP capture: explicit pairing is user-declared and not independently attested.')
            for e in r['results']:
                codes=','.join(d['code'] for d in e.get('diagnostics',[]))
                ev=e.get('evidence_v1',{})
                decision=e.get('decision_v1',{})
                suffix=f" | decision={decision.get('outcome')} reason={decision.get('reason')} body={ev.get('body_recovery','NOT_ASSESSED')} flag={ev.get('error_flag','UNKNOWN')}"
                status=e['causal_v1']['outcome']
                lines.append(f"{e['target']}/{e['id']}: {status} (legacy={e['verdict']})"+(f' [{codes}]' if codes else '')+suffix)
            lines.append('Primary causal summary: '+str(r['primary_causal_summary']))
            lines.append('Legacy comparator summary (not proof): '+str(r['summary']))
            lines.append('Diagnostics: '+str(r['diagnostic_summary']))
            lines.append('Evidence calibrated: '+str(r['evidence_summary']))
            lines.append('Decision (legacy P0; not independent causal proof): '+str(r['decision_summary']))
            from risu_causality import render_summary
            lines.extend(['',render_summary(r['causal_gate_v1']).rstrip('\n')])
            if args.semantic_map is not None:
                from risu_semantics import render as render_semantic
                lines.extend(['',render_semantic(r['semantic_mapping_v1']).rstrip('\n')])
            if args.field_coverage:
                from risu_coverage import render as render_coverage
                lines.extend(['',render_coverage(r['field_coverage_v1']).rstrip('\n')])
            if args.array_map is not None:
                from risu_arraymatch import render as render_array
                lines.extend(['',render_array(r['array_identity_v1']).rstrip('\n'),
                    'Combined source coverage: '+str(r['source_coverage_with_arrays_v1']['summary'])])
            if args.residual_map is not None:
                from risu_residual import render as render_residual
                lines.extend(['',render_residual(r['residual_disposition_v1']).rstrip('\n')])
            if args.obligation_map is not None:
                from risu_obligations import render as render_obligations
                lines.extend(['',render_obligations(r['field_obligations_v1']).rstrip('\n')])
            if args.recovery:
                from risu_recovery import render as render_recovery
                lines.extend(['',render_recovery(r['recovery_v1']).rstrip('\n')])
            rendered='\n'.join(lines)+'\n'
        if args.out:
            args.out.parent.mkdir(parents=True,exist_ok=True)
            args.out.write_text(rendered,encoding='utf-8')
        else:
            print(rendered,end='')
        from risu_decision import any_blocking
        if args.fail_on_confirmed_loss and r['causal_gate_v1']['summary']['CONFIRMED_LOSS']:
            return 1
        if (args.fail_on_operator_duty or args.fail_on_schema_duty or args.fail_on_unsupported_schema_claim) and args.obligation_map is None:
            raise ValueError('field obligation failure flags require --obligation-map')
        if args.fail_on_operator_duty and r['field_obligations_v1']['summary']['OPERATOR_POLICY_UNSATISFIED_OBSERVED']:
            return 1
        if args.fail_on_schema_duty and (r['field_obligations_v1']['summary']['SERVER_SCHEMA_REQUIRED_FIELD_MISSING'] or r['field_obligations_v1']['summary']['SERVER_SCHEMA_REQUIRED_FIELD_WRONG_TYPE']):
            return 1
        if args.fail_on_unsupported_schema_claim and r['field_obligations_v1']['summary']['NO_OBSERVED_SERVER_SCHEMA_REQUIREMENT']:
            return 1
        if (args.fail_on_residual_gap or args.fail_on_residual_nonexposure or args.fail_on_residual_contradiction) and args.residual_map is None:
            raise ValueError('residual failure flags require --residual-map')
        if args.fail_on_residual_contradiction and any(x['outcome']=='CONTRADICTED' for c in r['residual_disposition_v1']['cases'] for x in c['rules']):
            return 1
        if args.fail_on_residual_nonexposure and r['residual_disposition_v1']['summary']['observed_nonexposure']:
            return 1
        if args.fail_on_residual_gap and r['residual_disposition_v1']['summary']['remaining_unverified']:
            return 1
        if args.fail_on_array_contradiction and args.array_map is None:
            raise ValueError('--fail-on-array-contradiction requires --array-map')
        if args.fail_on_combined_coverage_gap and args.array_map is None:
            raise ValueError('--fail-on-combined-coverage-gap requires --array-map')
        if args.fail_on_array_contradiction and r['array_identity_v1']['summary']['contradicted_groups']:
            return 1
        if args.fail_on_combined_coverage_gap and r['source_coverage_with_arrays_v1']['summary']['combined_unverified']:
            return 1
        if args.fail_on_coverage_gap and not args.field_coverage:
            raise ValueError('--fail-on-coverage-gap requires --field-coverage')
        if args.fail_on_coverage_gap and any(c['full_source']['coverage_verified_units'] != c['full_source']['total_source_leaf_units'] or c['full_source']['total_source_leaf_units']==0 or c['rule_outcome']!='ALL_DECLARED_CHECKS_MATCH' for c in r['field_coverage_v1']['cases']):
            return 1
        if args.fail_on_semantic_contradiction and args.semantic_map is None:
            raise ValueError('--fail-on-semantic-contradiction requires --semantic-map')
        if args.fail_on_semantic_contradiction and r['semantic_mapping_v1']['rules_summary']['CONTRADICTED']:
            return 1
        # Historical strict flag remains available; it may flag *conditional* loss.
        return int(args.fail_on_loss and any_blocking(r,fail_review=args.fail_on_review))
    except (OSError,ValueError,KeyError,TypeError,AssertionError) as e:
        print('RISU Probe analyze: '+str(e),file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())