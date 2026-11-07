"""RISU P4-V: conservative $ref, anyOf/oneOf and array-items MCP outputSchema lens.

Compares advertised schemas, not witnessed production outcomes or legal duties.
Only local JSON pointers; ambiguity, recursion and unsupported composition fail closed.
Version 1: no JSON Schema implication/subtyping theorem prover.
"""
from __future__ import annotations
import copy
import hashlib
import json
import re
from typing import Any

MAX_DEPTH = 32
MAX_FIELDS = 5000
MAX_ALTERNATIVES = 40
VALID_JSON_TYPES = frozenset({'object','array','string','number','integer','boolean','null'})
VALIDATION_KEYWORDS = frozenset({
    'const','enum','format','minLength','maxLength','pattern','minimum','maximum',
    'exclusiveMinimum','exclusiveMaximum','multipleOf','minItems','maxItems',
    'uniqueItems','minProperties','maxProperties','additionalProperties',
})
ANNOTATION_KEYWORDS = frozenset({
    'title','description','default','examples','$comment','$schema','$id',
    'deprecated','readOnly','writeOnly','contentEncoding','contentMediaType',
})
STRUCTURE_KEYWORDS = frozenset({'$defs','definitions','$ref','properties','required',
                                'type','items','anyOf','oneOf'})
UNSUPPORTED_KEYWORDS = frozenset({
    'allOf','not','if','then','else','dependentSchemas','dependentRequired',
    'patternProperties','prefixItems','contains','unevaluatedItems','unevaluatedProperties',
    '$dynamicRef','$recursiveRef','propertyNames','minContains','maxContains',
})


def canon(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def pointer(token: str) -> str:
    return token.replace('~', '~0').replace('/', '~1')


def _validate_types(node: dict, where: str) -> frozenset[str]:
    raw = node.get('type')
    if raw is None:
        return frozenset()
    if isinstance(raw, str):
        if raw not in VALID_JSON_TYPES: raise ValueError('Invalid JSON Schema type at '+where)
        return frozenset((raw,))
    if not isinstance(raw, list) or not raw or not all(isinstance(t, str) and t in VALID_JSON_TYPES for t in raw) or len(set(raw)) != len(raw):
        raise ValueError('Invalid type declaration at '+where)
    return frozenset(raw)


class SchemaLens:
    def __init__(self, schema: dict):
        if not isinstance(schema, dict):
            raise ValueError('outputSchema must be a JSON object')
        self.schema = copy.deepcopy(schema)
        self.fields: dict[str, dict] = {}
        self.unions: dict[str, dict] = {}
        self._work = 0

    def _ref(self, ref: str) -> dict:
        if not isinstance(ref, str) or not ref.startswith('#/'):
            raise ValueError('External or non-pointer $ref is unsupported: '+str(ref))
        curr: Any = self.schema
        for token in ref[2:].split('/'):
            if re.search(r'~(?![01])', token):
                raise ValueError('Malformed JSON pointer: '+ref)
            key = token.replace('~1', '/').replace('~0', '~')
            if not isinstance(curr, dict) or key not in curr:
                raise ValueError('Unresolved $ref: '+ref)
            curr = curr[key]
        if not isinstance(curr, dict):
            raise ValueError('$ref target is not a schema object: '+ref)
        return curr

    def _dereference(self, node: dict, stack: tuple[str, ...], depth: int) -> tuple[dict, tuple[str, ...]]:
        if depth > MAX_DEPTH:
            raise ValueError('Schema traversal depth limit reached')
        while '$ref' in node:
            ref = node['$ref']
            if ref in stack:
                raise ValueError('Cyclic $ref detected: '+str(ref))
            # Keep semantic evidence separate: a sibling constraint is an intersection, not a ref override.
            if set(node) - {'$ref', 'title', 'description', '$comment'}:
                raise ValueError('Constrained $ref sibling requires allOf semantics; fail closed')
            stack = stack + (ref,)
            node = self._ref(ref)
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError('Excessive nested $ref depth')
        return node, stack

    def _constraints(self, node: dict, stack: tuple[str, ...], depth: int) -> dict:
        node, _ = self._dereference(node, stack, depth)
        return {k:copy.deepcopy(node[k]) for k in sorted(VALIDATION_KEYWORDS) if k in node}

    def _check_keywords(self, node: dict, path: str) -> None:
        excluded = set(node) & UNSUPPORTED_KEYWORDS
        if excluded:
            raise ValueError('Unsupported schema constraints at '+path+': '+str(sorted(excluded)))
        unknown = {k for k in node if k not in STRUCTURE_KEYWORDS | VALIDATION_KEYWORDS | ANNOTATION_KEYWORDS
                   and not k.startswith('x-')}
        if unknown:
            raise ValueError('Unknown semantic constraint at '+path+': '+str(sorted(unknown)))
        if isinstance(node.get('additionalProperties'),dict):
            raise ValueError('additionalProperties schema requires separate wildcard expansion at '+path)
        if 'additionalProperties' in node and not isinstance(node['additionalProperties'],bool):
            raise ValueError('Invalid additionalProperties at '+path)

    def _branch_label(self, raw: dict, stack: tuple[str, ...], depth: int) -> str:
        branch, _ = self._dereference(raw, stack, depth)
        if 'const' in branch:
            return 'const:'+hashlib.sha256(canon(branch['const'])).hexdigest()[:14]
        if isinstance(branch.get('enum'), list) and branch['enum']:
            return 'enum:'+hashlib.sha256(canon(sorted(branch['enum'],key=repr))).hexdigest()[:14]
        types = self._types(branch, stack, depth+1)
        if not types:
            return 'unknown'
        return 'type:' + '+'.join(sorted(types))

    def _types(self, node: dict, stack: tuple[str, ...], depth: int) -> frozenset[str]:
        node, stack = self._dereference(node, stack, depth)
        self._check_keywords(node, '$ref target')
        raw = _validate_types(node, '$ref target')
        if 'allOf' in node or 'not' in node or 'if' in node or 'then' in node or 'else' in node:
            raise ValueError('Unsupported composed schema constraint; review required')
        union_key = 'anyOf' if 'anyOf' in node else 'oneOf' if 'oneOf' in node else None
        if 'anyOf' in node and 'oneOf' in node:
            raise ValueError('Nested multiple combiners at same node require manual review')
        if union_key:
            if raw or 'properties' in node or 'items' in node:
                raise ValueError('Union with sibling structural constraints requires semantic intersection')
            arms=node[union_key]
            if not isinstance(arms, list) or not 1 <= len(arms) <= MAX_ALTERNATIVES:
                raise ValueError('Malformed or excessive union alternatives')
            total=frozenset()
            for arm in arms:
                if not isinstance(arm,dict):raise ValueError('Union arm is not an object')
                total |= self._types(arm, stack, depth+1)
            return total
        if raw:return raw
        if isinstance(node.get('properties'),dict):return frozenset({'object'})
        if 'items' in node:return frozenset({'array'})
        return frozenset()  # unconstrained, cannot assume a type

    def _walk(self, node: dict, path: str, guaranteed: bool,
              guard: tuple[str, ...], stack: tuple[str, ...], depth: int):
        self._work += 1
        if self._work > MAX_FIELDS or depth>MAX_DEPTH:
            raise ValueError('Output schema too complex to analyze safely')
        node, stack = self._dereference(node, stack, depth)
        self._check_keywords(node, path)
        # Any conditional or additional-properties/inherited composition is a review boundary.
        if any(k in node for k in ('allOf','not','if','then','else','dependentSchemas','dependentRequired','patternProperties','prefixItems','contains','unevaluatedItems','unevaluatedProperties','$dynamicRef','$recursiveRef')):
            raise ValueError('Unsupported constraint at '+path+'; refuse partial claim')
        if 'anyOf' in node or 'oneOf' in node:
            which = 'anyOf' if 'anyOf' in node else 'oneOf'
            if 'anyOf' in node and 'oneOf' in node:
                raise ValueError('Multiple union operators at '+path)
            if any(k in node for k in ('properties','items','type')):
                raise ValueError('Union sibling constraints at '+path)
            arms=node[which]
            if not isinstance(arms,list) or not 1 <= len(arms)<=MAX_ALTERNATIVES:
                raise ValueError('Invalid alternatives at '+path)
            pairs=[]
            for arm in arms:
                if not isinstance(arm,dict): raise ValueError('Invalid alternative at '+path)
                pairs.append((self._branch_label(arm,stack,depth+1),arm))
            labels=[p[0] for p in pairs]
            if len(set(labels))!=len(labels):
                raise ValueError('Ambiguous union arms cannot be mapped across versions: '+path)
            union_types = sorted(self._types(node, stack, depth+1))
            self.unions[path]={'kind':which,'arms':sorted(labels),'types':union_types}
            for label, arm in sorted(pairs,key=lambda p:p[0]):
                arm_path = path + '/@' + which + '[' + label + ']'
                self._walk(arm,arm_path,False,guard+(arm_path,),stack,depth+1)
            return
        types=self._types(node,stack,depth+1)
        props=node.get('properties',{})
        req=node.get('required',[])
        if not isinstance(props,dict) or not isinstance(req,list) or not all(isinstance(x,str) for x in req):
            raise ValueError('Malformed object properties or required at '+path)
        if len(req)!=len(set(req)) or not set(req).issubset(props):
            raise ValueError('Required key missing or duplicated at '+path)
        if props and types and types!=frozenset({'object'}):
            raise ValueError('Object properties incompatible with declared type at '+path)
        if 'items' in node and types and types!=frozenset({'array'}):
            raise ValueError('Array items incompatible with declared type at '+path)
        for key in sorted(props):
            if not isinstance(key,str) or not isinstance(props[key],dict):
                raise ValueError('Malformed property at '+path)
            at=path+'/'+pointer(key)
            child=props[key]
            child_types=sorted(self._types(child,stack,depth+1))
            local=key in req
            self.fields[at] = {'types':child_types,'constraints':self._constraints(child,stack,depth+1),'required_local':local,
                'unconditionally_required':bool(guaranteed and local and not guard),
                'guard':list(guard)}
            self._walk(child,at,guaranteed and local,guard,stack,depth+1)
        if 'items' in node:
            child=node['items']
            if not isinstance(child,dict):
                raise ValueError('Tuple / boolean items need separate handling at '+path)
            at=path+'/@items'
            self.fields[at]={'types':sorted(self._types(child,stack,depth+1)),'constraints':self._constraints(child,stack,depth+1),
               'required_local':False,'unconditionally_required':False,
               'guard':list(guard)+( [at] ),'array_item':True}
            self._walk(child,at,False,guard+(at,),stack,depth+1)

    def scan(self) -> dict:
        self._walk(self.schema,'',True,(),(),0)
        return {'fields':self.fields,'unions':self.unions,'field_count':len(self.fields),
                'union_count':len(self.unions),'root_constraints':self._constraints(self.schema,(),0),'schema_sha256':hashlib.sha256(canon(self.schema)).hexdigest()}


def _ancestor_added(path: str, previous: dict[str,Any]) -> bool:
    seg=path.split('/')
    return any('/'.join(seg[:i]) in previous for i in range(2,len(seg)))


def compare(old: dict, new: dict) -> dict:
    a=SchemaLens(old).scan();b=SchemaLens(new).scan()
    old_fields=a['fields'];new_fields=b['fields']
    events=[]; detail=[]; union_events=[]
    all_paths=sorted(old_fields.keys() | new_fields.keys())
    added=set(new_fields)-set(old_fields); removed=set(old_fields)-set(new_fields)
    for path in all_paths:
        left=old_fields.get(path);right=new_fields.get(path)
        if left is None:
            dependent = _ancestor_added(path, {k:True for k in added})
            event={'kind':'NESTED_FIELD_ADDED_UNDER_NEW_PARENT' if dependent else 'FIELD_ADDED',
                   'path':path,'before':None,'after':right,'independent_change':not dependent,
                   'risk':'NONE_INFERRED' if not right['unconditionally_required'] else 'REVIEW_REQUIRED'}
            (detail if dependent else events).append(event)
        elif right is None:
            dependent = _ancestor_added(path,{k:True for k in removed})
            event={'kind':'NESTED_FIELD_REMOVED_WITH_PARENT' if dependent else 'FIELD_REMOVED',
                   'path':path,'before':left,'after':None,'independent_change':not dependent,
                   'risk':'REVIEW_REQUIRED'}
            (detail if dependent else events).append(event)
        else:
            lt=set(left['types']);rt=set(right['types'])
            if lt != rt:
                # Unknown/untyped means unconstrained. Keep REVIEW, not a false type proof.
                if not lt or not rt: change='TYPE_CONSTRAINT_CHANGED_REVIEW'
                elif rt < lt:change='TYPE_SET_NARROWED'
                elif lt < rt:change='TYPE_SET_WIDENED'
                else:change='TYPE_SET_CHANGED'
                events.append({'kind':change,'path':path,'before':sorted(lt),'after':sorted(rt),
                               'risk':'POTENTIAL_COMPATIBILITY_CHANGE'})
            if left.get('constraints') != right.get('constraints'):
                events.append({'kind':'VALIDATION_CONSTRAINT_CHANGED_REVIEW','path':path,
                               'before':left.get('constraints'),'after':right.get('constraints'),
                               'risk':'REVIEW_REQUIRED'})
            if left['required_local'] != right['required_local']:
                events.append({'kind':'CONDITIONAL_REQUIREDNESS_CHANGED' if left['guard'] or right['guard'] else ('REQUIRED_TO_OPTIONAL' if left['required_local'] else 'OPTIONAL_TO_REQUIRED'),
                               'path':path,'before':left['required_local'],'after':right['required_local'],
                               'risk':'REVIEW_REQUIRED' if right['required_local'] else 'NONE_INFERRED'})
            if left['unconditionally_required']!=right['unconditionally_required'] and left['required_local']==right['required_local']:
                detail.append({'kind':'INHERITED_REACHABILITY_CHANGE','path':path,
                                'before':left['unconditionally_required'],'after':right['unconditionally_required'],
                                'risk':'REVIEW_REQUIRED'})
    if a['root_constraints']!=b['root_constraints']:
        events.append({'kind':'ROOT_VALIDATION_CONSTRAINT_CHANGED_REVIEW','path':'',
            'before':a['root_constraints'],'after':b['root_constraints'],'risk':'REVIEW_REQUIRED'})
    for path in sorted(a['unions'].keys() | b['unions'].keys()):
        old_un=a['unions'].get(path);new_un=b['unions'].get(path)
        if old_un == new_un:continue
        # Newly added union under a newly added property is one parent event plus detail.
        if path in added or _ancestor_added(path,{k:True for k in added}):
            detail.append({'kind':'NESTED_UNION_UNDER_NEW_PARENT','path':path,'after':new_un})
        elif path in removed or _ancestor_added(path,{k:True for k in removed}):
            detail.append({'kind':'NESTED_UNION_REMOVED_WITH_PARENT','path':path,'before':old_un})
        else:
            union_events.append({'kind':'UNION_ALTERNATIVES_CHANGED','path':path,'before':old_un,'after':new_un,
                                 'risk':'REVIEW_REQUIRED'})
    # Output compatibility is directional: can a consumer validating OLD outputs
    # still accept values emitted under NEW? Required-output obligations and
    # compatibility are separate questions. Conservatively classify an added
    # property under an explicitly closed old object as a validator break.
    # All remaining cases are not a proof of compatibility: real consumers may
    # reject unexpected fields independently of JSON Schema.
    backward_events = []
    def check_addition_path(p):
        seg=p.split('/')[1:]
        lens=SchemaLens(old)
        ancestor=old
        stack=()
        prefix=''
        for token in seg:
            ancestor,stack=lens._dereference(ancestor,stack,0)
            if token=='@items':
                if not isinstance(ancestor.get('items'),dict):return None
                ancestor=ancestor['items']
                prefix += '/@items'
                continue
            if token.startswith('@anyOf[') or token.startswith('@oneOf['):
                which=token[1:].split('[',1)[0]
                label=token[len(which)+2:-1]
                arms=ancestor.get(which,[])
                if not isinstance(arms,list):return None
                matches=[a for a in arms if isinstance(a,dict) and lens._branch_label(a,stack,0)==label]
                if len(matches)!=1:return None
                ancestor=matches[0]
                prefix += '/'+token
                continue
            if token.startswith('@'):
                return None
            name=token.replace('~1','/').replace('~0','~')
            props=ancestor.get('properties', {})
            if not isinstance(props,dict):return None
            if name not in props:
                if ancestor.get('additionalProperties') is False:
                    return {'path':p,'reason':'OLD_CLOSED_OBJECT_REJECTS_NEW_FIELD',
                            'closed_old_parent':prefix or '/', 'risk':'POTENTIAL_VALIDATOR_BREAK'}
                return None
            ancestor=props[name]
            prefix += '/'+pointer(name)
        return None
    for event in events:
        if event['kind']=='FIELD_ADDED':
            witness=check_addition_path(event['path'])
            if witness:
                event['risk']='POTENTIAL_VALIDATOR_BREAK'
                event['consumer_witness']=witness
                backward_events.append(witness)
        elif event['kind']=='FIELD_REMOVED' and event['before']['required_local']:
            witness={'path':event['path'],'reason':'OLD_REQUIRED_OUTPUT_MAY_BE_MISSING',
                     'risk':'POTENTIAL_VALIDATOR_BREAK'}
            event['risk']='POTENTIAL_VALIDATOR_BREAK'
            backward_events.append(witness)
        elif event['kind'] in ('REQUIRED_TO_OPTIONAL','TYPE_SET_WIDENED','TYPE_SET_CHANGED','TYPE_CONSTRAINT_CHANGED_REVIEW'):
            witness={'path':event['path'],'reason':'NEW_OUTPUTS_MAY_NOT_VALIDATE_AGAINST_OLD_SCHEMA',
                     'risk':'REVIEW_REQUIRED' if event['kind']=='TYPE_CONSTRAINT_CHANGED_REVIEW' else 'POTENTIAL_VALIDATOR_BREAK'}
            event['risk']=witness['risk']
            backward_events.append(witness)
        elif event['kind']=='VALIDATION_CONSTRAINT_CHANGED_REVIEW':
            backward_events.append({'path':event['path'],'reason':'CONSTRAINT_CHANGE_REQUIRES_VALIDATOR_PROOF',
                                    'risk':'REVIEW_REQUIRED'})
    for event in union_events:
        backward_events.append({'path':event['path'],'reason':'UNION_VARIANTS_CHANGED_REQUIRES_VALIDATOR_PROOF',
                                'risk':'REVIEW_REQUIRED'})
    old_root_types=SchemaLens(old)._types(old,(),0)
    new_root_types=SchemaLens(new)._types(new,(),0)
    if old_root_types!=new_root_types:
        if not old_root_types or not new_root_types or not new_root_types.issubset(old_root_types):
            backward_events.append({'path':'/','reason':'ROOT_OUTPUT_TYPE_WIDENED_OR_CHANGED',
                                    'before':sorted(old_root_types),'after':sorted(new_root_types),
                                    'risk':'REVIEW_REQUIRED' if not old_root_types or not new_root_types else 'POTENTIAL_VALIDATOR_BREAK'})
    for event in events:
        if event['kind']=='ROOT_VALIDATION_CONSTRAINT_CHANGED_REVIEW':
            backward_events.append({'path':'/','reason':'ROOT_VALIDATION_CONSTRAINT_CHANGED',
                                    'risk':'REVIEW_REQUIRED'})
    # Even the absence of a schema-level witness is not a blanket guarantee for
    # consumers: custom strict decoders and runtime code are outside our scope.
    consumer_status = 'POTENTIAL_VALIDATOR_BREAK' if any(x['risk']=='POTENTIAL_VALIDATOR_BREAK' for x in backward_events) else ('REVIEW_REQUIRED' if backward_events else 'NOT_PROVEN_COMPATIBLE')
    return {'format':'risu-nested-contract-diff-v2','consumer_output_compatibility':{
                'direction':'new outputs checked by old consumer schema',
                'status':consumer_status,'witnesses':backward_events,
                'guaranteed_safe':False,
                'limitation':'Only concrete schema-level witnesses; no actual consumer execution, total schema implication or universal compatibility claim'},
            'old':{'field_count':a['field_count'],'union_count':a['union_count'],'schema_sha256':a['schema_sha256']},
        'new':{'field_count':b['field_count'],'union_count':b['union_count'],'schema_sha256':b['schema_sha256']},
        'events':events,'conditional_structure_details_not_independent':detail,'union_events':union_events,
        'summary':{'independent_events':len(events),'conditional_detail_events':len(detail),
                   'union_events':len(union_events),'unconditionally_required_new_fields':sum(x['kind']=='FIELD_ADDED' and x['after']['unconditionally_required'] for x in events),
                   'potential_compatibility_changes':len({x['path'] for x in events+union_events if x.get('risk') in ('REVIEW_REQUIRED','POTENTIAL_COMPATIBILITY_CHANGE','POTENTIAL_VALIDATOR_BREAK')}),
                   'unresolved_schema_review':0},
        'limitation':'Declared schema difference only; no production regression, data loss, consumer breakage, operator duty or legal breach proven.'}
