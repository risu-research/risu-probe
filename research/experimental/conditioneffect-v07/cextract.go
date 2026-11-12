// ConditionEffect v0.7: restricted Go AST structural checking of conditional S3 writes.
// It only certifies a syntactic proof obligation. No cross-process concurrency,
// no library semantics or general backend behavior is proven.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Site struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Description string `json:"description"`
}
type Result struct {
	Operation      string          `json:"operation"`
	Classification string          `json:"classification"`
	Reason         string          `json:"reason"`
	Resource       string          `json:"resource"`
	Sites          []Site          `json:"sites"`
	Obligations    map[string]bool `json:"obligations"`
	Assumptions    []string        `json:"assumptions"`
}
type Record struct {
	Schema      string            `json:"schema"`
	SourceFiles map[string]string `json:"source_sha256"`
	Results     []Result          `json:"results"`
	Scope       string            `json:"scope"`
}
type Func struct {
	Fn   *ast.FuncDecl
	File string
}

var fset *token.FileSet

func callName(c *ast.CallExpr) string {
	switch e := c.Fun.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	case *ast.CallExpr:
		return callName(e)
	default:
		return ""
	}
}
func findCalls(n ast.Node, want string) []*ast.CallExpr {
	var hits []*ast.CallExpr
	ast.Inspect(n, func(x ast.Node) bool {
		if c, ok := x.(*ast.CallExpr); ok && callName(c) == want {
			hits = append(hits, c)
		}
		return true
	})
	return hits
}
func ident(e ast.Expr) string {
	x, ok := e.(*ast.Ident)
	if !ok {
		return ""
	}
	return x.Name
}
func exprString(e ast.Expr) string {
	if s := ident(e); s != "" {
		return s
	}
	return "?"
}
func pos(x ast.Node, path string, label string) Site {
	return Site{File: path, Line: fset.Position(x.Pos()).Line, Description: label}
}
func isErrReturn(st ast.Stmt) bool {
	b, ok := st.(*ast.BlockStmt)
	if !ok || len(b.List) == 0 {
		return false
	}
	_, ok = b.List[len(b.List)-1].(*ast.ReturnStmt)
	return ok
}
func errExitIf(i *ast.IfStmt) bool {
	if i.Else != nil || !isErrReturn(i.Body) {
		return false
	}
	b, ok := i.Cond.(*ast.BinaryExpr)
	if !ok || b.Op != token.NEQ {
		return false
	}
	left, right := ident(b.X), ident(b.Y)
	return (left == "aerr" && right == "nil") || (right == "aerr" && left == "nil")
}
func hasCall(stmt ast.Stmt, name string) bool { return len(findCalls(stmt, name)) > 0 }
func objFields(fn *ast.FuncDecl) (string, string) {
	var bucket, key string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		x, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		t, ok := x.Type.(*ast.Ident)
		if !ok || t.Name != "Object" {
			return true
		}
		var b, k string
		for _, el := range x.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			switch ident(kv.Key) {
			case "Bucket":
				b = exprString(kv.Value)
			case "Key":
				k = exprString(kv.Value)
			}
		}
		if b != "" && k != "" {
			bucket = b
			key = k
		}
		return true
	})
	return bucket, key
}
func guardIndex(fn *ast.FuncDecl) (int, int) {
	parse, active := -1, -1
	for i, s := range fn.Body.List {
		if hasCall(s, "parseConditionalWrite") && parse < 0 {
			parse = i
		}
		if branch, ok := s.(*ast.IfStmt); ok {
			if call, ok := branch.Cond.(*ast.CallExpr); ok && callName(call) == "active" && len(call.Args) == 0 {
				if x, ok := call.Fun.(*ast.SelectorExpr); ok && ident(x.X) == "cond" {
					active = i
				}
			}
		}
	}
	return parse, active
}
func verifyHelpers(funcs map[string]Func) (bool, []string) {
	needed := []string{"parseConditionalWrite", "checkConditionalWrite", "evaluate", "active"}
	var reasons []string
	for _, k := range needed {
		if _, ok := funcs[k]; !ok {
			reasons = append(reasons, "missing helper: "+k)
		}
	}
	if len(reasons) > 0 {
		return false, reasons
	}
	parserFn := funcs["parseConditionalWrite"].Fn
	evalFn := funcs["evaluate"].Fn
	checkFn := funcs["checkConditionalWrite"].Fn
	p := funcs["parseConditionalWrite"].File
	_, _ = p, parserFn
	// These are syntactic *preconditions*, not a full proof of helper semantics.
	if len(findCalls(parserFn, "Get")) < 2 {
		reasons = append(reasons, "header parser has too few Get calls")
	}
	if len(findCalls(checkFn, "lookupObjectMeta")) != 1 || len(findCalls(checkFn, "evaluate")) != 1 {
		reasons = append(reasons, "helper lookup/evaluate changed")
	}
	if len(findCalls(evalFn, "etagMatches")) != 1 || len(findCalls(evalFn, "errPreconditionFailed")) < 2 || len(findCalls(evalFn, "errNoSuchKey")) < 1 {
		reasons = append(reasons, "condition evaluation changed")
	}
	return len(reasons) == 0, reasons
}

func requestTargetBound(fn *ast.FuncDecl, bucket, key string) (bool, string) {
	seenB, seenK := 0, 0
	for _, st := range fn.Body.List {
		assign, ok := st.(*ast.AssignStmt)
		if !ok {
			continue
		}
		if len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			continue
		}
		id := ident(assign.Lhs[0])
		if id != bucket && id != key {
			continue
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return false, "target variable is not assigned from request function"
		}
		if id == bucket {
			seenB++
			if callName(call) != "URLParam" || len(call.Args) != 2 || ident(call.Args[0]) != "r" {
				return false, "bucket not sourced from request"
			}
			literal, ok := call.Args[1].(*ast.BasicLit)
			if !ok || literal.Value != `"bucket"` {
				return false, "bucket URL parameter name altered"
			}
		} else {
			seenK++
			if callName(call) != "objectKey" || len(call.Args) != 1 || ident(call.Args[0]) != "r" {
				return false, "key not sourced from request"
			}
		}
	}
	if seenB != 1 || seenK != 1 {
		return false, "request target has non-unique or missing assignments"
	}
	unsafe := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch t := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range t.Lhs {
				if selector, ok := lhs.(*ast.SelectorExpr); ok && (selector.Sel.Name == "Key" || selector.Sel.Name == "Bucket") {
					unsafe = true
				}
			}
		case *ast.UnaryExpr:
			if t.Op == token.AND && (ident(t.X) == bucket || ident(t.X) == key) {
				unsafe = true
			}
		}
		return true
	})
	if unsafe {
		return false, "target identity may be mutated or aliased"
	}
	return true, ""
}

func resourceLabel(b, k string) string {
	if b == "" || k == "" {
		return "unknown"
	}
	return b + "/" + k
}
func checkLock(block *ast.BlockStmt, bucket, key string) (bool, []Site, string) {
	if len(block.List) != 2 {
		return false, nil, "conditional branch is not exactly lock defer + check/error exit"
	}
	d, ok := block.List[0].(*ast.DeferStmt)
	if !ok {
		return false, nil, "first active-branch action is not a defer"
	}
	outer := d.Call
	inner, ok := outer.Fun.(*ast.CallExpr)
	if !ok || callName(inner) != "Lock" || len(inner.Args) != 1 || len(outer.Args) != 0 {
		return false, nil, "defer is not a Lock(...)()"
	}
	keyCalls := findCalls(inner, "objectStoreKey")
	if len(keyCalls) != 1 || len(keyCalls[0].Args) != 2 || ident(keyCalls[0].Args[0]) != bucket || ident(keyCalls[0].Args[1]) != key {
		return false, nil, "lock key does not match mutation resource"
	}
	q, ok := block.List[1].(*ast.IfStmt)
	if !ok || !errExitIf(q) {
		return false, nil, "check error does not force return"
	}
	if len(findCalls(q.Body, "WriteXMLError")) < 1 {
		return false, nil, "check error branch does not report error"
	}
	tests := findCalls(q.Init, "checkConditionalWrite")
	if len(tests) != 1 || len(tests[0].Args) != 4 {
		return false, nil, "not exactly one conditional check with four arguments"
	}
	args := tests[0].Args
	if ident(args[1]) != "cond" || ident(args[2]) != bucket || ident(args[3]) != key {
		return false, nil, "guard check conditions/resource differ from mutation"
	}
	return true, []Site{pos(d, "", "keyed deferred lock"), pos(q, "", "conditional preflight check with error exit")}, ""
}
func inspect(op string, fn Func, funcs map[string]Func, helperOk bool, helperReasons []string) Result {
	r := Result{Operation: op, Classification: "ABSTAIN", Resource: "unknown", Obligations: map[string]bool{}, Assumptions: []string{
		"Only this statically recognized handler is inspected.",
		"Effects of called helpers and object storage are trusted beyond the checked source shape.",
		"Concurrency claim is limited to competing conditional calls using the same lock; no guarantee against other writers.",
	}}
	path := fn.File
	f := fn.Fn
	// This restricted proof has no concurrent handler-body semantics.
	foundGo := false
	ast.Inspect(f.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.GoStmt); ok {
			foundGo = true
		}
		return true
	})
	if foundGo {
		r.Reason = "goroutine in handler is outside supported effect model"
		return r
	}
	b, k := objFields(f)
	r.Resource = resourceLabel(b, k)
	if b != "" && k != "" {
		if ok, why := requestTargetBound(f, b, k); !ok {
			r.Reason = "request target unbound: " + why
			return r
		}
		r.Obligations["request_target_bound"] = true
	}
	if b == "" || k == "" {
		r.Reason = "could not extract Object bucket/key"
		return r
	}
	target := findCalls(f.Body, "commitVersion")
	if len(target) != 1 {
		r.Reason = "mutation commit is not unique"
		return r
	}
	sink := target[0]
	r.Sites = append(r.Sites, pos(sink, path, "commitVersion effect site"))
	parseIdx, activeIdx := guardIndex(f)
	if parseIdx < 0 {
		r.Classification = "MISSING_GUARD_CANDIDATE"
		r.Reason = "mutation reached, no conditional parser found in handler"
		return r
	}
	r.Obligations["parses_condition"] = true
	r.Sites = append(r.Sites, pos(f.Body.List[parseIdx], path, "parse conditional request"))
	if activeIdx <= parseIdx {
		r.Reason = "active guard branch missing or occurs before parse"
		return r
	}
	var parseExit bool
	// The first statement after parsing must stop on *that* parse error.
	// No rebinding or unrelated error check may intervene.
	if parseIdx+1 < activeIdx {
		if x, ok := f.Body.List[parseIdx+1].(*ast.IfStmt); ok && errExitIf(x) && len(findCalls(x.Body, "WriteXMLError")) > 0 {
			parseExit = true
		}
	}
	if !parseExit {
		r.Reason = "parse errors may reach mutation"
		return r
	}
	r.Obligations["parse_error_stops_write"] = true
	branch := f.Body.List[activeIdx].(*ast.IfStmt)
	ok, sites, reason := checkLock(branch.Body, b, k)
	if !ok {
		r.Reason = reason
		return r
	}
	r.Obligations["guarded_check_and_keyed_lock"] = true
	for _, p := range sites {
		p.File = path
		r.Sites = append(r.Sites, p)
	}
	// Exclude writes reachable before guard; refuse unsupported control-flow before it.
	for i, s := range f.Body.List {
		if i < activeIdx {
			if hasCall(s, "beginVersion") || hasCall(s, "putObjectStream") || hasCall(s, "copyBody") || hasCall(s, "putObjectMeta") || hasCall(s, "commitVersion") {
				r.Reason = "effect may precede conditional check"
				return r
			}
			if _, ok := s.(*ast.GoStmt); ok {
				r.Reason = "concurrency before guard unsupported"
				return r
			}
		}
		if i >= activeIdx && i < len(f.Body.List)-1 {
			if x, ok := s.(*ast.IfStmt); ok && x.Else != nil && hasCall(x.Else, "commitVersion") {
				r.Reason = "branch-local commit unsupported"
				return r
			}
		}
	}
	if fset.Position(sink.Pos()).Offset <= fset.Position(branch.End()).Offset {
		r.Reason = "commit is not after the guarded branch"
		return r
	}
	r.Obligations["check_precedes_commit"] = true
	if !helperOk {
		r.Reason = "helper semantics cannot be recognized: " + strings.Join(helperReasons, "; ")
		return r
	}
	r.Obligations["helper_semantic_shape"] = true
	// Every direct call to these effect helpers must occur after the guard (including in nested blocks).
	for _, name := range []string{"beginVersion", "putObjectStream", "copyBody", "putObjectMeta", "commitVersion"} {
		for _, call := range findCalls(f.Body, name) {
			if call.Pos() < branch.End() {
				r.Reason = "effect " + name + " may occur before guard"
				return r
			}
		}
	}
	r.Obligations["no_known_pre_guard_effect"] = true
	r.Classification = "STRUCTURALLY_GUARDED"
	r.Reason = "recognized top-level conditional parser; error exit; condition-activated resource-keyed deferred lock; check error exit; later mutation"
	return r
}
func main() {
	var dir, out string
	flag.StringVar(&dir, "src", "", "directory containing Go source files")
	flag.StringVar(&out, "out", "", "output JSON path; omit for stdout")
	flag.Parse()
	if dir == "" {
		fmt.Fprintln(os.Stderr, "usage: cextract -src <path> [-out file]")
		os.Exit(2)
	}
	files := []string{"handler_object.go", "handler_multipart.go", "conditional_write.go", "handler.go"}
	funcs := map[string]Func{}
	hashes := map[string]string{}
	fset = token.NewFileSet()
	for _, name := range files {
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) && name == "conditional_write.go" {
				continue
			}
			fmt.Fprintln(os.Stderr, "missing:", path, err)
			os.Exit(2)
		}
		h := sha256.Sum256(raw)
		hashes[name] = hex.EncodeToString(h[:])
		file, err := parser.ParseFile(fset, path, raw, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid Go:", path, err)
			os.Exit(2)
		}
		for _, d := range file.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Body != nil {
				funcs[fn.Name.Name] = Func{Fn: fn, File: name}
			}
		}
	}
	good, reasons := verifyHelpers(funcs)
	// A method-body structural check can rely on a helper contract only when
	// its exact audited implementation is pinned. Otherwise ABSTAIN; the AST
	// call names alone are not evidence of correct helper semantics.
	const auditedConditionalHelperSHA256 = "aa3eb220eb504c8eb042b57fa166991ac05b4b237c5ce4c459781e37fb695fb5"
	if hashes["conditional_write.go"] != auditedConditionalHelperSHA256 {
		good = false
		reasons = append(reasons, "conditional helper differs from audited source hash")
	}
	record := Record{Schema: "risu.condition-effect.go-ast.v0.7", SourceFiles: hashes,
		Scope: "restricted source-structural obligation; not a general proof of atomicity, runtime safety or API behavior"}
	ops := []string{"PutObject", "CompleteMultipartUpload", "CopyObject"}
	for _, op := range ops {
		fn, ok := funcs[op]
		if !ok {
			record.Results = append(record.Results, Result{Operation: op, Classification: "ABSTAIN", Reason: "handler missing"})
			continue
		}
		record.Results = append(record.Results, inspect(op, fn, funcs, good, reasons))
	}
	sort.Slice(record.Results, func(i, j int) bool { return record.Results[i].Operation < record.Results[j].Operation })
	data, _ := json.MarshalIndent(record, "", "  ")
	data = append(data, '\n')
	if out == "" {
		os.Stdout.Write(data)
	} else {
		if err := os.WriteFile(out, data, 0644); err != nil {
			panic(err)
		}
	}
}
