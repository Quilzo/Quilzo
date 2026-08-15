package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rsh1k/scrivet/internal/auth"
)

// Every command that changes something must leave a record of having done it.
//
// There was already a test for this and it passed while `scrivet add` — the
// most common write in the entire program — wrote nothing at all. It passed
// because it checked a hand-maintained list of eight function names, and the
// comment above that list said the quiet part: "adding a privileged command
// means adding a line here". A list maintained by the same person who forgot
// the call is not a check.
//
// So the list is derived instead. The privilege table already says which
// commands mutate — anything needing more than a read — and this walks the
// call graph from each one to see whether record() is reachable. A new
// command is covered the moment it is dispatched, whether or not anybody
// remembered this file exists.
func TestEveryMutatingCommandCanReachTheAuditLog(t *testing.T) {
	fns, calls := callGraph(t)
	dispatch := dispatchTargets(t)

	var missing []string
	for cmd, n := range commandNeeds {
		if n.action == "" || n.action == auth.ActView {
			continue
		}
		if strings.Contains(cmd, " ") {
			continue // subcommands run inside their parent
		}
		entry, ok := dispatch[cmd]
		if !ok {
			t.Errorf("%q is in the privilege table but nothing dispatches it", cmd)
			continue
		}
		if !reaches(entry, "record", calls, fns, map[string]bool{}) {
			missing = append(missing, cmd+" ("+entry+")")
		}
	}
	if len(missing) > 0 {
		t.Errorf("these commands change something and cannot reach record():\n"+
			"  %s\n"+
			"AU-3 wants who did what. A store where the most ordinary write is "+
			"invisible is one where the log answers a narrower question than "+
			"anybody reading it will assume.", strings.Join(missing, "\n  "))
	}
}

// reaches reports whether target is callable from fn, following calls within
// this package. Depth-limited by the visited set rather than by a counter,
// because the graph is small and a counter would silently stop early.
func reaches(fn, target string, calls map[string][]string, known map[string]bool,
	seen map[string]bool) bool {

	if fn == target {
		return true
	}
	if seen[fn] {
		return false
	}
	seen[fn] = true
	for _, callee := range calls[fn] {
		if callee == target {
			return true
		}
		if known[callee] && reaches(callee, target, calls, known, seen) {
			return true
		}
	}
	return false
}

// callGraph returns the functions declared in package main and, for each, the
// names it calls.
func callGraph(t *testing.T) (map[string]bool, map[string][]string) {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	calls := map[string][]string{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			name := fn.Name.Name
			declared[name] = true
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					calls[name] = append(calls[name], fun.Name)
				case *ast.SelectorExpr:
					calls[name] = append(calls[name], fun.Sel.Name)
				}
				return true
			})
		}
	}
	if len(declared) < 50 {
		t.Fatalf("only %d functions parsed; the walk is wrong and a test that "+
			"sees nothing passes", len(declared))
	}
	return declared, calls
}

// dispatchTargets maps each case label in main's command switch to the
// function it calls.
func dispatchTargets(t *testing.T) map[string]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	ast.Inspect(f, func(node ast.Node) bool {
		sw, ok := node.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		if id, ok := sw.Tag.(*ast.Ident); !ok || id.Name != "cmd" {
			return true
		}
		for _, stmt := range sw.Body.List {
			cl, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			target := ""
			ast.Inspect(cl, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok && target == "" {
					if id, ok := call.Fun.(*ast.Ident); ok {
						target = id.Name
					}
				}
				return true
			})
			for _, expr := range cl.List {
				if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					out[strings.Trim(lit.Value, `"`)] = target
				}
			}
		}
		return true
	})
	return out
}
