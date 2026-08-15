package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An audit record that the log refuses is dropped, and `record` reports the
// refusal on stderr rather than failing the command — which is right, because a
// logging problem should not stop somebody publishing. The cost is that an
// invalid record is a bug that shows up as one line of stderr nobody reads.
//
// This found exactly that: `scrivet import` constructed a service-kind record
// without Verified, the audit package refused it because a service principal is
// only a service if a credential proved it, and the least trustworthy operation
// in the system was the one with no log entry.
//
// So the rule is checked in the source. A record literal naming KindService
// must also set Verified, and none may omit the fields AU-3 requires.
func TestEveryAuditRecordLiteralIsValid(t *testing.T) {
	found := 0
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return err
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}

		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Record" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "audit" {
				return true
			}
			found++

			keys := map[string]string{}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				k, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				keys[k.Name] = exprText(kv.Value)
			}

			where := fset.Position(lit.Pos()).String()

			// AU-3 requires these on every record. A literal missing one is a
			// record the log will refuse at runtime.
			for _, required := range []string{"Action", "Resource", "Outcome",
				"Principal", "Kind"} {
				if _, present := keys[required]; !present {
					t.Errorf("%s: an audit.Record with no %s; AU-3 requires it "+
						"and the log will refuse this at runtime", where, required)
				}
			}

			// A service principal is only a service because a credential proved
			// it, so the two cannot be stated separately.
			if strings.Contains(keys["Kind"], "KindService") {
				v, present := keys["Verified"]
				if !present {
					t.Errorf("%s: KindService with no Verified. Verified "+
						"defaults to false and the log refuses that pairing, so "+
						"this record is silently dropped", where)
				} else if v == "false" {
					t.Errorf("%s: KindService with Verified: false, which the "+
						"log refuses", where)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Vacuous passing is the failure mode of a source-walking test.
	if found < 5 {
		t.Fatalf("only %d audit.Record literals found; this test has stopped "+
			"looking at anything", found)
	}
}

func exprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprText(v.X) + "." + v.Sel.Name
	case *ast.BasicLit:
		return v.Value
	case *ast.CallExpr:
		return exprText(v.Fun) + "(...)"
	}
	return "?"
}
