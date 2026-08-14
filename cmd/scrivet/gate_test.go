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

// This project has three times shipped a rule that one interface enforced and
// another did not: the accessibility gate lived in the CLI while the web UI
// published around it, the provenance mark did the same, and a read-only token
// was checked when it was issued and never when it was used. Each time the
// finding was the same sentence — a control present in one interface and absent
// from another is a control with a hole in whichever one people actually use.
//
// So this is not a test of behaviour. It is a test of the source: every place
// that writes content must sit in a function that also consults the type gate.
// A fourth write surface added later fails here rather than in production.
func TestEveryWriteSurfaceConsultsTheTypeGate(t *testing.T) {
	// The known gate calls. The CLI and the MCP server call gateWrite directly;
	// the admin server is a separate package and reaches the same schema.Store
	// through the CheckTypes function field, wired in serve.go.
	gates := []string{"gateWrite", "CheckTypes"}

	roots := []string{"..", filepath.Join("..", "..", "internal")}
	found := 0

	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
				strings.HasSuffix(path, "_test.go") {
				return err
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}

			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				if !calls(fn, "SaveDraft") {
					continue
				}
				found++
				gated := false
				for _, g := range gates {
					if mentions(fn, g) {
						gated = true
						break
					}
				}
				if !gated {
					t.Errorf("%s:%s writes content but never consults the type "+
						"gate.\n  Every write surface must call one of %v before "+
						"site.SaveDraft, or type validation is a rule about "+
						"whichever interface you happened to read.",
						path, fn.Name.Name, gates)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// If the walk finds nothing, the test passes vacuously and would keep
	// passing after someone renamed SaveDraft. Four is the count today: the CLI
	// add command, the assist command, the MCP write operation and the admin
	// save handler. The assist path is the one this test found on its first
	// run, which is the argument for having written it.
	if found < 4 {
		t.Fatalf("expected at least 4 write surfaces, found %d — this test has "+
			"stopped looking at anything", found)
	}
}

func calls(fn *ast.FuncDecl, name string) bool {
	seen := false
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
			seen = true
		}
		return true
	})
	return seen
}

func mentions(fn *ast.FuncDecl, name string) bool {
	seen := false
	ast.Inspect(fn, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.Ident:
			if v.Name == name {
				seen = true
			}
		case *ast.SelectorExpr:
			if v.Sel.Name == name {
				seen = true
			}
		}
		return true
	})
	return seen
}
