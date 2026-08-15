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

			// Detail keys are checked against the same list the audit package
			// refuses on. A record with a forbidden key is dropped at runtime
			// with one line of stderr, which is how `review.approve` -- the
			// record AC-3(2) exists to produce -- was silently not being
			// written because its key was called "content" and held a hash.
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				k, ok := kv.Key.(*ast.Ident)
				if !ok || k.Name != "Detail" {
					continue
				}
				detail, ok := kv.Value.(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, d := range detail.Elts {
					dkv, ok := d.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					lit, ok := dkv.Key.(*ast.BasicLit)
					if !ok {
						continue
					}
					name := strings.ToLower(strings.Trim(lit.Value, `"`))
					for _, bad := range []string{
						"token", "secret", "password", "key", "body", "content",
					} {
						if strings.Contains(name, bad) {
							t.Errorf("%s: Detail key %q contains %q, which the "+
								"audit package refuses. This record is dropped "+
								"at runtime with one line of stderr.",
								where, name, bad)
						}
					}
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
	case *ast.BinaryExpr:
		// `"auth." + verb` — concatenation is how an action gets a variable
		// suffix, and returning "?" for it made this test unable to see a
		// record that was there.
		return exprText(v.X) + exprText(v.Y)
	}
	return "?"
}

// Every privileged command must leave a record.
//
// NIST AU-2 names privileged actions as the set that has to be logged, and a
// change to who holds a role is the most privileged thing this program does:
// it decides who may do everything else. A demo found `auth grant`, `auth
// revoke`, `token issue`, `token exchange` and `token revoke` all writing
// nothing — granting somebody admin left no trace at all.
//
// Checked in the source rather than by running commands, because the failure
// mode is an absent call and a behavioural test can only find those one at a
// time.
func TestEveryPrivilegedCommandWritesAnAuditRecord(t *testing.T) {
	// Function name to the action string its record must carry.
	//
	// This list is no longer the coverage check — TestEveryMutatingCommand-
	// CanReachTheAuditLog derives that from the privilege table, because this
	// list passed for months while `scrivet add` recorded nothing at all. A
	// list maintained by the same person who forgets the call is not a check.
	//
	// It is kept for what it does test and the derived one cannot: that these
	// records carry the specific action strings a SIEM rule will match on.
	// Renaming "token.issue" would still break somebody's alerting.
	required := map[string]string{
		"authGrant":     "auth.",
		"authRevoke":    "auth.revoke",
		"tokenIssue":    "token.issue",
		"tokenExchange": "token.exchange",
		"tokenRevoke":   "token.revoke",
		"cmdImport":     "import",
		"cmdExport":     "export",
		"cmdSiem":       "auditlog.export",
	}

	found := map[string]string{}
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
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if _, want := required[fn.Name.Name]; !want {
				continue
			}
			var actions []string
			ast.Inspect(fn, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				sel, ok := lit.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Record" {
					return true
				}
				for _, elt := range lit.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Action" {
						actions = append(actions, exprText(kv.Value))
					}
				}
				return true
			})
			found[fn.Name.Name] = strings.Join(actions, ",")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for name, wantAction := range required {
		got, present := found[name]
		if !present {
			t.Errorf("%s was not found; if it was renamed, update this list "+
				"rather than deleting the entry", name)
			continue
		}
		if got == "" {
			t.Errorf("%s performs a privileged action and writes no audit "+
				"record. AU-2 names exactly this set as the one that must be "+
				"logged", name)
			continue
		}
		if !strings.Contains(got, wantAction) {
			t.Errorf("%s records %q, expected an action containing %q",
				name, got, wantAction)
		}
	}
}
