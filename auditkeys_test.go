// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
)

// No audit record names a Detail key the log will refuse.
//
// Append refuses any key containing token, secret, password, key, body or
// content — and it refuses the *whole record*, not the key. Two shipped that
// way, and neither was a secret:
//
//   - "token" for the id of a credential being revoked through the admin. The
//     credential stopped working and the log said nothing about it having been
//     revoked, or by whom, which is the one entry an incident review needs.
//   - "content" for the hash of a proposal a publish gate had just refused.
//     The gate whose entire purpose is that somebody later can see the attempt
//     recorded nothing about it.
//
// Nothing failed in either case. `record` prints the refusal to stderr and
// returns, which on a server is a line in a log nobody is reading, and on the
// command line is a sentence under a page of output about something else.
//
// So the keys are checked where they are written, which is the only place the
// mistake is visible: at the call site the name looks reasonable, and the rule
// it breaks lives in another package.
func TestNoAuditRecordUsesAKeyTheLogRefuses(t *testing.T) {
	var bad []string
	seen := 0

	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			// Tests write refused keys on purpose — that is how the refusal
			// itself is checked. This is about the records the program
			// actually writes.
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			f, perr := parser.ParseFile(token.NewFileSet(), path, src, 0)
			if perr != nil {
				return nil
			}
			for _, k := range detailKeys(f) {
				seen++
				if why := audit.ForbiddenKey(k.name); why != "" {
					bad = append(bad, path+": "+why)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	if seen < 40 {
		t.Fatalf("only %d audit detail keys found; the walk is wrong and a "+
			"test that inspects nothing passes", seen)
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Errorf("%s\n    The record is dropped whole, so the act it "+
			"describes goes unlogged while the code that writes it looks "+
			"correct", b)
	}
}

type detailKey struct{ name string }

// detailKeys finds the keys of every map[string]string literal that is an
// argument to something audit-shaped.
//
// Shape rather than type, because the records are written through four
// different helpers — record, s.audit, s.auditPub, audit.Record{Detail: …} —
// and a check that knows about three of them is the same kind of gap as the
// one it is looking for.
func detailKeys(f *ast.File) []detailKey {
	var out []detailKey
	collect := func(e ast.Expr) {
		lit, ok := e.(*ast.CompositeLit)
		if !ok {
			return
		}
		m, ok := lit.Type.(*ast.MapType)
		if !ok {
			return
		}
		if id, ok := m.Key.(*ast.Ident); !ok || id.Name != "string" {
			return
		}
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			k, ok := kv.Key.(*ast.BasicLit)
			if !ok || k.Kind != token.STRING {
				continue
			}
			if name, err := strconv.Unquote(k.Value); err == nil {
				out = append(out, detailKey{name})
			}
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if !auditShaped(x.Fun) {
				return true
			}
			for _, a := range x.Args {
				collect(a)
			}
		case *ast.KeyValueExpr:
			if id, ok := x.Key.(*ast.Ident); ok && id.Name == "Detail" {
				collect(x.Value)
			}
		}
		return true
	})
	return out
}

func auditShaped(fun ast.Expr) bool {
	name := ""
	switch f := fun.(type) {
	case *ast.Ident:
		name = f.Name
	case *ast.SelectorExpr:
		name = f.Sel.Name
	}
	switch name {
	case "record", "audit", "auditPub", "auditType", "Append", "Submit":
		return true
	}
	return false
}
