// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package replay_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/dpop"
)

// Everything that remembers one-time proofs or tokens remembers them in
// this one bounded cache, and nothing keeps a Replays of its own.
//
// Three packages had each written theirs, and the rules drifted: DPoP's had
// no bound and swept everything it held on every request, while the agent
// proofs' was capped. A merge of the two proof checks must not bring a
// private cache back, so the holders are read out of the source: every
// type with a replay.Cache in it, and every type called Replays anywhere,
// which must be one of them.
func TestEveryReplayCacheIsTheOneBoundedCache(t *testing.T) {
	holders := map[string]bool{}
	var private []string
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "testdata" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			spec, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := spec.Type.(*ast.StructType)
			if !ok {
				return true
			}
			name := f.Name.Name + "." + spec.Name.Name
			holds := false
			for _, field := range st.Fields.List {
				if sel, ok := field.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Cache" {
					if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "replay" {
						holds = true
					}
				}
			}
			if holds {
				holders[name] = true
			} else if spec.Name.Name == "Replays" {
				private = append(private, name+" in "+path)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(private)
	for _, p := range private {
		t.Errorf("%s remembers proofs without internal/replay", p)
	}
	for _, want := range []string{"dpop.Replays", "agentcred.Replays", "federate.Replays", "ssf.Push"} {
		if !holders[want] {
			t.Errorf("%s no longer holds a replay.Cache; the holders are %v", want, holders)
		}
	}

	// And the bound reaches a holder: a DPoP cache of four takes four
	// proofs and refuses the fifth, fresh and good as it is, rather than
	// forget one early.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1787000000, 0)
	replays := dpop.NewReplays(4)
	for i := 0; i < 5; i++ {
		p, err := dpop.Prove(key, "POST", "https://admin.example/mcp", "qz_token", now)
		if err != nil {
			t.Fatal(err)
		}
		_, err = dpop.Check(p, "POST", "https://admin.example/mcp", "qz_token", now, replays)
		if (err == nil) != (i < 4) {
			t.Errorf("proof %d of 5 against a bound of 4: %v", i+1, err)
		}
	}
}
