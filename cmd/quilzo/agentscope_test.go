// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentexec"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
)

// A store with one page of each of two types, plus one page bound to nothing.
func typedStore(t *testing.T) string {
	t.Helper()
	if w == nil {
		w = out.New(false)
		t.Cleanup(func() { w = nil })
	}
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index":   map[string]any{"title": "Home"},
		"pen":     map[string]any{"title": "Brass pen", "locale": "en"},
		"returns": map[string]any{"title": "Returns", "locale": "fr"},
	}, "first", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}

	reg := schema.NewRegistry()
	for _, name := range []string{"product", "policy"} {
		if err := reg.Add(schema.Type{Name: name, Fields: []schema.Field{
			{Name: "title", Kind: schema.Text, Required: true}}}); err != nil {
			t.Fatal(err)
		}
	}
	st := &schema.Store{Registry: reg, Bound: map[string]string{
		"pen": "product", "returns": "policy"}}
	if err := saveJSON(filepath.Join(root, "types.json"), st); err != nil {
		t.Fatal(err)
	}
	return root
}

// readerFor builds the Reader exactly as `agent run` does.
func readerFor(t *testing.T, root string, m agent.Manifest) agentexec.Reader {
	t.Helper()
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	return agentexec.Reader{
		Store:  s,
		Types:  pageTypeOf(root),
		Locale: pageLocaleOf(s, refOf(m)),
	}
}

func scopedAgent(types, locales []string) agent.Manifest {
	return agent.Manifest{
		Name: "librarian", Kind: agent.KindRetrieval,
		Purpose:      "answer from one kind of page",
		Capabilities: []string{"list_pages", "read_page", "search_pages"},
		Autonomy:     agent.AutonomyPropose,
		Retrieval: agent.Retrieval{
			Ref: site.RefLive, Types: types, Locales: locales},
		Budget: agent.Budget{
			Steps: 20, Tools: 0, Duration: agent.Duration(time.Hour)},
	}
}

// The hole. `agent run` built the Reader with no type or locale resolver, and
// Reader treats a nil one as "nothing is typed" — which Session.Retrieve then
// reads as unrestricted. So a manifest scoped to one content type read
// everything, and said otherwise on every screen that showed it.
func TestAManifestsTypeScopeIsEnforced(t *testing.T) {
	root := typedStore(t)
	m := scopedAgent([]string{"product"}, nil)
	r := readerFor(t, root, m)
	s := agent.NewSession(m, nil)

	out, err := r.Perform(s)(context.Background(),
		agent.Action{Op: "list_pages"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "pen") {
		t.Errorf("the product page is missing:\n%s", out)
	}
	if strings.Contains(out, "returns") {
		t.Errorf("a page of another type was listed:\n%s", out)
	}
	// index is bound to no type at all, and a page with no type is not
	// excluded by a type scope — there is nothing to compare it against.
	if !strings.Contains(out, "index") {
		t.Errorf("an untyped page was excluded by a type scope:\n%s", out)
	}
}

// Reading the page directly is refused too, not merely omitted from a list.
func TestReadingOutsideTheTypeScopeIsRefused(t *testing.T) {
	root := typedStore(t)
	m := scopedAgent([]string{"product"}, nil)
	r := readerFor(t, root, m)

	_, err := r.Perform(agent.NewSession(m, nil))(context.Background(),
		agent.Action{Op: "read_page", Input: map[string]any{"page": "returns"}})
	if err == nil {
		t.Fatal("a page of another type was read")
	}
}

// Search is not tested here, and is on main.
//
// The upstream fix also checks that search_pages is bounded by the same scope.
// That operation was wired to the agent surface after this release was cut, so
// there is nothing here to bound, and a test asserting that an absent
// capability is correctly restricted would pass for the wrong reason. The type
// scope is enforced in Session.Retrieve, which every read goes through, so the
// check above covers this build.

// The locale scope, which comes from the page's own field rather than from the
// type — the same type exists in every language, which is the point of having
// locales.
func TestAManifestsLocaleScopeIsEnforced(t *testing.T) {
	root := typedStore(t)
	m := scopedAgent(nil, []string{"en"})
	r := readerFor(t, root, m)

	out, err := r.Perform(agent.NewSession(m, nil))(context.Background(),
		agent.Action{Op: "list_pages"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "pen") {
		t.Errorf("the English page is missing:\n%s", out)
	}
	if strings.Contains(out, "returns") {
		t.Errorf("a French page was listed to an agent scoped to en:\n%s", out)
	}
}

// A manifest that scopes nothing still reads everything, or the fix above
// would have closed the hole by breaking the feature.
func TestAnUnscopedManifestStillReadsEverything(t *testing.T) {
	root := typedStore(t)
	m := scopedAgent(nil, nil)
	r := readerFor(t, root, m)

	out, err := r.Perform(agent.NewSession(m, nil))(context.Background(),
		agent.Action{Op: "list_pages"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"index", "pen", "returns"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q is missing from an unscoped listing:\n%s", want, out)
		}
	}
}

// A store with no schema at all is not a store where everything is forbidden.
func TestNoSchemaMeansNothingIsTyped(t *testing.T) {
	if w == nil {
		w = out.New(false)
		t.Cleanup(func() { w = nil })
	}
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home"}}, "first", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}

	m := scopedAgent([]string{"product"}, nil)
	r := readerFor(t, root, m)
	got, err := r.Perform(agent.NewSession(m, nil))(context.Background(),
		agent.Action{Op: "list_pages"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "index") {
		t.Errorf("a store with no schema hid its pages:\n%s", got)
	}
}

// Every construction of agentexec.Reader must set both resolvers.
//
// The tests above prove the resolvers work. This one proves they are used,
// which is the half that was actually broken: `agent run` built the Reader
// with both fields left nil, and Reader documents a nil resolver as "nothing
// is typed" — so the manifest's scope quietly became unrestricted, and every
// screen that displayed the manifest displayed a restriction nothing applied.
//
// Walked from the source rather than asserted through a run, because the
// failure is a field somebody did not write. A behavioural test can only
// catch it where it already knows to look, and the next Reader will be built
// somewhere this test has not heard of.
func TestEveryReaderIsBuiltWithItsScopeResolvers(t *testing.T) {
	built := 0
	for _, file := range goFilesUnder(t, "..") {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, src, 0)
		if err != nil {
			// Not this test's business to police syntax.
			continue
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Reader" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "agentexec" {
				return true
			}
			built++
			set := map[string]bool{}
			for _, e := range lit.Elts {
				if kv, ok := e.(*ast.KeyValueExpr); ok {
					if k, ok := kv.Key.(*ast.Ident); ok {
						set[k.Name] = true
					}
				}
			}
			// A Reader in a test may leave them out: a store with no schema
			// and no locales is the case those tests are about.
			if strings.HasSuffix(file, "_test.go") {
				return true
			}
			for _, field := range []string{"Types", "Locale"} {
				if !set[field] {
					t.Errorf("%s:%d builds an agentexec.Reader without %s, "+
						"so the manifest's scope is decoration there",
						file, fset.Position(lit.Pos()).Line, field)
				}
			}
			return true
		})
	}
	if built == 0 {
		t.Fatal("found no agentexec.Reader anywhere; the walk is wrong and a " +
			"test that sees nothing passes")
	}
}

// goFilesUnder lists the Go files in the tree, so a walk covers what is added
// later and not only what existed when it was written.
func goFilesUnder(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
