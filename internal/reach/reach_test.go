// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package reach

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tree writes a small module and returns its directory.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const uses = `package app

import "github.com/acme/archive"

func Open(p string) error {
	_, err := archive.Extract(p)
	return err
}
`

const usesSomethingElse = `package app

import "github.com/acme/archive"

func List(p string) error {
	_, err := archive.List(p)
	return err
}
`

const importsNothing = `package app

func Nothing() {}
`

// TestNotReferencedIsAProof — where the filtering comes from.
func TestNotReferencedIsAProof(t *testing.T) {
	dir := tree(t, map[string]string{"app/a.go": usesSomethingElse})
	r, err := Assess("GHSA-1", "github.com/acme/archive",
		[]Affected{{Path: "github.com/acme/archive",
			Symbols: []string{"Extract"}}}, Source{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != NotReferenced {
		t.Fatalf("verdict = %s, found %v", r.Verdict, r.Found)
	}
	if !r.Verdict.Clears() || !r.Verdict.Settled() {
		t.Fatal("a proof should clear and should count as settled")
	}
	if !strings.Contains(r.Verdict.Why(), "proof rather than an estimate") {
		t.Fatalf("why = %q", r.Verdict.Why())
	}
}

// TestReferencedSaysWhereWithoutClaimingReachable.
func TestReferencedSaysWhereWithoutClaimingReachable(t *testing.T) {
	dir := tree(t, map[string]string{"app/a.go": uses})
	r, err := Assess("GHSA-1", "github.com/acme/archive",
		[]Affected{{Path: "github.com/acme/archive",
			Symbols: []string{"Extract"}}}, Source{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != Referenced {
		t.Fatalf("verdict = %s", r.Verdict)
	}
	if len(r.Found) != 1 ||
		r.Found[0] != "github.com/acme/archive.Extract" {
		t.Fatalf("found = %v", r.Found)
	}
	if len(r.Where) != 1 || !strings.HasSuffix(r.Where[0], "app/a.go") {
		t.Fatalf("where = %v", r.Where)
	}
	if r.Verdict.Clears() {
		t.Fatal("a reference should not clear a finding")
	}
	// And it does not overclaim.
	why := r.Verdict.Why()
	if strings.Contains(why, "is called") ||
		!strings.Contains(why, "does not claim to have followed the calls") {
		t.Fatalf("why = %q", why)
	}
}

// TestUnanalysedIsNotAClearResult — the verdict the package exists for.
func TestUnanalysedIsNotAClearResult(t *testing.T) {
	dir := tree(t, map[string]string{"app/a.go": uses})
	r, err := Assess("CVE-2026-1", "github.com/acme/archive", nil,
		Source{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != Unanalysed {
		t.Fatalf("verdict = %s", r.Verdict)
	}
	if r.Verdict.Clears() {
		t.Fatal("an advisory with no symbol cleared a finding")
	}
	if r.Verdict.Settled() {
		t.Fatal("an advisory with no symbol was counted as settled, which " +
			"is how a filter rate gets manufactured")
	}
	if !strings.Contains(r.Verdict.Why(), "not a clean result") {
		t.Fatalf("why = %q", r.Verdict.Why())
	}
}

func TestNoSourceIsItsOwnAnswer(t *testing.T) {
	r, err := Assess("GHSA-1", "github.com/acme/archive",
		[]Affected{{Path: "github.com/acme/archive",
			Symbols: []string{"Extract"}}}, Source{Dir: ""})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != NoSource || r.Verdict.Settled() {
		t.Fatalf("verdict = %s", r.Verdict)
	}
	// A directory that does not exist is the same answer, not an error.
	r2, err := Assess("GHSA-1", "x",
		[]Affected{{Path: "x", Symbols: []string{"Y"}}},
		Source{Dir: "/no/such/place"})
	if err != nil {
		t.Fatal(err)
	}
	if r2.Verdict != NoSource {
		t.Fatalf("verdict = %s", r2.Verdict)
	}
}

// TestAPackageNamedWithNoSymbolsMeansTheWholePackage.
func TestAPackageNamedWithNoSymbolsMeansTheWholePackage(t *testing.T) {
	dir := tree(t, map[string]string{"app/a.go": usesSomethingElse})
	r, err := Assess("GHSA-1", "github.com/acme/archive",
		[]Affected{{Path: "github.com/acme/archive"}}, Source{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != Referenced {
		t.Fatalf("importing an affected package at all is a reference: %s",
			r.Verdict)
	}
	// And a file importing nothing is still clear.
	clean := tree(t, map[string]string{"app/a.go": importsNothing})
	c, err := Assess("GHSA-1", "github.com/acme/archive",
		[]Affected{{Path: "github.com/acme/archive"}}, Source{Dir: clean})
	if err != nil {
		t.Fatal(err)
	}
	if c.Verdict != NotReferenced {
		t.Fatalf("verdict = %s", c.Verdict)
	}
}

// TestAnAliasedImportIsStillFound.
func TestAnAliasedImportIsStillFound(t *testing.T) {
	dir := tree(t, map[string]string{"app/a.go": `package app

import ar "github.com/acme/archive"

func Open(p string) error { _, err := ar.Extract(p); return err }
`})
	r, err := Assess("GHSA-1", "github.com/acme/archive",
		[]Affected{{Path: "github.com/acme/archive",
			Symbols: []string{"Extract"}}}, Source{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != Referenced {
		t.Fatalf("an aliased import hid the reference: %s", r.Verdict)
	}
}

// TestTestFilesDoNotCountUnlessAsked.
//
// A symbol used only in a test is not reachable in production, and
// counting it turns a clean result into an afternoon.
func TestTestFilesDoNotCountUnlessAsked(t *testing.T) {
	dir := tree(t, map[string]string{
		"app/a.go":      importsNothing,
		"app/a_test.go": uses,
	})
	adv := []Affected{{Path: "github.com/acme/archive",
		Symbols: []string{"Extract"}}}
	r, err := Assess("GHSA-1", "github.com/acme/archive", adv,
		Source{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != NotReferenced {
		t.Fatalf("a test-only use was counted: %s", r.Verdict)
	}
	with, err := Assess("GHSA-1", "github.com/acme/archive", adv,
		Source{Dir: dir, Tests: true})
	if err != nil {
		t.Fatal(err)
	}
	if with.Verdict != Referenced {
		t.Fatalf("asking for tests did not find it: %s", with.Verdict)
	}
}

// TestVendorAndTestdataAreNotThisModulesCode.
func TestVendorAndTestdataAreNotThisModulesCode(t *testing.T) {
	dir := tree(t, map[string]string{
		"app/a.go":            importsNothing,
		"vendor/x/v.go":       uses,
		"app/testdata/fix.go": uses,
	})
	r, err := Assess("GHSA-1", "github.com/acme/archive",
		[]Affected{{Path: "github.com/acme/archive",
			Symbols: []string{"Extract"}}}, Source{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != NotReferenced {
		t.Fatalf("vendored or testdata code was counted: %v", r.Where)
	}
}

// TestTheFilterRateIsReportedTwice — the whole argument.
func TestTheFilterRateIsReportedTwice(t *testing.T) {
	// Ninety-eight cleared out of a hundred, which is the figure a product
	// page would quote — but sixty of them were never assessed.
	var in []Result
	for range 38 {
		in = append(in, Result{Verdict: NotReferenced})
	}
	for range 2 {
		in = append(in, Result{Verdict: Referenced})
	}
	for range 40 {
		in = append(in, Result{Verdict: Unanalysed})
	}
	for range 20 {
		in = append(in, Result{Verdict: NoSource})
	}
	f := Measure(in)
	if f.Total != 100 || f.Silent != 60 || f.Settled != 40 {
		t.Fatalf("%+v", f)
	}
	if f.Cleared != 38 {
		t.Fatalf("cleared = %d", f.Cleared)
	}
	// The claimed rate counts only what cleared, over everything.
	if got := f.Claimed(); got != 0.38 {
		t.Fatalf("claimed = %v", got)
	}
	// The real one is over what was actually established.
	if got := f.Real(); got != 0.95 {
		t.Fatalf("real = %v", got)
	}
	if f.Honest() {
		t.Fatal("a run where sixty percent was silence was called honest")
	}
	why := f.Why()
	for _, want := range []string{"could not be assessed at all",
		"names no symbol", "no source here",
		"Unassessed and cleared look the same"} {
		if !strings.Contains(why, want) {
			t.Fatalf("why does not say %q:\n%s", want, why)
		}
	}

	// A run where everything was assessed says so plainly.
	clean := Measure([]Result{{Verdict: NotReferenced},
		{Verdict: Referenced}})
	if !clean.Honest() {
		t.Fatal("a fully assessed run was called dishonest")
	}
	if !strings.Contains(clean.Why(), "what it looks like") {
		t.Fatalf("why = %q", clean.Why())
	}
	if Measure(nil).Why() != "nothing was assessed" {
		t.Fatalf("empty = %q", Measure(nil).Why())
	}
}

// TestOnlyGoCarriesSymbols, which is why the caveat exists.
func TestOnlyGoCarriesSymbols(t *testing.T) {
	e, ok := Supports("Go")
	if !ok || !e.Symbols {
		t.Fatal("Go does not support symbols?")
	}
	if !strings.Contains(e.Where, "ecosystem_specific") {
		t.Fatalf("where = %q", e.Where)
	}
	supported := 0
	for _, x := range Ecosystems() {
		if x.Symbols {
			supported++
		}
	}
	if supported != 1 {
		t.Fatalf("%d ecosystems carry symbols; the asymmetry is the "+
			"finding", supported)
	}
	if _, ok := Supports("npm"); ok {
		t.Fatal("npm was reported as supporting symbol data")
	}
	if _, ok := Supports("nothing-like-this"); ok {
		t.Fatal("an unknown ecosystem was reported as supported")
	}
}

// TestWorstPutsWhatNeedsLookingAtFirst.
func TestWorstPutsWhatNeedsLookingAtFirst(t *testing.T) {
	got := Worst([]Result{
		{Advisory: "d", Verdict: NotReferenced},
		{Advisory: "c", Verdict: NoSource},
		{Advisory: "b", Verdict: Unanalysed},
		{Advisory: "a", Verdict: Referenced},
	})
	want := []Verdict{Referenced, Unanalysed, NoSource, NotReferenced}
	for i, v := range want {
		if got[i].Verdict != v {
			t.Fatalf("position %d is %s, want %s", i, got[i].Verdict, v)
		}
	}
}

// assess runs one advisory against a tree and fails on error.
func assess(t *testing.T, dir string, syms ...string) Result {
	t.Helper()
	r, err := Assess("GHSA-1", "github.com/acme/archive",
		[]Affected{{Path: "github.com/acme/archive", Symbols: syms}},
		Source{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestAMethodCalledThroughAValueIsFound.
//
// The false proof an earlier version gave. The advisory names Reader.Next;
// the source calls r.Next() on a value a constructor returned. There is no
// archive.Next anywhere, and matching only on the package name said
// NotReferenced about code that calls the vulnerable method.
func TestAMethodCalledThroughAValueIsFound(t *testing.T) {
	dir := tree(t, map[string]string{"app/a.go": `package app

import "github.com/acme/archive"

func Walk(p string) {
	r := archive.NewReader(p)
	r.Next()
}
`})
	r := assess(t, dir, "Reader.Next")
	if r.Verdict != Referenced {
		t.Fatalf("a method call through a value was missed: %s", r.Verdict)
	}
	if len(r.Found) != 1 || r.Found[0] != "github.com/acme/archive.Reader.Next" {
		t.Fatalf("found = %v", r.Found)
	}
}

// TestAMethodCalledInAFileThatDoesNotImportIsFound.
//
// The value crosses a file boundary inside one package, or arrives from a
// dependency that returns the type. The file with the call imports nothing
// affected, so an import filter cannot be what decides.
func TestAMethodCalledInAFileThatDoesNotImportIsFound(t *testing.T) {
	dir := tree(t, map[string]string{
		"app/open.go": `package app

import "github.com/acme/archive"

func open(p string) *archive.Reader { return archive.NewReader(p) }
`,
		"app/walk.go": `package app

func Walk(p string) { open(p).Next() }
`,
	})
	r := assess(t, dir, "Reader.Next")
	if r.Verdict != Referenced {
		t.Fatalf("a method called from another file was missed: %s",
			r.Verdict)
	}
	if len(r.Where) != 1 || !strings.HasSuffix(r.Where[0], "walk.go") {
		t.Fatalf("where = %v, want walk.go", r.Where)
	}
}

// TestMentioningTheTypeIsNotCallingTheMethod — the precision that is kept.
func TestMentioningTheTypeIsNotCallingTheMethod(t *testing.T) {
	dir := tree(t, map[string]string{"app/a.go": `package app

import "github.com/acme/archive"

func Walk(p string) *archive.Reader { return archive.NewReader(p) }
`})
	if r := assess(t, dir, "Reader.Next"); r.Verdict != NotReferenced {
		t.Fatalf("naming the type counted as calling the method: %v", r.Found)
	}
}

// TestADotImportIsStillFound.
func TestADotImportIsStillFound(t *testing.T) {
	dir := tree(t, map[string]string{"app/a.go": `package app

import . "github.com/acme/archive"

func Open(p string) error { _, err := Extract(p); return err }
`})
	r := assess(t, dir, "Extract")
	if r.Verdict != Referenced {
		t.Fatalf("a dot import hid the call: %s", r.Verdict)
	}
	// And a dot import of the package does not make every name a hit.
	if r := assess(t, dir, "List"); r.Verdict != NotReferenced {
		t.Fatalf("a dot import matched a name it does not use: %v", r.Found)
	}
}

// TestAFileThatDoesNotParseIsSearchedNotSkipped.
//
// A syntax error, or syntax newer than this parser, used to be read as
// "no reference here" — a false proof produced by a typo.
func TestAFileThatDoesNotParseIsSearchedNotSkipped(t *testing.T) {
	dir := tree(t, map[string]string{"app/a.go": `package app

import "github.com/acme/archive"

func Open(p string) error {
	_, err := archive.Extract(p)
	return err
` /* missing brace */})
	if r := assess(t, dir, "Extract"); r.Verdict != Referenced {
		t.Fatalf("an unparsable file was skipped: %s", r.Verdict)
	}
	if r := assess(t, dir, "List"); r.Verdict != NotReferenced {
		t.Fatalf("the text search matched a name that is not there: %v",
			r.Found)
	}
}

// TestUnreadableCodeIsAnErrorNotAClearResult.
//
// A directory or a file this cannot open is code nobody looked at. It used
// to be passed over and the verdict came back NotReferenced.
func TestUnreadableCodeIsAnErrorNotAClearResult(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	for _, locked := range []string{"hidden", "unreadable.go"} {
		t.Run(locked, func(t *testing.T) {
			dir := tree(t, map[string]string{
				"app/a.go":      importsNothing,
				"hidden/b.go":   uses,
				"unreadable.go": uses,
			})
			p := filepath.Join(dir, locked)
			if err := os.Chmod(p, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(p, 0o755) })
			r, err := Assess("GHSA-1", "github.com/acme/archive",
				[]Affected{{Path: "github.com/acme/archive",
					Symbols: []string{"Extract"}}}, Source{Dir: dir})
			if err == nil {
				t.Fatalf("unreadable code produced a verdict: %s", r.Verdict)
			}
			if !strings.Contains(err.Error(), "could not be read") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// TestAWholePackageAdvisoryCountsEveryKindOfImport.
func TestAWholePackageAdvisoryCountsEveryKindOfImport(t *testing.T) {
	for _, imp := range []string{
		`import _ "github.com/acme/archive"`,
		`import . "github.com/acme/archive"`,
		`import ar "github.com/acme/archive"`,
	} {
		dir := tree(t, map[string]string{"app/a.go": "package app\n\n" +
			imp + "\n\nvar _ = 1\n"})
		if r := assess(t, dir); r.Verdict != Referenced {
			t.Errorf("%s: %s", imp, r.Verdict)
		}
	}
}
