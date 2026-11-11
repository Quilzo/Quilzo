// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/out"
)

// Every listing answers --json with one JSON document, and nothing else.
//
// --json is global so that a caller scripting this "should not have to
// remember which subcommands happen to support it", and internal/out says the
// JSON is a contract. Nineteen commands ignored it and printed their prose,
// so a script that asked for the tokens, the grants or the version got a
// sentence to parse — which is the failure that package exists to prevent.
//
// Those nineteen were a list written by hand, and the commands nobody wrote
// into it went on breaking the contract: `cell status` and `desktop status`
// printed their prose, and `gateway status`, `geo status` and `note list`
// printed nothing at all and exited 0, so a script asking for the notes was
// told there were none by an empty output. `config list` and `config show`
// did the same, because a setting holds a function JSON cannot write, and
// thirteen lists answered null when they had nothing in them. So every read
// the help names — each `status`, `list`, `show` and `check` — is asked, in
// a fresh store and in the demo, and a command added to the help is asked
// without anybody adding it here. A read that cannot run there (a `show`
// with no NAME, a review with no draft) fails, says why on stderr, and
// writes nothing to stdout; one that succeeds writes one document, and a
// list with nothing in it is [], not null, whether it is the answer or the
// list inside it: `board list`, `menu list` and a dozen more answered
// {"boards": null} once the bare lists were []. `agent check` and `fleet
// check` were the same defect under another verb, the one printing its
// verdicts and the other nothing. The commands after that are the reads the
// help words otherwise.
//
// The real command line, in a process of its own, because most of these
// write to the process's standard output rather than to a writer a test can
// swap.
func TestEveryListingAnswersInJSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("QUILZO_TOKEN", "")
	old := w
	t.Cleanup(func() { w = old })
	w = out.New(false)
	fresh, root, tpl := t.TempDir()+"/fresh", t.TempDir()+"/st", t.TempDir()+"/tpl"
	if err := cmdInit(fresh); err != nil {
		t.Fatal(err)
	}
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdDemo(root, []string{"-publish=false", "-templates", tpl}); err != nil {
		t.Fatal(err)
	}
	bookings := t.TempDir() + "/bookings.json"
	body, _ := json.Marshal(bookingExample())
	if err := os.WriteFile(bookings, body, 0o600); err != nil {
		t.Fatal(err)
	}

	reads := readCommands(t)
	if len(reads) < 60 {
		t.Fatalf("only %d reads in the help; it was not read", len(reads))
	}
	for _, store := range []struct{ name, root string }{{"a fresh store", fresh}, {"the demo", root}} {
		for _, c := range reads {
			t.Run(store.name+"/"+strings.Join(c, " "), func(t *testing.T) {
				answersInJSON(t, home, store.root, c, false)
			})
		}
	}
	for _, c := range [][]string{
		{"agent", "templates"}, {"audit", tpl}, {"auth", "roles"},
		{"diff"}, {"log"}, {"rights"}, {"version"},
		// These three printed their prose under --json too: a sweep for
		// tokens nobody uses, the operations the agent interface offers,
		// and a research report checked before it goes out.
		{"token", "stale"}, {"mcp", "--list"}, {"research", "check", "repeat-orders"},
		// These three printed their prose under --json. A site that takes no
		// bookings yet, one being set up and one that does, in that order,
		// because each is a different branch; and an explanation both of
		// everything a principal may do and of one action, refused.
		{"auth", "explain", "ada"}, {"auth", "explain", "ada", "publish"}, {"saml", "presets"},
		{"booking", "setup"}, {"booking", "setup", bookings}, {"booking", "setup"},
	} {
		t.Run(strings.Join(c, " "), func(t *testing.T) {
			answersInJSON(t, home, root, c, true)
		})
	}
}

// answersInJSON runs `quilzo ARGS --json` on a store and holds its stdout to
// the contract: one document, or — for a command that failed, when always is
// false — nothing at all, its error being on stderr.
func answersInJSON(t *testing.T, home, root string, c []string, always bool) {
	t.Helper()
	name := strings.Join(c, " ")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := append([]string{"quilzo-main", "--root", root}, c...)
	cmd := exec.CommandContext(ctx, os.Args[0], append(args, "--json")...)
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "HOME="+home, "QUILZO_TOKEN=")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run() // a refusal still exits non-zero; stdout is the question
	if ctx.Err() != nil {
		t.Fatalf("`quilzo %s --json` did not finish", name)
	}
	if err != nil && !always && strings.TrimSpace(stdout.String()) == "" {
		return
	}
	dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	var doc any
	if derr := dec.Decode(&doc); derr != nil {
		t.Fatalf("`quilzo %s --json` did not answer in JSON (exit: %v): %v\nstdout: %s\nstderr: %s",
			name, err, derr, firstLines(stdout.String(), 4), firstLines(stderr.String(), 4))
	}
	if _, err := dec.Token(); err != io.EOF {
		t.Errorf("`quilzo %s --json` wrote more than one document: %s", name, stdout.String())
	}
	if strings.Contains(stdout.String(), "\x1b[") {
		t.Errorf("`quilzo %s --json` wrote escape codes", name)
	}
	if c[len(c)-1] == "list" && doc == nil {
		t.Errorf("`quilzo %s --json` answered null; a list with nothing in it is []", name)
	}
	if fields, ok := doc.(map[string]any); ok && c[len(c)-1] == "list" {
		for k, v := range fields {
			if v == nil {
				t.Errorf("`quilzo %s --json` answered %q: null; a list with nothing in it is [] there too", name, k)
			}
		}
	}
}

// readCommands is every read the help names: each command's `status`,
// `list`, `show` and `check`, read from the help text by helpClaims.
func readCommands(t *testing.T) [][]string {
	t.Helper()
	var reads [][]string
	for cmd, subs := range helpClaims(t) {
		seen := map[string]bool{}
		for _, s := range subs {
			if (s == "status" || s == "list" || s == "show" || s == "check") && !seen[s] {
				seen[s] = true
				reads = append(reads, []string{cmd, s})
			}
		}
	}
	sort.Slice(reads, func(i, j int) bool {
		return strings.Join(reads[i], " ") < strings.Join(reads[j], " ")
	})
	return reads
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// No read answers a person and then reports success with nothing for --json.
//
// w.Human writes nothing under --json, which is what lets a command call it
// without a mode check on every line. The cost is a branch that only calls
// it: it returns nil, the process exits 0, and stdout is empty. `note list`
// on a store with no notes did that, and so did `gateway status` with no
// gateway and `geo status` always. fmt.Print is worse, because it writes the
// prose whatever was asked for: `cell status` and `desktop status` answered
// a script with sentences.
//
// The test above runs every read, but only as far as a store reaches with no
// arguments, and `inbox show ID` or `eval show AGENT` for an agent never
// evaluated is a branch it cannot get to. So this reads the source: for
// every read the help names, the case that answers it and every function
// that case calls, and on every path to a `return nil`, something written
// for a person with no JSON written before it is a failure.
//
// The path is read leniently. A JSON write anywhere earlier on the path
// counts, even inside a branch not taken, because a test that fails on code
// that is right is a test somebody learns to ignore.
//
// Writes, like `webhook add`, are not read here: many confirm only in prose,
// and whether each must answer --json too is a decision of its own.
func TestNoHumanOnlyBranchReturnsSuccessUnderJSON(t *testing.T) {
	// Each exception is a function, with why it is right as it is. One that
	// no longer needs it is a failure too, so the list does not outlive its
	// reasons.
	exceptions := map[string]string{
		"agentShow": "it prints the manifest itself, marshalled: one JSON document whichever mode is asked for",
	}

	fset := token.NewFileSet()
	pkg := map[string]*ast.File{}
	files, err := filepath.Glob(filepath.Join(".", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	funcs := map[string]*ast.FuncDecl{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		parsed, perr := parser.ParseFile(fset, f, nil, 0)
		if perr != nil {
			t.Fatal(perr)
		}
		pkg[f] = parsed
		for _, d := range parsed.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Body != nil {
				funcs[fn.Name.Name] = fn
			}
		}
	}
	l := newBranchLint(fset, funcs)
	handler := commandHandlers(t, pkg)

	// The reading itself, on a branch of each kind and one that is right, so
	// a lint that has stopped seeing anything fails rather than passes.
	probe, err := parser.ParseFile(fset, "probe.go", `package main
func silent() error { if x { w.Human("none\n"); return nil }; if w.JSON(1) { return nil }; return nil }
func prose() error { fmt.Println("none"); return nil }
func right() error { if w.JSON(1) { return nil }; w.Human("one\n"); return nil }`, 0)
	if err != nil {
		t.Fatal(err)
	}
	var probed []string
	for _, d := range probe.Decls {
		fn := d.(*ast.FuncDecl)
		for _, h := range l.walk(fn.Name.Name, fn.Body.List, pathState{}) {
			probed = append(probed, h.fn)
		}
	}
	if strings.Join(probed, " ") != "silent prose" {
		t.Fatalf("the lint found %v in the probe, not [silent prose]; it does not read paths", probed)
	}

	used := map[string]bool{}
	reads := readCommands(t)
	if len(reads) < 60 {
		t.Fatalf("only %d reads in the help; it was not read", len(reads))
	}
	for _, c := range reads {
		fn := funcs[handler[c[0]]]
		if fn == nil {
			t.Errorf("`quilzo %s` is in the help and main.go does not dispatch it", c[0])
			continue
		}
		answer := answeringCase(fn, c[1], funcs)
		if answer == nil {
			t.Errorf("cannot find where `quilzo %s` is answered: not a case in %s or what it calls",
				strings.Join(c, " "), fn.Name.Name)
			continue
		}
		hits := l.walk(fn.Name.Name, answer, pathState{})
		for _, callee := range directCallees(answer, funcs) {
			hits = append(hits, l.walk(callee.Name.Name, callee.Body.List, pathState{})...)
		}
		for _, h := range hits {
			if _, ok := exceptions[h.fn]; ok {
				used[h.fn] = true
				continue
			}
			t.Errorf("%s: `quilzo %s` returns success in %s after %s",
				h.pos, strings.Join(c, " "), h.fn, h.what)
		}
	}
	for fn, why := range exceptions {
		if !used[fn] {
			t.Errorf("%s is excepted (%s) and has no branch that needs it", fn, why)
		}
	}
}

// answeringCase is the body that answers SUB: its case in the handler's
// switch on its subcommand, or in a function the handler hands its arguments
// to, as `newsletter` does; or the whole handler, when nothing switches on a
// subcommand because main.go called it for this read alone, as it does
// `logd status`.
func answeringCase(fn *ast.FuncDecl, sub string, funcs map[string]*ast.FuncDecl) []ast.Stmt {
	body, switches := caseIn(fn, sub)
	if body != nil {
		return body
	}
	for _, c := range directCallees(fn.Body.List, funcs) {
		if c == fn {
			continue
		}
		b, sw := caseIn(c, sub)
		if b != nil {
			return b
		}
		switches = switches || sw
	}
	if !switches {
		return fn.Body.List
	}
	return nil
}

// caseIn is the body of the case labelled SUB in a switch on the
// subcommand, and whether the function switches on its subcommand at all.
func caseIn(fn *ast.FuncDecl, sub string) ([]ast.Stmt, bool) {
	var body []ast.Stmt
	switches := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok || body != nil || !switchesOnArgsZero(sw.Tag) {
			return body == nil
		}
		switches = true
		for _, stmt := range sw.Body.List {
			cl := stmt.(*ast.CaseClause)
			for _, e := range cl.List {
				if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.Trim(lit.Value, `"`) == sub {
					body = cl.Body
				}
			}
		}
		return body == nil
	})
	return body, switches
}

// branchLint finds the paths to `return nil` that wrote for a person and
// wrote no JSON.
type branchLint struct {
	fset *token.FileSet
	// writesJSON and writesProse are the package's functions that write the
	// document, or prose to stdout, themselves or through what they call; a
	// call to one counts as what it writes.
	writesJSON, writesProse map[string]bool
}

type pathState struct {
	human, printed, json bool
}

type branchHit struct {
	fn, pos, what string
}

func newBranchLint(fset *token.FileSet, funcs map[string]*ast.FuncDecl) *branchLint {
	l := &branchLint{fset: fset, writesJSON: map[string]bool{}, writesProse: map[string]bool{}}
	for changed := true; changed; {
		changed = false
		for name, fn := range funcs {
			if !l.writesJSON[name] && l.has(fn.Body, l.isJSON) {
				l.writesJSON[name], changed = true, true
			}
			if !l.writesProse[name] && l.has(fn.Body, func(n ast.Node) bool { return l.isHuman(n) || l.isPrint(n) }) {
				l.writesProse[name], changed = true, true
			}
		}
	}
	return l
}

// has reports whether a node holds one that matches, leaving out function
// literals: what a closure writes is written when it is called, not where it
// is made.
func (l *branchLint) has(n ast.Node, match func(ast.Node) bool) bool {
	found := false
	ast.Inspect(n, func(m ast.Node) bool {
		if found || m == nil {
			return false
		}
		if _, ok := m.(*ast.FuncLit); ok {
			return false
		}
		found = match(m)
		return !found
	})
	return found
}

func selectorIs(n ast.Node, x, sel string) bool {
	s, ok := n.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := s.X.(*ast.Ident)
	return ok && id.Name == x && s.Sel.Name == sel
}

// isJSON is a JSON write or a look at the mode: `if w.Mode == out.JSON`
// is a command answering --json its own way.
func (l *branchLint) isJSON(n ast.Node) bool {
	if selectorIs(n, "w", "JSON") || selectorIs(n, "out", "JSON") {
		return true
	}
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	return ok && l.writesJSON[id.Name]
}

func (l *branchLint) isHuman(n ast.Node) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return false
	}
	if selectorIs(call.Fun, "w", "Human") {
		return true
	}
	id, ok := call.Fun.(*ast.Ident)
	return ok && l.writesProse[id.Name] && !l.writesJSON[id.Name]
}

// isPrint is prose written straight to stdout, which --json does not stop.
func (l *branchLint) isPrint(n ast.Node) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return false
	}
	for _, f := range []string{"Print", "Printf", "Println"} {
		if selectorIs(call.Fun, "fmt", f) {
			return true
		}
	}
	for _, f := range []string{"Fprint", "Fprintf", "Fprintln"} {
		if selectorIs(call.Fun, "fmt", f) && len(call.Args) > 0 && selectorIs(call.Args[0], "os", "Stdout") {
			return true
		}
	}
	return false
}

// directCallees are the package's functions a body calls, in the order it
// first calls them.
func directCallees(body []ast.Stmt, funcs map[string]*ast.FuncDecl) []*ast.FuncDecl {
	seen := map[string]bool{}
	var out []*ast.FuncDecl
	for _, s := range body {
		ast.Inspect(s, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && funcs[id.Name] != nil && !seen[id.Name] {
				seen[id.Name] = true
				out = append(out, funcs[id.Name])
			}
			return true
		})
	}
	return out
}

// walk follows the statements in order, carrying what the path has written.
func (l *branchLint) walk(fn string, stmts []ast.Stmt, st pathState) []branchHit {
	var hits []branchHit
	for _, s := range stmts {
		var h []branchHit
		h, st = l.walkStmt(fn, s, st)
		hits = append(hits, h...)
	}
	return hits
}

// seen adds what nodes write to a path.
func (l *branchLint) seen(st pathState, nodes ...ast.Node) pathState {
	for _, n := range nodes {
		st.human = st.human || l.has(n, l.isHuman)
		st.printed = st.printed || l.has(n, l.isPrint)
		st.json = st.json || l.has(n, l.isJSON)
	}
	return st
}

func (l *branchLint) walkStmt(fn string, s ast.Stmt, st pathState) ([]branchHit, pathState) {
	var hits []branchHit
	switch s := s.(type) {
	case *ast.ReturnStmt:
		if len(s.Results) == 1 && !st.json && (st.human || st.printed) {
			if id, ok := s.Results[0].(*ast.Ident); ok && id.Name == "nil" {
				what := "writing only for a person, so --json is answered with nothing"
				if st.printed {
					what = "printing its prose, which --json does not stop"
				}
				hits = append(hits, branchHit{fn, l.fset.Position(s.Pos()).String(), what})
			}
		}
		return hits, st
	case *ast.BlockStmt:
		hits = l.walk(fn, s.List, st)
	case *ast.LabeledStmt:
		return l.walkStmt(fn, s.Stmt, st)
	case *ast.IfStmt:
		in := st
		if s.Init != nil {
			in = l.seen(in, s.Init)
		}
		in = l.seen(in, s.Cond)
		hits = l.walk(fn, s.Body.List, in)
		if s.Else != nil {
			h, _ := l.walkStmt(fn, s.Else, in)
			hits = append(hits, h...)
		}
	case *ast.SwitchStmt:
		in := st
		if s.Init != nil {
			in = l.seen(in, s.Init)
		}
		if s.Tag != nil {
			in = l.seen(in, s.Tag)
		}
		for _, c := range s.Body.List {
			hits = append(hits, l.walk(fn, c.(*ast.CaseClause).Body, in)...)
		}
	case *ast.TypeSwitchStmt:
		for _, c := range s.Body.List {
			hits = append(hits, l.walk(fn, c.(*ast.CaseClause).Body, st)...)
		}
	case *ast.SelectStmt:
		for _, c := range s.Body.List {
			hits = append(hits, l.walk(fn, c.(*ast.CommClause).Body, st)...)
		}
	case *ast.ForStmt:
		hits = l.walk(fn, s.Body.List, st)
	case *ast.RangeStmt:
		hits = l.walk(fn, s.Body.List, st)
	}
	// Whatever the statement wrote, in any of its branches, is on the path
	// after it: lenient, as above.
	return hits, l.seen(st, s)
}
