// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The help text and the program agree about what the program can do.
//
// usage() says why it is written the way it is: "`--help` is how an agent
// discovers a CLI… Half a help page is a schema with holes in it." It had
// holes. Three entries named subcommands that do not exist — `anchor list`,
// `anchor verify` and `timestamp verify` — and around twenty working
// subcommands were not in it at all.
//
// A wrong entry is the worse of the two. A missing one costs somebody a
// search; a wrong one sends them, or an agent reading the help as a schema,
// to run a command that fails. For a project whose argument is that the
// documented behaviour and the real behaviour are the same thing, help that
// names a command the binary does not have is the worst-shaped bug available.
//
// So the help is checked against the dispatch rather than proof-read. Both
// halves are read out of the source: the top-level switch in main.go for the
// commands, and each command's own switch for its subcommands.
func TestTheHelpTextAndTheProgramAgree(t *testing.T) {
	claimed := helpClaims(t)
	real := realSubcommands(t)
	dispatched := map[string]bool{}
	for _, c := range dispatchedCommands(t) {
		dispatched[c] = true
	}

	if len(claimed) < 20 || len(real) < 20 {
		t.Fatalf("parsed %d help entries against %d commands; the parse is "+
			"wrong and a test that compares nothing passes", len(claimed), len(real))
	}

	// Every command the help names must be dispatched.
	// Against every case in the switch, not only the ones that call a cmdX
	// function: `version` and `help` are answered inline and are real.
	var ghosts []string
	for cmd := range claimed {
		if !dispatched[cmd] {
			ghosts = append(ghosts, cmd)
		}
	}
	sort.Strings(ghosts)
	for _, c := range ghosts {
		t.Errorf("the help names `quilzo %s` and nothing dispatches it", c)
	}

	// Every subcommand the help names must exist.
	var wrong []string
	for cmd, subs := range claimed {
		groups, ok := real[cmd]
		if !ok || len(groups) == 0 {
			continue // no subcommand switch to check against
		}
		for _, s := range subs {
			if !inAnyGroup(groups, s) {
				wrong = append(wrong, "quilzo "+cmd+" "+s)
			}
		}
	}
	sort.Strings(wrong)
	for _, w := range wrong {
		t.Errorf("the help says `%s` and the code has no such subcommand, so "+
			"anybody following the help runs a command that fails", w)
	}

	// And every subcommand that exists must be in the help — once per
	// behaviour, not once per spelling.
	//
	// `case "remove", "rm":` is one thing you can do with two names for it, so
	// naming either in the help is enough. Requiring both would widen the help
	// to say the same thing twice, and an exemption list of every synonym
	// would be a list nobody maintains. Reading the case clause is what makes
	// the distinction, rather than guessing from the spelling.
	var missing []string
	for cmd, groups := range real {
		subs, ok := claimed[cmd]
		if !ok {
			continue // the command's absence is caught by the test below
		}
		named := map[string]bool{}
		for _, s := range subs {
			named[s] = true
		}
		for _, g := range groups {
			documented := false
			for _, spelling := range g {
				if named[spelling] {
					documented = true
					break
				}
			}
			if !documented {
				missing = append(missing, cmd+" "+strings.Join(g, "|"))
			}
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("`quilzo %s` works and the help does not mention it under "+
			"any of its names. Half a help page is a schema with holes in "+
			"it", m)
	}
}

// inAnyGroup reports whether sub is one of the spellings the code accepts.
func inAnyGroup(groups [][]string, sub string) bool {
	for _, g := range groups {
		for _, s := range g {
			if s == sub {
				return true
			}
		}
	}
	return false
}

// Every top-level command is in the help.
//
// Separate from the subcommand check because a command missing entirely is a
// different failure from a command whose subcommands drifted: the first means
// a whole capability is undiscoverable.
func TestEveryCommandIsInTheHelp(t *testing.T) {
	help := helpText(t)
	var missing []string
	for _, c := range dispatchedCommands(t) {
		if strings.HasPrefix(c, "__") {
			continue // internal re-exec, not a command anybody types
		}
		if notInHelp[c] {
			continue
		}
		if !regexp.MustCompile(`(?m)^\s+quilzo ` + regexp.QuoteMeta(c) + `\b`).
			MatchString(help) {
			missing = append(missing, c)
		}
	}
	sort.Strings(missing)
	for _, c := range missing {
		t.Errorf("`quilzo %s` is dispatched and the help never names it", c)
	}
}

// notInHelp is for commands deliberately absent from the help, with a reason.
var notInHelp = map[string]bool{
	// Aliases. The command is in the help under its primary spelling.
	"prov": true, "locales": true, "integration": true, "webhooks": true,
	"forms": true, "listings": true, "taxonomy": true, "menus": true,
	"locks": true, "stamp": true, "help": true, "-h": true, "notes": true,
	"environments": true, "extensions": true, "record": true,
	"sections": true, "templates": true, "types": true,
}

// Every command the program tells somebody to run is one it has.
//
// The help is not the only place a command is named. An error says "try
// this", a hint after a result says what to run next, and a screen in the
// console shows the command that does the same from a terminal. Each of
// those is a promise, and the help test never reads them: a hint naming a
// command that was renamed, or never existed in this program, survives every
// other test and fails the one person who follows it.
//
// So every string in the program and every page of the console is read for
// `quilzo WORD`, and WORD must be a command main.go dispatches. Comments are
// not read; they explain the code to whoever is changing it.
func TestEveryCommandTheProgramNamesExists(t *testing.T) {
	dispatched := map[string]bool{}
	for _, c := range dispatchedCommands(t) {
		dispatched[c] = true
	}
	for c := range notInHelp {
		if !dispatched[c] {
			t.Errorf("notInHelp excuses `quilzo %s`, which is not a command", c)
		}
	}

	// A word followed by a colon is a message's prefix ("quilzo box: needs
	// Linux"), not a command somebody is told to run.
	named := regexp.MustCompile("(?:^|[\\s\"'`(>])quilzo ([a-z][a-z0-9-]*)([^a-z0-9-]|$)")
	found := map[string][]string{}
	note := func(where, text string) {
		for _, m := range named.FindAllStringSubmatch(text, -1) {
			if m[2] == ":" || notCommands[m[1]] {
				continue
			}
			found[m[1]] = append(found[m[1]], where)
		}
	}
	for _, top := range []string{".", "../../internal"} {
		err := filepath.WalkDir(top, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")
			switch {
			case strings.HasSuffix(path, "_test.go"):
			case strings.HasSuffix(path, ".go"):
				f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
				if err != nil {
					return err
				}
				ast.Inspect(f, func(n ast.Node) bool {
					if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						note(rel, lit.Value)
					}
					return true
				})
			case strings.HasSuffix(path, ".html"):
				body, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				note(rel, string(body))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(found) < 20 {
		t.Fatalf("found %d commands named in the program; the scan is wrong "+
			"and a test that reads nothing passes", len(found))
	}
	words := make([]string, 0, len(found))
	for w := range found {
		words = append(words, w)
	}
	sort.Strings(words)
	for _, w := range words {
		if !dispatched[w] {
			t.Errorf("%s tells somebody to run `quilzo %s`, and there is no "+
				"such command", strings.Join(found[w], ", "), w)
		}
	}
}

// notCommands are "quilzo WORD" in the program's text that are not a
// command somebody is told to run, each with why.
var notCommands = map[string]bool{
	// The realm of the sandbox's proxy, which a program's HTTP client shows.
	"run": true,
	// A domain separator inside a hash, never shown to anybody.
	"handoff": true,
	// The comment at the top of the service worker the public site serves.
	"service": true,
}

// helpText returns the usage string as the program prints it.
func helpText(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(".", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	// The raw literal, read from the source rather than by capturing stdout:
	// the point is to check the text somebody edits.
	const open = "fmt.Print(`"
	i := strings.Index(string(src), open)
	if i < 0 {
		t.Fatal("usage() no longer prints a raw string literal")
	}
	rest := string(src)[i+len(open):]
	end := strings.Index(rest, "`)")
	if end < 0 {
		t.Fatal("the usage literal is not closed")
	}
	return rest[:end]
}

// helpClaims reads what the help says each command can do.
//
// A line looks like
//
//	quilzo anchor status | submit | upgrade    one hash over a publication
//
// and the alternatives before the description are the subcommands it claims.
//
// # Why this is not a split on "|"
//
// The help uses a pipe for two different things:
//
//	quilzo siem ocsf|cef|jsonl --envelope F    three subcommands
//	quilzo section move PAGE N up|down         one subcommand, two argument values
//
// What separates them is position, not spacing. A spaced pipe separates whole
// alternatives; an unspaced run of pipes is a set of values, and it names
// subcommands only when it sits in the first position — where a subcommand
// goes — rather than after one, where an argument goes.
//
// So: bracketed spans are dropped first, because a pipe inside them is always
// an argument ("--ref draft|live"). The rest splits on the spaced pipe, and
// each alternative is read from its first field only: a run of pipes there
// expands, a plain lowercase word is taken as-is, and anything else is the
// bare command with its arguments and is skipped.
//
// Being lenient in the wrong direction is what matters here. A parser that
// reads "down" as a subcommand reports a failure that is not there, and a test
// somebody has learned to ignore is worse than no test.
func helpClaims(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	line := regexp.MustCompile(`(?m)^\s+quilzo (\S+)([^\n]*)$`)
	bracketed := regexp.MustCompile(`\[[^\]]*\]`)
	description := regexp.MustCompile(`\s{2,}`)
	word := regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	for _, m := range line.FindAllStringSubmatch(helpText(t), -1) {
		cmd, rest := m[1], m[2]
		if i := description.FindStringIndex(rest); i != nil {
			rest = rest[:i[0]]
		}
		rest = bracketed.ReplaceAllString(rest, " ")

		subs := out[cmd]
		for _, alt := range strings.Split(rest, " | ") {
			fields := strings.Fields(alt)
			if len(fields) == 0 {
				continue
			}
			for _, w := range strings.Split(fields[0], "|") {
				if word.MatchString(w) {
					subs = append(subs, w)
				}
			}
		}
		out[cmd] = subs
	}
	return out
}

// realSubcommands reads each command's own switch.
//
// main.go maps a command name to the function that runs it; that function
// switches on args[0]. Read from the syntax tree rather than by grepping for
// `case`, because every command file is full of other switches.
func realSubcommands(t *testing.T) map[string][][]string {
	t.Helper()
	fset := token.NewFileSet()
	pkg := map[string]*ast.File{}
	files, err := filepath.Glob(filepath.Join(".", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		parsed, perr := parser.ParseFile(fset, f, nil, 0)
		if perr != nil {
			t.Fatal(perr)
		}
		pkg[f] = parsed
	}

	handler := commandHandlers(t, pkg)
	out := map[string][][]string{}
	for cmd, fn := range handler {
		for _, f := range pkg {
			decl := findFunc(f, fn)
			if decl == nil {
				continue
			}
			out[cmd] = append(out[cmd], casesOnArgs(decl)...)
		}
	}
	return out
}

// commandHandlers maps each dispatched command to the function that runs it.
func commandHandlers(t *testing.T, pkg map[string]*ast.File) map[string]string {
	t.Helper()
	main := pkg[filepath.Join(".", "main.go")]
	if main == nil {
		t.Fatal("main.go did not parse")
	}
	out := map[string]string{}
	ast.Inspect(main, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
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
			fn := calledFunc(cl.Body)
			if fn == "" {
				continue
			}
			for _, expr := range cl.List {
				lit, ok := expr.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				out[strings.Trim(lit.Value, `"`)] = fn
			}
		}
		return true
	})
	return out
}

// calledFunc returns the name of the first cmdX function a case body calls.
func calledFunc(body []ast.Stmt) string {
	var name string
	for _, stmt := range body {
		ast.Inspect(stmt, func(n ast.Node) bool {
			if name != "" {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || !strings.HasPrefix(id.Name, "cmd") {
				return true
			}
			name = id.Name
			return false
		})
	}
	return name
}

func findFunc(f *ast.File, name string) *ast.FuncDecl {
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name &&
			fn.Recv == nil {
			return fn
		}
	}
	return nil
}

// casesOnArgs collects the cases of a switch over args[0], one entry per case
// clause so that `case "remove", "rm":` stays a single thing with two names.
func casesOnArgs(fn *ast.FuncDecl) [][]string {
	var out [][]string
	ast.Inspect(fn, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		if !switchesOnArgsZero(sw.Tag) {
			return true
		}
		for _, stmt := range sw.Body.List {
			cl, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			var group []string
			for _, expr := range cl.List {
				if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					group = append(group, strings.Trim(lit.Value, `"`))
				}
			}
			if len(group) > 0 {
				out = append(out, group)
			}
		}
		return true
	})
	return out
}

// switchesOnArgsZero reports whether a switch tag is args[0] or sub, the two
// shapes the command files use.
func switchesOnArgsZero(tag ast.Expr) bool {
	switch e := tag.(type) {
	case *ast.IndexExpr:
		id, ok := e.X.(*ast.Ident)
		if !ok || id.Name != "args" {
			return false
		}
		lit, ok := e.Index.(*ast.BasicLit)
		return ok && lit.Value == "0"
	case *ast.Ident:
		return e.Name == "sub"
	}
	return false
}
