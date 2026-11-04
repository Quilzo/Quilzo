// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Every flag the help lists under a command is one that command takes.
//
// The help listed --api, --api-writable, --base-url and --redirects under
// `quilzo studio`, which records the screen and takes only --addr; they are
// the published site's, `quilzo site`. Somebody following the help got
// "flag provided but not defined", and an agent reading the help as a
// schema had the content API on the wrong command.
//
// A flag is looked for in what the command's handler can reach: the string
// literals of every function it calls, directly or not. That is generous —
// a flag defined anywhere the command might go counts — so a failure here
// is a flag the command cannot possibly take.
func TestEveryFlagTheHelpListsUnderACommandIsOneItTakes(t *testing.T) {
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
	funcs := map[string]*ast.FuncDecl{}
	methods := map[string][]*ast.FuncDecl{}
	for _, f := range pkg {
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Body != nil {
				if fn.Recv == nil {
					funcs[fn.Name.Name] = fn
				} else {
					methods[fn.Name.Name] = append(methods[fn.Name.Name], fn)
				}
			}
		}
	}
	// reachable is every string literal in the code a command's case runs,
	// and in every function that code can reach.
	reachable := func(body []ast.Stmt) map[string]bool {
		lits := map[string]bool{}
		seen := map[*ast.FuncDecl]bool{}
		var queue []*ast.FuncDecl
		visit := func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BasicLit:
				if x.Kind == token.STRING {
					if s, err := strconv.Unquote(x.Value); err == nil {
						lits[s] = true
					}
				}
			case *ast.Ident:
				queue = append(queue, funcs[x.Name])
			case *ast.SelectorExpr:
				queue = append(queue, methods[x.Sel.Name]...)
			}
			return true
		}
		for _, st := range body {
			ast.Inspect(st, visit)
		}
		for len(queue) > 0 {
			fn := queue[0]
			queue = queue[1:]
			if fn == nil || seen[fn] {
				continue
			}
			seen[fn] = true
			ast.Inspect(fn.Body, visit)
		}
		return lits
	}
	cases := commandCases(t, pkg)

	claims := helpFlagClaims(helpText(t))
	if len(claims["site"]) == 0 || len(claims["serve"]) == 0 {
		t.Fatalf("parsed flags for %d commands, and none for site or serve; "+
			"the parse is wrong and a test that compares nothing passes", len(claims))
	}
	var wrong []string
	for cmd, flags := range claims {
		body, ok := cases[cmd]
		if !ok {
			continue // a command nothing dispatches is the other test's
		}
		lits := reachable(body)
		for _, f := range flags {
			name := strings.TrimPrefix(f, "--")
			if !lits[name] && !lits[f] && !lits["-"+name] && !global[name] {
				wrong = append(wrong, "quilzo "+cmd+" "+f)
			}
		}
	}
	sort.Strings(wrong)
	for _, w := range wrong {
		t.Errorf("the help lists `%s` and the command takes no such flag", w)
	}
}

// commandCases maps each command main.go dispatches to the body of its
// case. The body rather than the first function it calls: `quilzo init`
// runs cmdInit and then initAdmin, and --admin is initAdmin's.
func commandCases(t *testing.T, pkg map[string]*ast.File) map[string][]ast.Stmt {
	t.Helper()
	main := pkg[filepath.Join(".", "main.go")]
	if main == nil {
		t.Fatal("main.go did not parse")
	}
	out := map[string][]ast.Stmt{}
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
			for _, expr := range cl.List {
				if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					out[strings.Trim(lit.Value, `"`)] = cl.Body
				}
			}
		}
		return true
	})
	return out
}

// global is what every command takes, read before the command is.
var global = map[string]bool{"root": true, "json": true, "help": true}

// helpFlagClaims reads the long flags the help lists for each command: on
// the command's own line, before its description, and on the indented lines
// under it that begin with a flag. A flag named in a description is prose,
// and is not read.
func helpFlagClaims(help string) map[string][]string {
	out := map[string][]string{}
	entry := regexp.MustCompile(`^  quilzo (\S+)(.*)$`)
	flag := regexp.MustCompile(`--[a-z][a-z0-9-]*`)
	description := regexp.MustCompile(`\s{2,}`)
	syntax := func(s string) string {
		if i := description.FindStringIndex(s); i != nil {
			return s[:i[0]]
		}
		return s
	}
	current := ""
	for _, line := range strings.Split(help, "\n") {
		if m := entry.FindStringSubmatch(line); m != nil {
			current = m[1]
			out[current] = append(out[current], flag.FindAllString(syntax(m[2]), -1)...)
			continue
		}
		trimmed := strings.TrimLeft(line, " ")
		switch {
		case trimmed == "" || len(line)-len(trimmed) < 4:
			// A heading or a blank line ends the entry above.
			current = ""
		case current != "" && strings.HasPrefix(trimmed, "--"):
			out[current] = append(out[current], flag.FindAllString(syntax(trimmed), -1)...)
		}
	}
	return out
}

// `quilzo theme export --tailwind` writes a Tailwind CSS stylesheet, and the
// help did not say so: somebody wanting the site's look in Tailwind had no
// way to learn that it was one flag away.
func TestTheHelpSaysThemeExportCanWriteTailwind(t *testing.T) {
	claims := helpFlagClaims(helpText(t))
	for _, f := range claims["theme"] {
		if f == "--tailwind" {
			return
		}
	}
	t.Errorf("the help lists %v for quilzo theme, and not --tailwind", claims["theme"])
}
