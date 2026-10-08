// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package reach

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Affected is what an advisory says about one package's symbols.
//
// The shape OSV carries for Go, in ecosystem_specific.imports: a package
// path and the functions or methods in it that are affected. A method is
// written Type.Method, which matters because a source that mentions the
// type and not the method has not referenced the symbol.
type Affected struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols,omitempty"`
}

// Source is a tree of Go files to look in.
type Source struct {
	// Dir is the root. Everything under it is read except vendor and
	// testdata, which are not this module's code.
	Dir string
	// Tests says whether _test.go files count.
	//
	// Off by default and it is a real decision: a symbol used only in a
	// test is not reachable in production, and counting it turns a clean
	// result into a finding somebody spends an afternoon on.
	Tests bool
}

// MaxFiles caps a scan.
//
// A repository with more than this is not a module, it is a monorepo, and
// walking all of it to answer one question would make the check something
// nobody runs.
const MaxFiles = 20_000

// Assess works out what can be said about one advisory against a source
// tree.
//
// imports is what the advisory said. An empty list is not an error and is
// not a clean result — it is Unanalysed, which is the verdict this package
// exists to keep separate from the other kind of nothing.
func Assess(advisory, pkg string, imports []Affected, src Source) (Result,
	error) {

	r := Result{Advisory: advisory, Package: pkg}
	var want []string
	for _, im := range imports {
		for _, s := range im.Symbols {
			want = append(want, im.Path+"."+s)
		}
		if len(im.Symbols) == 0 && im.Path != "" {
			// A package named with no symbols means the whole package is
			// affected. Importing it at all is the reference.
			want = append(want, im.Path)
		}
	}
	sort.Strings(want)
	r.Symbols = want
	if len(want) == 0 {
		r.Verdict = Unanalysed
		return r, nil
	}
	if strings.TrimSpace(src.Dir) == "" {
		r.Verdict = NoSource
		return r, nil
	}
	if fi, err := os.Stat(src.Dir); err != nil || !fi.IsDir() {
		r.Verdict = NoSource
		return r, nil
	}

	found, where, err := look(src, imports)
	if err != nil {
		return r, err
	}
	r.Found, r.Where = found, where
	if len(found) == 0 {
		r.Verdict = NotReferenced
		return r, nil
	}
	r.Verdict = Referenced
	return r, nil
}

// look walks the source for references to any affected symbol.
//
// Every shortcut here errs towards Referenced, because the verdict it
// protects is NotReferenced and that one is trusted to mean no direct call.
// Four places where an earlier version did not:
//
//   - A method. The advisory says Client.Do and the source says c.Do(),
//     where c came from a constructor, a parameter, or another file of the
//     same package that did the importing. No import in this file and no
//     package name on the call. So a method is matched by its name on any
//     selector anywhere in the tree. Without type information that is the
//     only sound reading, and it costs precision on common names like Do
//     and Close — which is the right way round.
//   - A dot import. import . "pkg" makes Bad() a call to pkg.Bad with no
//     selector at all, so bare identifiers count in a file that does it.
//   - A file that does not parse. Skipping it would let a syntax error, or
//     syntax newer than this parser, hide a call. Its text is searched for
//     the names instead.
//   - A directory or file that cannot be read. Nothing can be proved about
//     code nobody looked at, so that is an error and not a clean result.
func look(src Source, imports []Affected) (found, where []string,
	err error) {

	// Functions by package, and methods by their bare name.
	funcs := map[string][]string{}
	methods := map[string][]string{} // "Do" -> ["pkg.Client.Do", ...]
	for _, im := range imports {
		if _, ok := funcs[im.Path]; !ok {
			funcs[im.Path] = nil
		}
		for _, s := range im.Symbols {
			if i := strings.LastIndexByte(s, '.'); i >= 0 {
				methods[s[i+1:]] = append(methods[s[i+1:]], im.Path+"."+s)
				continue
			}
			funcs[im.Path] = append(funcs[im.Path], s)
		}
	}
	whole := func(p string) bool {
		for _, im := range imports {
			if im.Path == p && len(im.Symbols) == 0 {
				return true
			}
		}
		return false
	}
	seen := map[string]bool{}
	files := 0

	walkErr := filepath.WalkDir(src.Dir, func(path string, d fs.DirEntry,
		err error) error {
		if err != nil {
			return fmt.Errorf(
				"%s could not be read (%w). Code nobody looked at cannot be "+
					"shown not to call anything", path, err)
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "testdata", ".git", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if !src.Tests && strings.HasSuffix(path, "_test.go") {
			return nil
		}
		files++
		if files > MaxFiles {
			return fmt.Errorf(
				"more than %d Go files under %s. That is a monorepo rather "+
					"than a module, and walking all of it to answer one "+
					"question makes this a check nobody runs — point it at "+
					"the module", MaxFiles, src.Dir)
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return fmt.Errorf("%s could not be read (%w). Code nobody "+
				"looked at cannot be shown not to call anything", path, rerr)
		}

		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, body, 0)
		if perr != nil {
			// Unparsed is not unreferenced. Search the text for anything
			// the advisory names; a false match costs a look, a missed
			// one is a false proof.
			text := string(body)
			for p, syms := range funcs {
				if whole(p) && strings.Contains(text, p) {
					record(seen, &found, &where, p, path)
				}
				for _, s := range syms {
					if strings.Contains(text, s) {
						record(seen, &found, &where, p+"."+s, path)
					}
				}
			}
			for name, full := range methods {
				if strings.Contains(text, name) {
					for _, sym := range full {
						record(seen, &found, &where, sym, path)
					}
				}
			}
			return nil
		}

		// Which affected packages this file imports, and under what name.
		aliases := map[string]string{}
		var dotted []string
		for _, im := range f.Imports {
			p, uerr := strconv.Unquote(im.Path.Value)
			if uerr != nil {
				continue
			}
			if _, affected := funcs[p]; !affected {
				continue
			}
			name := lastSegment(p)
			if im.Name != nil {
				name = im.Name.Name
			}
			if whole(p) {
				// The whole package is affected, so importing it is the
				// reference — blank, dotted or named. A blank import still
				// runs its init.
				record(seen, &found, &where, p, path)
			}
			switch name {
			case "_":
			case ".":
				dotted = append(dotted, p)
			default:
				aliases[name] = p
			}
		}
		if len(aliases) == 0 && len(dotted) == 0 && len(methods) == 0 {
			return nil
		}

		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SelectorExpr:
				if full, ok := methods[n.Sel.Name]; ok {
					for _, sym := range full {
						record(seen, &found, &where, sym, path)
					}
				}
				id, ok := n.X.(*ast.Ident)
				if !ok {
					return true
				}
				p, ok := aliases[id.Name]
				if !ok {
					return true
				}
				for _, s := range funcs[p] {
					if n.Sel.Name == s {
						record(seen, &found, &where, p+"."+s, path)
					}
				}
			case *ast.Ident:
				for _, p := range dotted {
					for _, s := range funcs[p] {
						if n.Name == s {
							record(seen, &found, &where, p+"."+s, path)
						}
					}
				}
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		return nil, nil, walkErr
	}
	sort.Strings(found)
	sort.Strings(where)
	return found, where, nil
}

func record(seen map[string]bool, found, where *[]string, sym, file string) {
	if !seen["s:"+sym] {
		seen["s:"+sym] = true
		*found = append(*found, sym)
	}
	if !seen["f:"+file] {
		seen["f:"+file] = true
		*where = append(*where, file)
	}
}

func lastSegment(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
