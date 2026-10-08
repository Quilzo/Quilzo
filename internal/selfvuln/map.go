// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package selfvuln

import (
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Which of this program's features use which standard library packages.
//
// A flaw in a standard library package is only this program's to contain
// by turning a feature off if every file that uses the package belongs to
// that feature: then turning it off is turning the flaw off. A package the
// servers' core uses (net/http, encoding/json) cannot be contained that
// way, and a flaw in it is a person's to act on by upgrading Go.
//
// The map is read from the source at release (Map, run by the generator
// in ./gen) and embedded, because a deployed binary has no source; a test
// fails when the embedded one no longer matches the source.

// Core is a file no single feature owns: what every server runs.
const Core = "*"

// owners are which feature a file serves, first match wins. A file that
// matches none is Core, the conservative answer: a flaw there is told to a
// person and never contained automatically.
var owners = []struct{ pattern, feature string }{
	{"internal/public/searchanswer.go", "search-answers"},
	{"internal/public/ask*.go", "chatbots"},
	{"internal/public/handoff.go", "chatbots"},
	{"internal/public/agent*.go", "chatbots"},
	{"internal/assistant/*", "chatbots"},
	{"internal/handoff/*", "chatbots"},
	{"internal/public/forms.go", "forms"},
	{"internal/form/*", "forms"},
	{"internal/public/share.go", "uploads"},
	{"internal/media/*", "uploads"},
	{"internal/medialib/*", "uploads"},
	{"internal/admin/media*.go", "uploads"},
	{"internal/public/boards.go", "boards"},
	{"internal/board/*", "boards"},
	{"internal/public/members.go", "signup"},
	{"internal/member/*", "signup"},
	{"internal/importer/*", "import"},
	{"internal/admin/transfer.go", "import"},
	{"internal/inbound/*", "feeds"},
	{"internal/ssf/*", "feeds"},
	{"internal/scim/*", "scim"},
	{"internal/api/*", "api"},
	{"internal/mcp/*", "mcp"},
}

// FeatureOf is the feature a file (a path from the module root) serves.
func FeatureOf(file string) string {
	file = filepath.ToSlash(file)
	for _, o := range owners {
		if ok, _ := path.Match(o.pattern, file); ok {
			return o.feature
		}
	}
	return Core
}

// FeatureMap is which features use each standard library package.
type FeatureMap struct {
	Packages map[string][]string `json:"packages"`
}

// Map reads the module's source under root: every non-test file's imports
// of the standard library, by the feature that file serves.
func Map(root string) (FeatureMap, error) {
	m := FeatureMap{Packages: map[string][]string{}}
	seen := map[string]map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if name == ".git" || name == "testdata" || name == "vendor" || name == "node_modules" || (strings.HasPrefix(name, ".") && p != root) {
				return filepath.SkipDir
			}
			if rel, _ := filepath.Rel(root, p); filepath.ToSlash(rel) == "internal/selfvuln/gen" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		feature := FeatureOf(rel)
		for _, im := range f.Imports {
			ip, err := strconv.Unquote(im.Path.Value)
			if err != nil || !standard(ip) {
				continue
			}
			if seen[ip] == nil {
				seen[ip] = map[string]bool{}
			}
			seen[ip][feature] = true
		}
		return nil
	})
	if err != nil {
		return m, err
	}
	for ip, fs := range seen {
		var list []string
		for f := range fs {
			list = append(list, f)
		}
		sort.Strings(list)
		m.Packages[ip] = list
	}
	return m, nil
}

// standard reports an import path of the standard library: no dot in its
// first element.
func standard(ip string) bool {
	first, _, _ := strings.Cut(ip, "/")
	return !strings.Contains(first, ".") && first != "C"
}

// Features are the features that use a package, or Core for one this
// program does not import itself (a package the standard library uses
// inside, which every server reaches).
func (m FeatureMap) Features(pkg string) []string {
	if fs, ok := m.Packages[pkg]; ok {
		return fs
	}
	return []string{Core}
}
