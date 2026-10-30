// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package egress_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/egress"
)

// Every purpose the program uses is declared, and every declared purpose is
// one the program uses.
//
// The gate refuses an undeclared purpose in every mode, so a caller naming
// one has a feature that fails the first time it reaches the network, and a
// test with a stand-in for the far end never notices. A declared purpose
// nothing uses is the opposite mistake: a way off the host that the report
// lists, an operator weighs, and nothing needs.
func TestEveryPurposeIsDeclaredAndUsed(t *testing.T) {
	names := []*regexp.Regexp{
		regexp.MustCompile(`egress\.(?:Client|Dial|Allowed)\(\s*(?:[A-Za-z_.()]+,\s*)?"([a-z-]+)"`),
		regexp.MustCompile(`fetch\.(?:For|Speaking)\(\s*"([a-z-]+)"`),
		regexp.MustCompile(`\.Purpose\s*=\s*"([a-z-]+)"`),
	}
	used := map[string][]string{}
	for _, top := range []string{"../../cmd", "../../internal"} {
		err := filepath.WalkDir(top, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" || filepath.ToSlash(path) == "../../internal/egress" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")
			for _, re := range names {
				for _, m := range re.FindAllStringSubmatch(string(body), -1) {
					used[m[1]] = append(used[m[1]], rel)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(used) == 0 {
		t.Fatal("no use of any purpose was found, so this test reads nothing")
	}

	declared := map[string]bool{}
	for _, p := range egress.Purposes {
		declared[p.Name] = true
	}
	for _, name := range sortedKeys(used) {
		if !declared[name] {
			t.Errorf("%s names the network purpose %q, which is not declared, so the "+
				"connection is refused every time. Declare it in egress.Purposes with "+
				"what it is for and what stops working without it",
				strings.Join(used[name], ", "), name)
		}
	}
	for _, p := range egress.Purposes {
		if used[p.Name] == nil {
			t.Errorf("the network purpose %q is declared and nothing uses it: a way "+
				"off the host that nothing needs. Remove it", p.Name)
		}
	}
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
