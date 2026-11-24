// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package plaintext

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// A cut that lands inside a character goes back to where it starts, and
// the bound stays a bound in bytes.
func TestAClipNeverEndsInHalfACharacter(t *testing.T) {
	for _, c := range []struct {
		s    string
		n    int
		mark string
		want string
	}{
		{"short", 10, "…", "short"},
		{"exactly", 7, "…", "exactly"},
		{"abcdef", 3, "…", "abc…"},
		{"abcdef", 3, "", "abc"},
		{"ab\u00e9cd", 3, "…", "ab…"},                // é is two bytes; the cut fell after the first
		{"ab\u00e9cd", 4, "…", "ab\u00e9…"},          // after the second, so é is whole
		{"a\u20acb", 2, "", "a"},                     // € is three bytes
		{"a\u20acb", 3, "", "a"},                     // and two of them are still half of it
		{"a\u20acb", 4, "", "a\u20ac"},               // all three
		{"a\U0001F600b", 4, "...", "a..."},           // an emoji is four
		{"a\U0001F600b", 5, "...", "a\U0001F600..."}, // and whole at five
		{"\u00e9\u00e9", 1, "…", "…"},                // nothing whole fits
		{"abc", 0, "…", "…"},
		{"abc", -1, "", ""},
		{"", -1, "…", ""},
		{"ab\xffcd", 3, "", "ab\xff"}, // not UTF-8: cut where asked, there is no character to keep
	} {
		got := Clip(c.s, c.n, c.mark)
		if got != c.want {
			t.Errorf("Clip(%q, %d, %q) = %q, want %q", c.s, c.n, c.mark, got, c.want)
		}
		if utf8.ValidString(c.s) && !utf8.ValidString(got) {
			t.Errorf("Clip(%q, %d) = %q, which ends in half a character", c.s, c.n, got)
		}
		if len(got) > max(c.n, 0)+len(c.mark) {
			t.Errorf("Clip(%q, %d) = %q, longer than the bound and the mark", c.s, c.n, got)
		}
	}
	// Every cut of every length of a line in several scripts is whole.
	line := "Quilzo \u00e9t\u00e9 \u65e5\u672c\u8a9e \U0001F600 \u0928\u092e\u0938\u094d\u0924\u0947"
	for n := 0; n <= len(line); n++ {
		if got := Clip(line, n, ""); !utf8.ValidString(got) || !strings.HasPrefix(line, got) || len(got) > n || len(got) < n-3 {
			t.Errorf("Clip at %d = %q", n, got)
		}
	}
}

// No text Quilzo clips ends in half a character, because every clip is
// Clip.
//
// There were about twenty hand-written copies, and most cut at a byte. An
// audit note written by `quilzo schedule add` kept the first byte of an é
// and then "…": U+FFFD in a hash-chained record that is meant to be
// evidence. The copies that were careful were careful in five different
// ways. So this reads the source of every package and refuses the two
// shapes a byte cut takes: a slice with an ellipsis added to it, and a
// helper taking text and a length that hands back a slice of the text.
// Either is the copy that splits a character the day somebody types one.
//
// One copy is left as it is, and named here so it is not forgotten: the
// MCP client's clamp cuts an A2A skill's description, and the description
// is hashed into the definition a person pinned. Making that cut whole
// changes the hash of a long description with a wide character at its
// thousandth byte, and the pinned tool is refused until it is pinned
// again. Whether to re-pin or keep the old bytes is the owner's decision.
func TestNoClippedTextEndsInHalfACharacter(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if strings.HasSuffix(filepath.ToSlash(path), "internal/mcpclient/mcpclient.go") && fn.Name.Name == "clamp" {
				continue
			}
			text := clipParam(fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.BinaryExpr:
					if _, sliced := n.X.(*ast.SliceExpr); sliced && n.Op == token.ADD && ellipsis(n.Y) {
						t.Errorf("%s: a byte cut with an ellipsis after it; use plaintext.Clip", fset.Position(n.Pos()))
					}
				case *ast.ReturnStmt:
					if text == "" || len(n.Results) != 1 {
						return true
					}
					if sl, ok := n.Results[0].(*ast.SliceExpr); ok && sl.Low == nil {
						if id, ok := sl.X.(*ast.Ident); ok && id.Name == text {
							t.Errorf("%s: %s hands back a byte cut of %s; use plaintext.Clip", fset.Position(n.Pos()), fn.Name.Name, text)
						}
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// clipParam is the name of the text a helper shaped like a clip takes,
// func(s string, n int) string, or "" for any other function.
func clipParam(fn *ast.FuncDecl) string {
	ps, rs := fn.Type.Params.List, fn.Type.Results
	if rs == nil || len(rs.List) != 1 || !named(rs.List[0].Type, "string") {
		return ""
	}
	var names, types []string
	for _, p := range ps {
		id, ok := p.Type.(*ast.Ident)
		if !ok {
			return ""
		}
		for _, n := range p.Names {
			names, types = append(names, n.Name), append(types, id.Name)
		}
	}
	if len(names) != 2 || types[0] != "string" || types[1] != "int" {
		return ""
	}
	return names[0]
}

func named(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// ellipsis reports a string literal that says text was cut.
func ellipsis(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	s, err := strconv.Unquote(lit.Value)
	return err == nil && (strings.Contains(s, "…") || strings.HasPrefix(s, "..."))
}
