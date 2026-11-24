// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package plaintext

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
// ways. So this reads the source of every package and refuses the three
// shapes a byte cut takes: a slice with an ellipsis added to it, a helper
// taking text and a length that hands back a slice of the text, and text
// cut to length in place, `if len(s) > n { s = s[:n] }`, which
// refuseInPlaceCuts finds. Each is the copy that splits a character the day
// somebody types one.
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
	refuseInPlaceCuts(t)
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

// refuseInPlaceCuts refuses the third shape, the one that reads as
// obviously right:
//
//	if len(s) > n {
//		s = s[:n]
//	}
//
// It bounds bytes, which is what a store, a provider and a log line limit,
// and on English it is never wrong, which is how thirty-one of them shipped.
// On a visitor's question in Japanese, an error a provider wrote in German,
// or a filename with an accent in it, the cut lands inside a character
// whenever that character is longer than a byte, and what is kept ends in
// bytes that are not text.
//
// The same shape on a slice is right, and far more common, so this
// type-checks the source: a check of the syntax alone would either refuse
// every list cut to length or miss a string field such as in.Purpose. It
// covers the files this platform builds; those built only elsewhere are file
// locks and process plumbing.
func refuseInPlaceCuts(t *testing.T) {
	t.Helper()
	found, packages := inlineClipsIn(t, filepath.Join("..", ".."))
	if packages < 100 {
		t.Fatalf("only %d packages were type-checked; the walk is wrong, and "+
			"a test that inspects nothing passes", packages)
	}
	seen := map[string]bool{}
	for _, c := range found {
		seen[c.key] = true
		if _, ok := notText[c.key]; ok {
			continue
		}
		t.Errorf("%s: %s cuts a string at a byte, which can be inside a "+
			"character.\n    Use plaintext.Clip(%s, %s, \"\"); or, if it can "+
			"only ever hold ASCII, add %q to notText with the reason",
			c.at, c.cut, c.name, c.bound, c.key)
	}
	for key := range notText {
		if !seen[key] {
			t.Errorf("%q is in notText but no longer cuts a string in place; "+
				"take it off, so the list stays one of reasons that are true", key)
		}
	}
}

// notText is every string cut in place that is right as it is, and why.
//
// Each is named by file, function and variable, not line, so an edit nearby
// does not unlist it, and renaming any of the three makes somebody look again.
var notText = map[string]string{
	"internal/tmpl/prose.go findWithin s": "a window to search for a " +
		"marker in, not text anybody reads: every marker is ASCII, so none " +
		"starts inside a character the window cuts, and the index found is " +
		"into the whole string",
	"internal/apiimport/apiimport.go opName n": "reWord has replaced " +
		"everything but A to Z, a to z and 0 to 9",
	"internal/feature/infer.go Infer base": "slug keeps a to z, 0 to 9 and " +
		"hyphens, and the hyphens have become underscores",
	"internal/feature/infer.go Infer listName": `"all_" and base, which is ASCII`,
	"internal/research/literature.go SuggestKey base": "only a to z are " +
		"written into it",
	"internal/agentbox/openshell.go SandboxName n": "reSandboxName has " +
		"replaced everything but a to z, 0 to 9 and hyphens",
	"internal/c2pa/manifest.go shortDigest s": "base64",
	"cmd/quilzo/version.go selfIdentity rev":  "a commit hash, in hexadecimal",
}

// The walk finds the shape on strings, whatever the string is called or
// typed as, and nothing else: not a slice cut the same way, and not a cut
// that is marked, which is a different shape with its own fix.
func TestTheInPlaceCutIsRecognised(t *testing.T) {
	const src = `package p

type name string

type rec struct{ Purpose string }

func f(s string, b []byte, n name, r *rec) {
	if len(s) > 10 {
		s = s[:10]
	}
	if len(b) > 10 {
		b = b[:10]
	}
	if 10 < len(n) {
		n = n[0:10]
	}
	if (len(r.Purpose) >= 300) {
		r.Purpose = (r.Purpose[:300])
	}
	if len(s) > 10 {
		s = s[:10] + "..."
	}
	if len(s) > 10 {
		t := s[:10]
		_ = t
	}
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}
	if _, err := (&types.Config{}).Check("p", fset, []*ast.File{f}, info); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range inlineClips(fset, info, f, "p.go") {
		got = append(got, c.key)
	}
	want := []string{"p.go f s", "p.go f n", "p.go f r.Purpose"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("found %q, want %q", got, want)
	}
}

// inlineClip is one string cut to length in place.
type inlineClip struct {
	key   string // file, function and variable: what notText is keyed by
	at    string // file and line, for the person reading the failure
	name  string // the variable
	bound string // what it is compared with
	cut   string // the slice it is set to
}

// listed is what go list says of one package.
type listed struct {
	ImportPath string
	Dir        string
	Export     string
	GoFiles    []string
	Standard   bool
}

// inlineClipsIn type-checks every package of the module at root and finds
// each string cut in place, with how many packages it looked at.
func inlineClipsIn(t *testing.T, root string) ([]inlineClip, int) {
	t.Helper()
	// Export data for every package from one go list, which is what the
	// build has made already, rather than type-checking the standard
	// library from source for every import: two seconds, not most of a
	// minute.
	cmd := exec.Command("go", "list", "-export", "-deps",
		"-json=ImportPath,Dir,Export,GoFiles,Standard", "./...")
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}
	exports := map[string]string{}
	var ours []listed
	for dec := json.NewDecoder(bytes.NewReader(out)); ; {
		var p listed
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("go list: %v", err)
		}
		exports[p.ImportPath] = p.Export
		if !p.Standard {
			ours = append(ours, p)
		}
	}
	base, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		if exports[path] == "" {
			return nil, fmt.Errorf("go list made no export data for %s", path)
		}
		return os.Open(exports[path])
	})
	var found []inlineClip
	for _, p := range ours {
		var files []*ast.File
		for _, name := range p.GoFiles {
			f, err := parser.ParseFile(fset, filepath.Join(p.Dir, name), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
		info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}
		if _, err := (&types.Config{Importer: imp}).Check(p.ImportPath, fset, files, info); err != nil {
			t.Fatalf("%s: %v", p.ImportPath, err)
		}
		for _, f := range files {
			rel, err := filepath.Rel(base, fset.File(f.Pos()).Name())
			if err != nil {
				t.Fatal(err)
			}
			found = append(found, inlineClips(fset, info, f, filepath.ToSlash(rel))...)
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].at < found[j].at })
	return found, len(ours)
}

// inlineClips finds, in one file, every if guarded by the length of a
// string whose body sets that string to a slice of itself from the start.
func inlineClips(fset *token.FileSet, info *types.Info, f *ast.File, file string) []inlineClip {
	var out []inlineClip
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			ifs, ok := n.(*ast.IfStmt)
			if !ok {
				return true
			}
			x, bound := lengthGuard(ifs.Cond)
			if x == nil || !isString(info, x) {
				return true
			}
			name := types.ExprString(x)
			for _, st := range ifs.Body.List {
				as, ok := st.(*ast.AssignStmt)
				if !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 ||
					types.ExprString(as.Lhs[0]) != name {
					continue
				}
				sl, ok := ast.Unparen(as.Rhs[0]).(*ast.SliceExpr)
				if !ok || sl.High == nil || !fromStart(sl.Low) || types.ExprString(sl.X) != name {
					continue
				}
				out = append(out, inlineClip{
					key:   file + " " + funcName(fn) + " " + name,
					at:    fmt.Sprintf("%s:%d", file, fset.Position(as.Pos()).Line),
					name:  name,
					bound: types.ExprString(bound),
					cut:   types.ExprString(sl),
				})
			}
			return true
		})
	}
	return out
}

// lengthGuard is x and the bound in len(x) > bound or len(x) >= bound,
// either way round, or nil.
func lengthGuard(cond ast.Expr) (x, bound ast.Expr) {
	be, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok {
		return nil, nil
	}
	lenSide, other := be.X, be.Y
	switch be.Op {
	case token.GTR, token.GEQ:
	case token.LSS, token.LEQ:
		lenSide, other = be.Y, be.X
	default:
		return nil, nil
	}
	call, ok := ast.Unparen(lenSide).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return nil, nil
	}
	if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "len" {
		return nil, nil
	}
	return call.Args[0], other
}

// fromStart reports a slice's low bound that is absent or zero.
func fromStart(low ast.Expr) bool {
	if low == nil {
		return true
	}
	lit, ok := low.(*ast.BasicLit)
	return ok && lit.Value == "0"
}

func isString(info *types.Info, e ast.Expr) bool {
	tv, ok := info.Types[e]
	if !ok || tv.Type == nil {
		return false
	}
	b, ok := tv.Type.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsString != 0
}

// funcName is a function's name, with its receiver's type for a method.
func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	return types.ExprString(fn.Recv.List[0].Type) + "." + fn.Name.Name
}
