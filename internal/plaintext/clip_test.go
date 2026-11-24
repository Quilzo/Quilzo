// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package plaintext

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/constant"
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
	refuseByteCuts(t)
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

// refuseByteCuts refuses the three shapes on the type-checked source,
// where the syntax alone cannot see them.
//
// The first is the one that reads as obviously right:
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
// The other two are the shapes the walk above refuses by their syntax: a cut
// with an ellipsis after it, and a helper that hands one back. The syntax
// misses a cut that is not the first term of its sum ("said " + s[:n] +
// "…"), and a helper that takes no length, such as a clip300 or a
// clampName: three of those were cutting a provider's refusal, an A2A
// sender's names and a share at the byte after the walk above passed. Here
// a marked cut is a string sliced from the start and joined straight after
// to a constant with "…" or "..." in it, anywhere in a sum, and a returned
// cut is a string returned sliced from the start once its length has been
// compared, inside the comparison that it is longer or after the one that
// returns early when it is not. A cut at an index that was searched for is
// neither, unless it is marked, and a digest's prefix returned with no
// comparison is not a clip.
//
// The same shapes on a slice are right, and far more common, so this
// type-checks the source: a check of the syntax alone would either refuse
// every list cut to length or miss a string field such as in.Purpose. It
// covers the files this platform builds; those built only elsewhere are file
// locks and process plumbing.
func refuseByteCuts(t *testing.T) {
	t.Helper()
	found, packages := byteCutsIn(t, filepath.Join("..", ".."))
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
		t.Errorf("%s: %s", c.at, c.complaint())
	}
	for key := range notText {
		if !seen[key] {
			t.Errorf("%q is in notText but no longer cuts a string at a byte; "+
				"take it off, so the list stays one of reasons that are true", key)
		}
	}
}

// notText is every string cut at a byte that is right as it is, or is held
// as it is on purpose, and why.
//
// Each is named by file, function and variable, not line, so an edit nearby
// does not unlist it, and renaming any of the three makes somebody look again.
//
// Most of what is cut to twelve or sixteen is an identifier this program
// made by writing a digest or random bytes in hexadecimal: a commit, an
// object, a media file, a record, a session, a submission. Each such helper
// is listed with what reaches it.
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

	"cmd/quilzo/agentcmd.go shortCommit s": "a commit id",
	"cmd/quilzo/main.go short oid": "commit and object ids, digests, " +
		"fingerprints, and record, media and submission ids, each hexadecimal",
	"cmd/quilzo/rightscmd.go shortID id": "a media file's id, the digest " +
		"of its bytes",
	"internal/admin/server.go New id": "the templates' short, given " +
		"commits, digests, a timestamp's root, and session and submission ids",
	"internal/admin/types.go shortHash h": "commits, schema and source " +
		"hashes, media ids and pinned SHA-256s",
	"internal/agentexec/write.go shortID s":   "a commit id",
	"internal/collab/collab.go short s":       "a commit id",
	"internal/ext/ext.go short s":             "an extension binary's SHA-256",
	"internal/medialib/edit.go ShortID id":    "a media file's id, the digest of its bytes",
	"internal/posture/rules.go short digest":  "a tool definition's digest",
	"internal/provenance/backfill.go short s": "a commit id",
	"internal/replica/replica.go shortID s":   "a commit or object id",
	"internal/research/report.go short d":     "a file's, a program's or an environment's digest",
	"internal/site/site.go shortID s":         "a commit id",
	"internal/store/cas.go *RefMoved.Error s": "an object id",
	"internal/store/nested.go short s":        "an object id",
	"internal/timestamp/timestamp.go short s": "a publication root, which is a commit id",

	"internal/pii/pii.go Scan local": "the part of an address before the " +
		"@, which reEmail only matches when it is A to Z, a to z, 0 to 9 " +
		"and ._%+-",

	// Not right, and held: what it returns becomes part of a tool's
	// definition, a skill's description among it, and a definition is
	// pinned by its digest. Cutting where a character starts changes the
	// digest of every pinned tool whose description was cut inside one, and
	// each would then be refused as changed until somebody pinned it again.
	// Whether that is worth it is the owner's decision.
	"internal/mcpclient/mcpclient.go clamp s": "held: it feeds the digests " +
		"tool definitions are pinned by",
}

// The walk finds the in-place shape on strings, whatever the string is
// called or typed as, and nothing else: not a slice cut the same way, and
// not a cut that is marked, which is the next shape.
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
	fset, info, f := checked(t, src)
	assertFound(t, inlineClips(fset, info, f, "p.go"), "p.go f s", "p.go f n", "p.go f r.Purpose")
}

// The walk finds a string cut from the start and joined to a mark, guarded
// or not, wherever it sits in the sum, and with the mark named or written
// out. Not a slice, not a cut joined to something that is not a mark, and
// not a cut from somewhere other than the start, which is the end of a
// string and starts where a character does.
func TestTheMarkedCutIsRecognised(t *testing.T) {
	const src = `package p

import "fmt"

const ellipsis = "…"

type rec struct{ Purpose string }

func f(s, u, v, w string, b []byte, r *rec, n int) string {
	if len(s) > 10 {
		s = s[:10] + "…"
	}
	if len(r.Purpose) > 300 {
		r.Purpose = r.Purpose[:297] + "..."
	}
	u = "said: " + u[:n] + ellipsis
	v = v[:n] + "\n…cut at " + fmt.Sprint(n) + " bytes"
	_ = string(b[:10]) + "…"
	_ = w[:4] + "-" + w[4:]
	_ = w[n:] + "…"
	_ = b[:10]
	return w[:n] + ellipsis
}
`
	fset, info, f := checked(t, src)
	assertFound(t, markedClips(fset, info, f, "p.go"),
		"p.go f s", "p.go f r.Purpose", "p.go f u", "p.go f v", "p.go f w")
}

// The walk finds a string returned cut from the start once its length has
// been compared, either way round: inside the comparison that it is longer,
// or after the one that returns early when it is not. Not a cut returned
// with no comparison, which is a digest's prefix or a search's, and not a
// slice.
func TestTheReturnedCutIsRecognised(t *testing.T) {
	const src = `package p

import "strings"

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func backed(s string, n int) string {
	if n >= len(s) {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return (s[0:n])
}

func digest(h string) string { return h[:16] }

func first(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func list(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

func notEarly(s string, n int) string {
	if len(s) <= n {
		s = strings.TrimSpace(s)
	}
	return s[:n]
}
`
	fset, info, f := checked(t, src)
	assertFound(t, returnedClips(fset, info, f, "p.go"), "p.go clip s", "p.go short s", "p.go backed s")
}

// checked is src parsed and type-checked as one file, p.go.
func checked(t *testing.T, src string) (*token.FileSet, *types.Info, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}
	conf := &types.Config{Importer: importer.Default()}
	if _, err := conf.Check("p", fset, []*ast.File{f}, info); err != nil {
		t.Fatal(err)
	}
	return fset, info, f
}

func assertFound(t *testing.T, found []byteCut, want ...string) {
	t.Helper()
	var got []string
	for _, c := range found {
		got = append(got, c.key)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("found %q, want %q", got, want)
	}
}

// shape is which of the three ways a string is cut at a byte.
type shape int

const (
	inPlace  shape = iota // if len(s) > n { s = s[:n] }
	marked                // s[:n] + "…"
	returned              // if len(s) <= n { return s }; return s[:n]
)

// byteCut is one string cut at a byte.
type byteCut struct {
	shape shape
	key   string // file, function and variable: what notText is keyed by
	at    string // file and line, for the person reading the failure
	name  string // the variable
	bound string // what it is compared with, or for a marked cut where it is cut
	cut   string // the slice
	mark  string // what a marked cut is joined to
}

// complaint is what is wrong with c and what to do about it.
func (c byteCut) complaint() string {
	or := fmt.Sprintf("; or, if it can only ever hold ASCII, add %q to "+
		"notText with the reason", c.key)
	switch c.shape {
	case marked:
		return fmt.Sprintf("%s + %s cuts a string at a byte, which can be "+
			"inside a character, and the mark after it does not make what is "+
			"before it text.\n    Use plaintext.Clip(%s, n, %s), with n the "+
			"bound the whole is held to: the mark counts inside it%s",
			c.cut, c.mark, c.name, c.mark, or)
	case returned:
		return fmt.Sprintf("return %s cuts a string at a byte, which can be "+
			"inside a character, for every caller.\n    Use plaintext.Clip(%s, "+
			"%s, \"\"), and if that is all the function does, call it in "+
			"the function's place%s", c.cut, c.name, c.bound, or)
	}
	return fmt.Sprintf("%s cuts a string at a byte, which can be inside a "+
		"character.\n    Use plaintext.Clip(%s, %s, \"\")%s",
		c.cut, c.name, c.bound, or)
}

// listed is what go list says of one package.
type listed struct {
	ImportPath string
	Dir        string
	Export     string
	GoFiles    []string
	Standard   bool
}

// byteCutsIn type-checks every package of the module at root and finds each
// string cut at a byte, in any of the three shapes, with how many packages
// it looked at.
func byteCutsIn(t *testing.T, root string) ([]byteCut, int) {
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
	var found []byteCut
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
			file := filepath.ToSlash(rel)
			found = append(found, inlineClips(fset, info, f, file)...)
			found = append(found, markedClips(fset, info, f, file)...)
			found = append(found, returnedClips(fset, info, f, file)...)
		}
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].at < found[j].at })
	return found, len(ours)
}

// inlineClips finds, in one file, every if guarded by the length of a
// string whose body sets that string to a slice of itself from the start.
func inlineClips(fset *token.FileSet, info *types.Info, f *ast.File, file string) []byteCut {
	var out []byteCut
	eachFunc(f, func(fn *ast.FuncDecl, n ast.Node) {
		ifs, ok := n.(*ast.IfStmt)
		if !ok {
			return
		}
		x, bound := lengthGuard(ifs.Cond)
		if x == nil || !isString(info, x) {
			return
		}
		name := types.ExprString(x)
		for _, st := range ifs.Body.List {
			as, ok := st.(*ast.AssignStmt)
			if !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 ||
				types.ExprString(as.Lhs[0]) != name {
				continue
			}
			sl := cutFromStart(info, as.Rhs[0])
			if sl == nil || types.ExprString(sl.X) != name {
				continue
			}
			out = append(out, byteCut{
				shape: inPlace,
				key:   file + " " + funcName(fn) + " " + name,
				at:    fmt.Sprintf("%s:%d", file, fset.Position(as.Pos()).Line),
				name:  name,
				bound: types.ExprString(bound),
				cut:   types.ExprString(sl),
			})
		}
	})
	return out
}

// markedClips finds, in one file, every string sliced from the start and
// joined straight after to a mark: a constant with "…" or "..." in it.
//
// It need not be guarded. A mark only goes on a cut that was made, so the
// mark is what says the slice is a cut to length, wherever it is.
func markedClips(fset *token.FileSet, info *types.Info, f *ast.File, file string) []byteCut {
	var out []byteCut
	// A sum of three or more is a sum inside a sum, and the walk meets both.
	done := map[*ast.SliceExpr]bool{}
	eachFunc(f, func(fn *ast.FuncDecl, n ast.Node) {
		sum, ok := n.(*ast.BinaryExpr)
		if !ok || sum.Op != token.ADD {
			return
		}
		terms := addends(sum)
		for i := 0; i+1 < len(terms); i++ {
			sl := cutFromStart(info, terms[i])
			if sl == nil || done[sl] || !isMark(info, terms[i+1]) {
				continue
			}
			done[sl] = true
			name := types.ExprString(sl.X)
			out = append(out, byteCut{
				shape: marked,
				key:   file + " " + funcName(fn) + " " + name,
				at:    fmt.Sprintf("%s:%d", file, fset.Position(sl.Pos()).Line),
				name:  name,
				bound: types.ExprString(sl.High),
				cut:   types.ExprString(sl),
				mark:  types.ExprString(terms[i+1]),
			})
		}
	})
	return out
}

// returnedClips finds, in one file, every string returned as a slice of
// itself from the start after its length was compared: inside an if that
// holds when it is longer than a bound, or after an if in the same block
// that returns early when it is not.
func returnedClips(fset *token.FileSet, info *types.Info, f *ast.File, file string) []byteCut {
	var out []byteCut
	returns := func(fn *ast.FuncDecl, stmts []ast.Stmt, x, bound ast.Expr) {
		name := types.ExprString(x)
		for _, st := range stmts {
			ret, ok := st.(*ast.ReturnStmt)
			if !ok {
				continue
			}
			for _, r := range ret.Results {
				sl := cutFromStart(info, r)
				if sl == nil || types.ExprString(sl.X) != name {
					continue
				}
				out = append(out, byteCut{
					shape: returned,
					key:   file + " " + funcName(fn) + " " + name,
					at:    fmt.Sprintf("%s:%d", file, fset.Position(ret.Pos()).Line),
					name:  name,
					bound: types.ExprString(bound),
					cut:   types.ExprString(sl),
				})
			}
		}
	}
	eachFunc(f, func(fn *ast.FuncDecl, n ast.Node) {
		switch n := n.(type) {
		case *ast.IfStmt:
			if x, bound, longer := lengthCompare(n.Cond); x != nil && longer && isString(info, x) {
				returns(fn, n.Body.List, x, bound)
			}
		case *ast.BlockStmt:
			for i, st := range n.List {
				ifs, ok := st.(*ast.IfStmt)
				if !ok || ifs.Else != nil || !endsInReturn(ifs.Body) {
					continue
				}
				if x, bound, longer := lengthCompare(ifs.Cond); x != nil && !longer && isString(info, x) {
					returns(fn, n.List[i+1:], x, bound)
				}
			}
		}
	})
	return out
}

// eachFunc calls visit for every node in the body of every function
// declared in f, with the function it is in.
func eachFunc(f *ast.File, visit func(*ast.FuncDecl, ast.Node)) {
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if n != nil {
				visit(fn, n)
			}
			return true
		})
	}
}

// addends is the terms of a sum in order: a + b + c is (a + b) + c, so the
// left is opened up until it is not a sum. Parentheses are left closed,
// since what is in them is a sum of its own that the walk also meets.
func addends(e ast.Expr) []ast.Expr {
	if sum, ok := e.(*ast.BinaryExpr); ok && sum.Op == token.ADD {
		return append(addends(sum.X), addends(sum.Y)...)
	}
	return []ast.Expr{e}
}

// cutFromStart is e as a slice of a string from its start to a bound, or nil.
func cutFromStart(info *types.Info, e ast.Expr) *ast.SliceExpr {
	sl, ok := ast.Unparen(e).(*ast.SliceExpr)
	if !ok || sl.High == nil || !fromStart(sl.Low) || !isString(info, sl.X) {
		return nil
	}
	return sl
}

// isMark reports a string constant that says something was left out.
func isMark(info *types.Info, e ast.Expr) bool {
	tv, ok := info.Types[e]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return false
	}
	v := constant.StringVal(tv.Value)
	return strings.Contains(v, "…") || strings.Contains(v, "...")
}

// endsInReturn reports a block whose last statement is a return.
func endsInReturn(b *ast.BlockStmt) bool {
	if len(b.List) == 0 {
		return false
	}
	_, ok := b.List[len(b.List)-1].(*ast.ReturnStmt)
	return ok
}

// lengthGuard is x and the bound in len(x) > bound or len(x) >= bound,
// either way round, or nil.
func lengthGuard(cond ast.Expr) (x, bound ast.Expr) {
	x, bound, longer := lengthCompare(cond)
	if !longer {
		return nil, nil
	}
	return x, bound
}

// lengthCompare is x and the bound in a comparison of len(x) with a bound,
// either way round, and whether it holds when x is the longer: true for
// len(x) > n and n <= len(x), false for len(x) <= n and n > len(x). x is
// nil if cond is not one.
func lengthCompare(cond ast.Expr) (x, bound ast.Expr, longer bool) {
	be, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok {
		return nil, nil, false
	}
	switch be.Op {
	case token.GTR, token.GEQ:
		longer = true
	case token.LSS, token.LEQ:
	default:
		return nil, nil, false
	}
	if x := lenOf(be.X); x != nil {
		return x, be.Y, longer
	}
	// The length is on the right, which turns the comparison round.
	if x := lenOf(be.Y); x != nil {
		return x, be.X, !longer
	}
	return nil, nil, false
}

// lenOf is x in len(x), or nil.
func lenOf(e ast.Expr) ast.Expr {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return nil
	}
	if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "len" {
		return nil
	}
	return call.Args[0]
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
