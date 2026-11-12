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
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClipNeverCutsInsideACharacter(t *testing.T) {
	for _, c := range []struct {
		s    string
		n    int
		mark string
		want string
	}{
		{"short", 10, "…", "short"},
		{"exactly", 7, "…", "exactly"},
		{"abcdef", 3, "", "abc"},
		{"abcdef", 4, "…", "a…"},
		// é is two bytes, 中 three and 𝄞 four: a cut at every byte inside
		// each goes back to where it starts.
		{"café", 4, "", "caf"},
		{"a中b", 2, "", "a"},
		{"a中b", 3, "", "a"},
		{"a中b", 4, "", "a中"},
		{"a𝄞b", 2, "", "a"},
		{"a𝄞b", 4, "", "a"},
		{"a𝄞b", 5, "", "a𝄞"},
		{"中文字", 7, "…", "中…"},
		// Nothing fits beside the mark, so only the mark comes back.
		{"中文字", 3, "…", "…"},
		// A mark longer than the bound is left off rather than returned
		// alone in place of text it does not describe.
		{"abcdef", 2, "…", "ab"},
		{"abcdef", 0, "…", ""},
		{"abcdef", -1, "", ""},
		// A stray continuation byte after a letter is not part of it: the
		// letter stays.
		{"ab\x80\x80cd", 3, "", "ab\x80"},
	} {
		if got := Clip(c.s, c.n, c.mark); got != c.want {
			t.Errorf("Clip(%q, %d, %q) = %q, want %q", c.s, c.n, c.mark, got, c.want)
		}
	}
}

// Every bound over text mixing one-, two-, three- and four-byte characters,
// with and without a mark: what comes back fits the bound, is text, and is
// the start of what went in.
func TestClipFitsItsBoundAndKeepsTheStart(t *testing.T) {
	s := strings.Repeat("aé中𝄞", 5)
	for _, mark := range []string{"", "…", "..."} {
		for n := 0; n <= len(s)+1; n++ {
			got := Clip(s, n, mark)
			if len(got) > n {
				t.Errorf("Clip(_, %d, %q) is %d bytes", n, mark, len(got))
			}
			if !utf8.ValidString(got) {
				t.Errorf("Clip(_, %d, %q) = %q, which is not text", n, mark, got)
			}
			kept := strings.TrimSuffix(got, mark)
			if n < len(s) && n >= len(mark) && !strings.HasSuffix(got, mark) {
				t.Errorf("Clip(_, %d, %q) = %q has lost its mark", n, mark, got)
			}
			if !strings.HasPrefix(s, kept) {
				t.Errorf("Clip(_, %d, %q) = %q is not the start of the text", n, mark, got)
			}
			// Backing off never costs a whole character more than it must.
			if n >= len(mark) && len(kept) < n-len(mark)-(utf8.UTFMax-1) {
				t.Errorf("Clip(_, %d, %q) kept %d bytes", n, mark, len(kept))
			}
		}
	}
}

// No text the program keeps, sends or shows is cut inside a character.
//
// There are three shapes of it, and all three read as obviously right. The
// first cuts in place:
//
//	if len(s) > n {
//		s = s[:n]
//	}
//
// The second marks the cut, in place or anywhere else:
//
//	s = s[:n] + "…"
//
// The third is a helper that returns the cut, so every caller shares it:
//
//	func clip(s string, n int) string {
//		if len(s) <= n {
//			return s
//		}
//		return s[:n]
//	}
//
// Each bounds bytes, which is what a store, a provider and a log line limit,
// and on English each is never wrong, which is how so many of them shipped.
// On a visitor's question in Japanese, an error a provider wrote in German,
// or a filename with an accent in it, the cut lands inside a character
// whenever that character is longer than a byte, and what is kept ends in
// bytes that are not text. A mark after the cut does not help: the half
// character is still there, just before it. Clip makes the same cut at the
// start of that character instead.
//
// The same shapes on a slice are right, and far more common, so the walk
// type-checks the source: a check of the syntax alone would either refuse
// every list cut to length or miss a string field such as in.Purpose. It
// covers the files this platform builds; those built only elsewhere are file
// locks and process plumbing.
//
// A cut at an index that was searched for, such as the last space before a
// bound, is not one of the shapes unless it is marked: whether the index is
// a character's start depends on what was searched for, which the types do
// not say, and a returned cut is only taken for a clip when the string's
// length was compared first.
func TestNoClippedTextEndsInHalfACharacter(t *testing.T) {
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
