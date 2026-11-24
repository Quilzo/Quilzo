// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"go/scanner"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Two names this repository does not carry.
//
// Two names belong to work beside Quilzo, and neither appears in it: not in
// its code, tests, fixtures or documents, and not in a commit message. What
// Quilzo leaves to other tools is said of any tool, "a security team's own
// tools" or "a SIEM", because a reader who finds one product named in
// another's source takes it for a dependency or an endorsement, and Quilzo
// has neither.
//
// A rule like that is kept by review until the day review misses it, and the
// usual guard, a list of words to grep for, would be the leak: the names
// would sit in plain text in the file that keeps them out. So the guard holds
// only the SHA-256 digest of each name, in lower case, and compares the
// digest of every word in the repository with them. A digest keeps a name
// out of the text: out of grep, out of a search engine's index and out of a
// reader's eye. It does not keep it from somebody willing to hash every short
// word, and nothing in a public repository could.
//
// A word is a run of ASCII letters and digits, and each part of the run where
// the case or the kind of character changes, so a name is found in prose, in
// a path and inside an identifier however it is cased: fooBar, FooBar,
// foo_bar, FOO-BAR and foo2 all hold the word foo. A name run into another
// word in one case, as a Go package name would be, makes a word of its own
// and is not found. That much is left to review.
var forbiddenNames = []string{
	"b3c3025df6815516162f8403a6841525dc08d0786d127c1e7f9d70c65ccdeb82",
	"4f0a9857ce012e161e52aea17566d7687fecec28e3b328cec68e49db762ecf81",
}

// namedBefore is the commits whose messages named one of the two before this
// guard existed.
//
// A commit is history, and history is not rewritten here: a rewrite changes
// the hash of every commit after it, and every clone, tag and release that
// points at one. So these are let stand, by hash, and only these; any other
// message that names one fails. Both are of 3 and 4 November 2026: the
// commit that corrected the references to what had left Quilzo, and the
// squashed merge that carried its message.
var namedBefore = map[string]bool{
	"b540d7666b1bc1e4807e99553f9bad2da58c54c3": true,
	"e8a85ccd80fad6ed4c72c46efcfc5a089cf864d1": true,
}

// guardSource is the file that holds the digests.
const guardSource = "naming_test.go"

// No file in the repository, and no commit message in its history, carries a
// name the guard holds a digest of.
//
// The files are what git tracks and what it would add: a new file nobody has
// added yet is the likeliest leak, and a guard that waits for `git add` finds
// it in review, after the push. A path is read as well as what is in it, and
// a compressed fixture is read uncompressed.
//
// The history is what this checkout has. CI checks a pull request out one
// commit deep and reads only the merge GitHub made for it; a full clone, as
// the maintainer's is, reads every message.
func TestNoForbiddenNames(t *testing.T) {
	g := mustGuard(t, forbiddenNames)
	files, err := repositoryFiles(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 1000 {
		t.Fatalf("only %d files found; this test is reading the wrong tree", len(files))
	}
	hits, err := g.files(".", files)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits {
		t.Error(h)
	}

	history, err := commitMessages(".")
	if err != nil {
		t.Logf("no history to read here (%v), so only the files were read", err)
		return
	}
	for _, h := range g.messages(history, namedBefore) {
		t.Error(h)
	}
}

// The guard finds a name planted where a leak would be: in a file nobody has
// added yet, in each of the shapes a word takes, and in a commit message.
//
// A test cannot plant a real name without writing it down, which is what the
// guard exists to stop. So it plants a stand-in and gives the guard the
// stand-in's digest beside the real ones: the guard finds a word because its
// digest is one the guard holds, so a word it finds is a word it would find
// as either name.
//
// That the digests the guard holds are of the names is shown only by
// somebody who knows them. QUILZO_FORBIDDEN_NAMES, set to both names
// separated by commas, plants each one as well, and then each must be found
// by the guard as it stands, with no stand-in, and every digest it holds
// must be one of them. CI does not know the names and does not set it.
func TestGuardCatchesPlantedName(t *testing.T) {
	const standIn = "quarnel"
	sum := sha256.Sum256([]byte(standIn))
	held := append(slices.Clone(forbiddenNames), hex.EncodeToString(sum[:]))
	g := mustGuard(t, held)

	dir := t.TempDir()
	planted := map[string]string{
		"README.md":          "# Example\n\nBuilt beside Quarnel.\n",
		"cmd/x/main.go":      "package main\n\n// Copied from quarnel/internal/connector.\n",
		"pkg/y/y.go":         "package y\n\nvar quarnelClient = 1\n",
		"pkg/y/z.go":         "package y\n\n// FromQuarnel is a record.\ntype FromQuarnel struct{}\n",
		"deploy/env":         "QUARNEL_TOKEN=x\n",
		"testdata/feed.json": "{\n  \"source\": \"quarnel-2\"\n}\n",
		"docs/quarnel.md":    "Nothing to see here.\n",
		"docs/clean.md":      "Nothing to see here either.\n",
	}
	for name, body := range planted {
		write(t, filepath.Join(dir, name), []byte(body))
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	fmt.Fprint(zw, "{\n  \"records\": [],\n  \"from\": \"Quarnel\"\n}\n")
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "testdata/feed.json.gz"), gz.Bytes())

	// Planted in a repository and not added, as a new file is before
	// anybody runs `git add`, where git is here to make one.
	hasGit := false
	if _, err := exec.LookPath("git"); err == nil {
		hasGit = true
		gitIn(t, dir, "init", "-q")
	}

	want := []string{
		"README.md:3", "cmd/x/main.go:3", "deploy/env:1", "docs/quarnel.md",
		"pkg/y/y.go:3", "pkg/y/z.go:3", "pkg/y/z.go:4",
		"testdata/feed.json.gz:3", "testdata/feed.json:2",
	}
	files, err := repositoryFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(planted)+1 {
		t.Errorf("the guard was given %d of the %d files planted: %v", len(files), len(planted)+1, files)
	}
	hits, err := g.files(dir, files)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, h := range hits {
		got = append(got, h.where)
		if h.name != len(held) {
			t.Errorf("%s was found as name %d, and the only word planted was the stand-in, %d", h.where, h.name, len(held))
		}
	}
	sort.Strings(got)
	if !slices.Equal(got, want) {
		t.Errorf("the guard found the stand-in at\n\t%v\nand it was planted at\n\t%v", got, want)
	}

	// A message naming it fails, unless it is one let stand by hash.
	if hasGit {
		gitIn(t, dir, "add", "docs/clean.md")
		gitIn(t, dir, "commit", "-q", "-m", "Clean up\n\nAs Quarnel does.")
		named := strings.TrimSpace(gitIn(t, dir, "rev-parse", "HEAD"))
		gitIn(t, dir, "commit", "-q", "--allow-empty", "-m", "Say what quarnel-2 is")
		later := strings.TrimSpace(gitIn(t, dir, "rev-parse", "HEAD"))
		gitIn(t, dir, "commit", "-q", "--allow-empty", "-m", "Nothing named")
		history, err := commitMessages(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(history) != 3 {
			t.Fatalf("the history has %d messages, and three were written", len(history))
		}
		hits := g.messages(history, map[string]bool{named: true})
		if len(hits) != 1 || hits[0].where != "commit "+later[:12]+":1" {
			t.Errorf("with %s let stand, the messages naming the stand-in were found as %v; want only commit %s:1",
				named[:12], hits, later[:12])
		}
		if hits := g.messages(history, nil); len(hits) != 2 {
			t.Errorf("with nothing let stand, %d messages naming the stand-in were found, and two do: %v", len(hits), hits)
		}
	}

	names := os.Getenv("QUILZO_FORBIDDEN_NAMES")
	if names == "" {
		return
	}
	real := mustGuard(t, forbiddenNames)
	covered := map[int]bool{}
	for i, name := range strings.Split(names, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		sum := sha256.Sum256([]byte(name))
		n := real.sums[sum]
		if n == 0 {
			t.Errorf("name %d of QUILZO_FORBIDDEN_NAMES is not one the guard holds a digest of", i+1)
			continue
		}
		covered[n] = true
		hits := real.scan("planted", []byte("Copied from "+strings.ToUpper(name[:1])+name[1:]+"'s source.\n"))
		if len(hits) != 1 || hits[0].name != n {
			t.Errorf("name %d of QUILZO_FORBIDDEN_NAMES, planted in a sentence, was found as %v", i+1, hits)
		}
	}
	for i := range forbiddenNames {
		if !covered[i+1] {
			t.Errorf("digest %d the guard holds is of none of the names in QUILZO_FORBIDDEN_NAMES", i+1)
		}
	}
}

// The guard's own source holds the digests and no name.
//
// Every entry is a SHA-256 digest. And no name is spelt in the file in any
// way a reader could undo by eye: the file's letters are read as one run with
// everything else taken out, so a name split across words, punctuation or
// string literals is still a run of them, and the run is read forwards,
// backwards and in rot13. Each string literal is decoded from base64 and from
// hex too, and its letters read the same way.
func TestGuardHoldsOnlyHashes(t *testing.T) {
	src := []byte(read(t, guardSource))
	if len(forbiddenNames) == 0 {
		t.Fatal("the guard holds no digest, so it finds nothing")
	}
	seen := map[string]bool{}
	for i, d := range forbiddenNames {
		if b, err := hex.DecodeString(d); err != nil || len(b) != sha256.Size || d != strings.ToLower(d) {
			t.Errorf("entry %d the guard holds is not a SHA-256 digest in lower-case hex", i+1)
		}
		if seen[d] {
			t.Errorf("entry %d the guard holds is held twice", i+1)
		}
		seen[d] = true
		if !bytes.Contains(src, []byte(`"`+d+`"`)) {
			t.Errorf("entry %d the guard holds is not in %s, so this test is reading the wrong file", i+1, guardSource)
		}
	}

	g := mustGuard(t, forbiddenNames)
	for _, h := range g.spelt(guardSource, src) {
		t.Error(h)
	}
	for _, lit := range stringLiterals(t, guardSource, src) {
		for how, b := range decodings(lit.value) {
			for _, h := range g.spelt(fmt.Sprintf("%s, decoded from %s", lit.where, how), b) {
				t.Error(h)
			}
		}
	}
}

// Every internal package a comment or a document names is here.
//
// Comments cited seven packages that had left Quilzo for work beside it, as
// the place an argument was made or a rule was kept. A reader sent to one
// found no such directory, and a reader who knew where it had gone learnt it
// from the comment. The argument is made where it is cited now, or the
// package that keeps the rule today is named.
//
// NEWS is left out: it is the history of what changed, and what left is part
// of it. A path inside another repository, or a host, is not one of Quilzo's
// packages: what comes before internal/ says which.
func TestEveryInternalPackageNamedIsHere(t *testing.T) {
	files, err := repositoryFiles(".")
	if err != nil {
		t.Fatal(err)
	}
	named := regexp.MustCompile(`(?:^|[^A-Za-z0-9._/-]|github\.com/quilzo/quilzo/)internal/([a-z0-9]+)\b`)
	for _, name := range files {
		if name == "NEWS" {
			continue
		}
		body, err := os.ReadFile(name)
		if err != nil || bytes.IndexByte(body, 0) >= 0 {
			continue
		}
		for i, line := range strings.Split(string(body), "\n") {
			for _, m := range named.FindAllStringSubmatch(line, -1) {
				if st, err := os.Stat(filepath.Join("internal", m[1])); err != nil || !st.IsDir() {
					t.Errorf("%s:%d names internal/%s, and there is no such package", name, i+1, m[1])
				}
			}
		}
	}
}

// guard compares words with the digests of the names.
type guard struct {
	// sums is each name's digest, and which name it is, counting from 1.
	sums map[[sha256.Size]byte]int
	// seen is each word already hashed, and which name it is, 0 for none.
	seen map[string]int
}

// hit is a name found: where, and which of the guard's digests it matched,
// counting from 1. It never carries the word, so a failing run says where a
// name is and does not print it.
type hit struct {
	where string
	name  int
}

func (h hit) String() string {
	return fmt.Sprintf("%s holds a name this repository does not carry (digest %d the guard holds)", h.where, h.name)
}

// mustGuard is a guard holding digests, each a SHA-256 digest in hex.
func mustGuard(t *testing.T, digests []string) *guard {
	t.Helper()
	g := &guard{sums: map[[sha256.Size]byte]int{}, seen: map[string]int{}}
	for i, d := range digests {
		b, err := hex.DecodeString(d)
		if err != nil || len(b) != sha256.Size {
			t.Fatalf("entry %d the guard is given is not a SHA-256 digest in hex", i+1)
		}
		g.sums[[sha256.Size]byte(b)] = i + 1
	}
	return g
}

// which is which name word is, counting from 1, or 0 for none.
//
// A word is hashed once. A repository says the same few thousand words over
// and over, and looking one up costs less than hashing it again.
func (g *guard) which(word []byte) int {
	if n, ok := g.seen[string(word)]; ok {
		return n
	}
	n := g.sums[sha256.Sum256(word)]
	g.seen[string(word)] = n
	return n
}

// scan is every name in text, which is at where: one hit a line, at
// where:line.
func (g *guard) scan(where string, text []byte) []hit {
	var hits []hit
	last := 0
	words(text, func(word []byte, line int) {
		if n := g.which(word); n != 0 && line != last {
			hits = append(hits, hit{fmt.Sprintf("%s:%d", where, line), n})
			last = line
		}
	})
	return hits
}

// files is every name in the files under dir, in what they hold and in
// their paths. A file ending .gz is read uncompressed, since that is the
// text a name would be in.
func (g *guard) files(dir string, names []string) ([]hit, error) {
	var hits []hit
	for _, name := range names {
		if h := g.scan(name, []byte(name)); len(h) > 0 {
			hits = append(hits, hit{name, h[0].name})
		}
		body, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if errors.Is(err, fs.ErrNotExist) {
			// Tracked, and deleted from the working tree: it holds nothing.
			continue
		}
		if err != nil {
			return hits, err
		}
		if strings.HasSuffix(name, ".gz") {
			zr, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil {
				return hits, fmt.Errorf("%s: %w", name, err)
			}
			if body, err = io.ReadAll(zr); err != nil {
				return hits, fmt.Errorf("%s: %w", name, err)
			}
		}
		hits = append(hits, g.scan(name, body)...)
	}
	return hits, nil
}

// messages is every name in history's messages, but for the commits let
// stand.
func (g *guard) messages(history []commit, let map[string]bool) []hit {
	var hits []hit
	for _, c := range history {
		if let[c.hash] {
			continue
		}
		short := c.hash
		if len(short) > 12 {
			short = short[:12]
		}
		hits = append(hits, g.scan("commit "+short, []byte(c.message))...)
	}
	return hits
}

// maxSpelt is the longest run of letters spelt checks: longer than any name
// a product goes by.
const maxSpelt = 32

// spelt is every name spelt in text's letters, with everything that is not
// a letter taken out. Every run of two to maxSpelt of them is hashed, read
// forwards, backwards and in rot13.
//
// It hashes far more than words does, which is why it reads only the
// guard's own source: a name hidden there would be hidden on purpose.
func (g *guard) spelt(where string, text []byte) []hit {
	var letters []byte
	for _, c := range text {
		switch {
		case 'a' <= c && c <= 'z':
			letters = append(letters, c)
		case 'A' <= c && c <= 'Z':
			letters = append(letters, c+'a'-'A')
		}
	}
	backwards := slices.Clone(letters)
	slices.Reverse(backwards)
	rot13 := make([]byte, len(letters))
	for i, c := range letters {
		rot13[i] = 'a' + (c-'a'+13)%26
	}
	var hits []hit
	for _, way := range []struct {
		how     string
		letters []byte
	}{{"as written", letters}, {"backwards", backwards}, {"in rot13", rot13}} {
		found := map[int]bool{}
		for i := range way.letters {
			for n := 2; n <= maxSpelt && i+n <= len(way.letters); n++ {
				if k := g.sums[sha256.Sum256(way.letters[i:i+n])]; k != 0 && !found[k] {
					found[k] = true
					hits = append(hits, hit{fmt.Sprintf("%s, its letters read %s", where, way.how), k})
				}
			}
		}
	}
	return hits
}

// words calls see with each word in text, in lower case, and the line it is
// on: each run of ASCII letters and digits, and each part of a run that
// changes case or kind of character. word is good only until see returns.
func words(text []byte, see func(word []byte, line int)) {
	var lower []byte
	line := 1
	for i := 0; i < len(text); {
		if !isAlnum(text[i]) {
			if text[i] == '\n' {
				line++
			}
			i++
			continue
		}
		j := i + 1
		for j < len(text) && isAlnum(text[j]) {
			j++
		}
		run := text[i:j]
		lower = append(lower[:0], run...)
		for k, c := range lower {
			if isUpper(c) {
				lower[k] = c + 'a' - 'A'
			}
		}
		see(lower, line)
		start := 0
		for k := 1; k < len(run); k++ {
			if partBreak(run, k) {
				see(lower[start:k], line)
				start = k
			}
		}
		if start > 0 {
			see(lower[start:], line)
		}
		i = j
	}
}

// partBreak is whether a part of run ends before run[k]: between a
// lower-case letter and a capital (fooBar), before the last of several
// capitals when a lower-case letter follows it (HTTPServer), and between a
// letter and a digit (foo2).
func partBreak(run []byte, k int) bool {
	a, b := run[k-1], run[k]
	switch {
	case isLower(a) && isUpper(b):
		return true
	case isUpper(a) && isUpper(b) && k+1 < len(run) && isLower(run[k+1]):
		return true
	}
	return isDigit(a) != isDigit(b)
}

func isLower(c byte) bool { return 'a' <= c && c <= 'z' }
func isUpper(c byte) bool { return 'A' <= c && c <= 'Z' }
func isDigit(c byte) bool { return '0' <= c && c <= '9' }
func isAlnum(c byte) bool { return isLower(c) || isUpper(c) || isDigit(c) }

// repositoryFiles is every file in the repository at dir, by its path from
// dir with forward slashes: what git tracks and what it would add, which is
// everything but what .gitignore leaves out. Where git is not, or dir is not
// a checkout, as a source archive is not, it is every file under dir.
func repositoryFiles(dir string) ([]string, error) {
	out, err := exec.Command("git", "-C", dir, "ls-files", "-z", "--cached", "--others", "--exclude-standard").Output()
	if err == nil {
		var names []string
		seen := map[string]bool{}
		for _, name := range strings.Split(string(out), "\x00") {
			if name != "" && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
		return names, nil
	}
	var names []string
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if d.Type().IsRegular() {
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			names = append(names, filepath.ToSlash(rel))
		}
		return nil
	})
	return names, err
}

// commit is one commit's hash and message.
type commit struct{ hash, message string }

// commitMessages is every commit message in the history of dir's HEAD,
// newest first, merges among them: a merge's message is written by whoever
// merged.
func commitMessages(dir string) ([]commit, error) {
	out, err := exec.Command("git", "-C", dir, "log", "-z", "--format=%H%n%B", "HEAD").Output()
	if err != nil {
		return nil, err
	}
	var history []commit
	for _, rec := range strings.Split(string(out), "\x00") {
		hash, message, _ := strings.Cut(strings.TrimLeft(rec, "\n"), "\n")
		if hash != "" {
			history = append(history, commit{hash, message})
		}
	}
	return history, nil
}

// literal is one string or rune literal in a Go file, its value, and where
// it is.
type literal struct{ where, value string }

// stringLiterals is every string and rune literal in the Go source src,
// which is the file name.
func stringLiterals(t *testing.T, name string, src []byte) []literal {
	t.Helper()
	fset := token.NewFileSet()
	var s scanner.Scanner
	s.Init(fset.AddFile(name, -1, len(src)), src, func(pos token.Position, msg string) {
		t.Errorf("%s: %s", pos, msg)
	}, 0)
	var lits []literal
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			return lits
		}
		if tok != token.STRING && tok != token.CHAR {
			continue
		}
		v, err := strconv.Unquote(lit)
		if err != nil {
			t.Errorf("%s: %v", fset.Position(pos), err)
			continue
		}
		lits = append(lits, literal{fset.Position(pos).String(), v})
	}
}

// decodings is s decoded each way a name is written down without being
// written: base64, padded or not, of either alphabet, and hex. A way s does
// not decode is left out.
func decodings(s string) map[string][]byte {
	out := map[string][]byte{}
	for how, enc := range map[string]*base64.Encoding{
		"base64": base64.StdEncoding, "unpadded base64": base64.RawStdEncoding,
		"URL-safe base64": base64.URLEncoding, "unpadded URL-safe base64": base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			out[how] = b
		}
	}
	if b, err := hex.DecodeString(s); err == nil {
		out["hex"] = b
	}
	return out
}

func write(t *testing.T, name string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

// gitIn runs git in dir with no configuration of the machine's, so a
// signing or hook setting there does not reach the test.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=x", "GIT_AUTHOR_EMAIL=x@example.com", "GIT_COMMITTER_NAME=x", "GIT_COMMITTER_EMAIL=x@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}
