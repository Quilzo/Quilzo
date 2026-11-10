// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/webfont"
)

// trueTypeFace is a TrueType file with every table a browser's sanitiser
// asks for, laid out as a font tool lays one out. The tables are stand-ins
// with the fields that are read in the right places; nothing draws a glyph.
func trueTypeFace(fsType uint16) []byte { return declaringFace(fsType, 0, false) }

// declaringFace is trueTypeFace with the weight and the italic its OS/2
// table states, as a foundry's static face states them; weight 0 says none.
func declaringFace(fsType, weight uint16, italic bool) []byte {
	be := binary.BigEndian
	head := make([]byte, 54)
	be.PutUint32(head[12:16], 0x5F0F3CF5)
	os2 := make([]byte, 96)
	be.PutUint16(os2[4:6], weight)
	be.PutUint16(os2[8:10], fsType)
	if italic {
		be.PutUint16(os2[62:64], 0x0001)
	}
	tables := map[string][]byte{
		"cmap": bytes.Repeat([]byte{0, 1, 2, 3}, 64), "glyf": bytes.Repeat([]byte("outline "), 400),
		"head": head, "hhea": make([]byte, 36), "hmtx": bytes.Repeat([]byte{0, 200}, 100),
		"loca": make([]byte, 202), "maxp": make([]byte, 6), "name": []byte("Aster"),
		"OS/2": os2, "post": make([]byte, 32),
	}
	tags := make([]string, 0, len(tables))
	for tag := range tables {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	dir := make([]byte, 12+16*len(tags))
	be.PutUint32(dir[0:4], 0x00010000)
	be.PutUint16(dir[4:6], uint16(len(tags)))
	var body bytes.Buffer
	offset := len(dir)
	for i, tag := range tags {
		rec := dir[12+16*i:]
		copy(rec[0:4], tag)
		be.PutUint32(rec[8:12], uint32(offset))
		be.PutUint32(rec[12:16], uint32(len(tables[tag])))
		body.Write(tables[tag])
		pad := (4 - len(tables[tag])%4) % 4
		body.Write(make([]byte, pad))
		offset += len(tables[tag]) + pad
	}
	return append(dir, body.Bytes()...)
}

// accessibleLayout is a default layout the publish gate passes, and that
// links the stylesheet the site serves.
const accessibleLayout = `<!doctype html><html lang="en"><head><title>{{ page.title }}</title>` +
	`<link rel="stylesheet" href="/site.css"></head><body><main><h1>{{ page.title }}</h1>` +
	`<p>{{ page.body }}</p></main></body></html>`

// fontSite is a store with one published page, and a template directory.
func fontSite(t *testing.T) (root, tpl string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	root = newStoreWithDraft(t)
	if err := runCmd(t, root, "provenance", "set", "index", "--source", "humanEdits", "--author", "someone"); err != nil {
		t.Fatal(err)
	}
	tpl = filepath.Join(t.TempDir(), "templates")
	if err := os.MkdirAll(tpl, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tpl, "page.html"), []byte(accessibleLayout), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runPublish(t, root, "-templates", tpl); err != nil {
		t.Fatal(err)
	}
	return root, tpl
}

func writeTemp(t *testing.T, name string, b []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func actions(t *testing.T, root, action string) []audit.Event {
	t.Helper()
	evs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var outs []audit.Event
	for _, e := range evs {
		if e.Action == action {
			outs = append(outs, e)
		}
	}
	return outs
}

// A customer with a TrueType file has a way in, and it ends at the reader.
//
// There was none: templates/fonts/ took WOFF2 only, WOFF2 needs Brotli, and
// nothing here has Brotli. `quilzo theme font add` makes a WOFF 1.0 with
// zlib, checks it as the site will, records who added it, and the face is
// then a font the theme accepts by name, served from this origin with its
// own type and announced in the stylesheet as what it is.
func TestATrueTypeFileIsAddedAsAWOFFAndServed(t *testing.T) {
	root, tpl := fontSite(t)
	ttf := writeTemp(t, "Aster.ttf", trueTypeFace(0))

	if err := cmdTheme(root, []string{"font", "add", ttf, "--dir", tpl, "--name", "Aster-400-700"}); err != nil {
		t.Fatal(err)
	}
	served := filepath.Join(tpl, "fonts", "Aster-400-700.woff")
	b, err := os.ReadFile(served)
	if err != nil {
		t.Fatalf("nothing was written: %v", err)
	}
	if webfont.Sniff(b) != "woff" {
		t.Fatalf("wrote a %q", webfont.Sniff(b))
	}
	recs := actions(t, root, "theme.font.add")
	if len(recs) != 1 || recs[0].Detail["file"] != "Aster-400-700.woff" || recs[0].Detail["from"] != "truetype" {
		t.Fatalf("recorded %+v", recs)
	}
	// The theme accepts it by name, which is what "does not serve a font by
	// that name" was refusing.
	if err := cmdTheme(root, []string{"set", "font-body", "Aster", "--dir", tpl}); err != nil {
		t.Fatalf("the theme does not know the face it was just given: %v", err)
	}

	design, err := loadDesign(tpl)
	if err != nil {
		t.Fatal(err)
	}
	st, err := testRun(t, root).build(design, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := st.Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/fonts/Aster-400-700.woff", nil))
	if w.Code != 200 || w.Header().Get("Content-Type") != "font/woff" || !bytes.Equal(w.Body.Bytes(), b) {
		t.Fatalf("the site served %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/site.css", nil))
	css := w.Body.String()
	for _, want := range []string{`url("/fonts/Aster-400-700.woff") format("woff")`, "font-weight: 400 700;", `"Aster"`} {
		if !strings.Contains(css, want) {
			t.Errorf("the stylesheet does not say %s", want)
		}
	}
}

// A face already served is not replaced unless that is asked for, and one
// face is one file.
func TestAFaceIsReplacedOnlyWhenAskedAndIsOneFile(t *testing.T) {
	root, tpl := fontSite(t)
	ttf := writeTemp(t, "Aster-Bold.ttf", trueTypeFace(0))
	add := func(args ...string) error {
		return cmdTheme(root, append([]string{"font", "add", ttf, "--dir", tpl}, args...))
	}
	if err := add(); err != nil {
		t.Fatal(err)
	}
	// Named from the file when no name is given: Aster, bold.
	f, err := webfont.Load(filepath.Join(tpl, "fonts"))
	if err != nil || f.Len() != 1 || f.Faces()[0].File != "Aster-Bold.woff" || f.Faces()[0].Weight != "700" {
		t.Fatalf("the served face: %+v %v", f.Faces(), err)
	}
	if err := add(); err == nil || !strings.Contains(err.Error(), "already served") {
		t.Fatalf("a second add of the same face: %v", err)
	}
	if err := add("--force"); err != nil {
		t.Fatalf("an asked-for replacement: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tpl, "fonts", "Aster-Bold.woff2"), []byte("wOF2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := add("--force"); err == nil || !strings.Contains(err.Error(), "two files for one face") {
		t.Fatalf("a WOFF beside the WOFF2 of the same face: %v", err)
	}
	if n := len(actions(t, root, "theme.font.add")); n != 2 {
		t.Errorf("%d records for two faces written", n)
	}
}

// The record says when a face that was served has been replaced.
//
// An add and a replacement wrote the same record, so somebody asking when the
// body text on every page changed shape found the first add and nothing to
// say the file under that name had since been overwritten.
func TestAReplacedFaceIsRecordedAsReplaced(t *testing.T) {
	root, tpl := fontSite(t)
	ttf := writeTemp(t, "Aster.ttf", trueTypeFace(0))
	for _, force := range []bool{false, true} {
		args := []string{"font", "add", ttf, "--dir", tpl}
		if force {
			args = append(args, "--force")
		}
		if err := cmdTheme(root, args); err != nil {
			t.Fatal(err)
		}
	}
	recs := actions(t, root, "theme.font.add")
	if len(recs) != 2 {
		t.Fatalf("%d records", len(recs))
	}
	if recs[0].Detail["replaced"] == "true" || recs[1].Detail["replaced"] != "true" {
		t.Errorf("the first add recorded %v and the replacement %v", recs[0].Detail, recs[1].Detail)
	}
}

// Adding a typeface is a publisher's decision, on the command line as on the
// Design screen; an author still sets the tokens.
//
// A face is the glyphs every page that names it is drawn with, and what a
// page appears to say is the font's to decide: a face whose digits are drawn
// as other digits changes every price and telephone number at once. No gate
// reads a glyph, and a publisher reviewing a draft sees words, not shapes, so
// it needs the authority over the whole site that installing a layout does.
func TestAddingATypefaceIsAPublishersDecision(t *testing.T) {
	root, tpl := fontSite(t)
	seedPolicy(t, root, [2]string{"kit", "author"}, [2]string{"pat", "publisher"})
	old := flagToken
	t.Cleanup(func() { flagToken = old })

	flagToken = personToken(t, root, "kit", auth.RoleAuthor)
	ttf := writeTemp(t, "Aster.ttf", trueTypeFace(0))
	if err := authoriseCommand(root, "theme", []string{"font", "add", ttf, "--dir", tpl}); err == nil {
		t.Error("an author may add a typeface")
	}
	if err := authoriseCommand(root, "theme", []string{"set", "radius", "3px", "--dir", tpl}); err != nil {
		t.Errorf("an author may no longer set a token: %v", err)
	}
	flagToken = personToken(t, root, "pat", auth.RolePublisher)
	if err := authoriseCommand(root, "theme", []string{"font", "add", ttf, "--dir", tpl}); err != nil {
		t.Errorf("a publisher may not add a typeface: %v", err)
	}
}

// What is not a face, or is a face its licence forbids embedding, is not
// written, and nothing is recorded as having been added.
func TestWhatIsNotAServableFaceIsNotWritten(t *testing.T) {
	root, tpl := fontSite(t)
	for name, b := range map[string][]byte{
		"notes.ttf":      []byte("these are not glyphs"),
		"Locked.ttf":     trueTypeFace(0x0002),
		"Renamed.woff2":  trueTypeFace(0)[:40],
		"../Escape.ttf":  trueTypeFace(0),
		"Aster-wide.ttf": trueTypeFace(0),
	} {
		path := writeTemp(t, strings.ReplaceAll(name, "../", ""), b)
		args := []string{"font", "add", path, "--dir", tpl}
		if strings.HasPrefix(name, "../") {
			args = append(args, "--name", "../Escape")
		}
		if err := cmdTheme(root, args); err == nil {
			t.Errorf("%s was added", name)
		}
	}
	if entries, _ := os.ReadDir(filepath.Join(tpl, "fonts")); len(entries) != 0 {
		t.Errorf("refused faces left %d file(s)", len(entries))
	}
	if entries, _ := os.ReadDir(filepath.Dir(tpl)); len(entries) != 1 {
		t.Errorf("something was written beside the template directory: %d entries", len(entries))
	}
	if n := len(actions(t, root, "theme.font.add")); n != 0 {
		t.Errorf("%d refused faces recorded as added", n)
	}
}

// A foundry's files, added as they came, are served at the weights they are.
//
// Foundries name static faces Family-Regular.ttf and Family-BoldItalic.ttf.
// The first was served as covering every weight, because a filename that
// says no weight is the whole range, so a browser asked for bold drew the
// regular glyphs; the second was refused for a word the filename contract
// does not read. Without --name, the face's own tables say what the file's
// name does not, and the output says that is where the name came from.
func TestAFoundrysFilesAreServedAtTheirOwnWeights(t *testing.T) {
	root, tpl := fontSite(t)
	old := w
	t.Cleanup(func() { w = old })
	for _, c := range []struct {
		file, served, weight, style string
		face                        []byte
	}{
		{"Aster-Regular.ttf", "Aster-400.woff", "400", "normal", declaringFace(0, 400, false)},
		{"Aster-BoldItalic.ttf", "Aster-700-italic.woff", "700", "italic", declaringFace(0, 700, true)},
		{"Aster-Bold.ttf", "Aster-Bold.woff", "700", "normal", declaringFace(0, 700, false)},
	} {
		var b strings.Builder
		w = &out.Writer{Mode: out.Human, Out: &b, Err: io.Discard}
		if err := cmdTheme(root, []string{"font", "add", writeTemp(t, c.file, c.face), "--dir", tpl}); err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		said := strings.Contains(b.String(), "named with the weight and style the face declares, because")
		if renamed := c.served != strings.TrimSuffix(c.file, ".ttf")+".woff"; said != renamed {
			t.Errorf("%s: the output says it was named from the face: %v, and it was: %v\n%s",
				c.file, said, renamed, b.String())
		}
	}
	set, err := webfont.Load(filepath.Join(tpl, "fonts"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range set.Faces() {
		got[f.File] = f.Weight + " " + f.Style
	}
	for file, want := range map[string]string{"Aster-400.woff": "400 normal",
		"Aster-700-italic.woff": "700 italic", "Aster-Bold.woff": "700 normal"} {
		if got[file] != want {
			t.Errorf("%s is served as %q, want %q (all: %v)", file, got[file], want, got)
		}
	}

	// A name somebody gives is used as given.
	w = &out.Writer{Mode: out.JSON, Out: io.Discard, Err: io.Discard}
	added, err := addFont(tpl, "Other-Regular.ttf", declaringFace(0, 400, false), "Other", false, fontFromCommand)
	if err != nil || added.File != "Other.woff" || added.NamedFromFace {
		t.Errorf("a given name was not used as given: %+v %v", added, err)
	}
}

// A refusal names what to do on the surface it was made from: the flag on
// the command line, the field and the checkbox on the Design screen.
//
// Both said "say so to replace it anyway", which is neither.
func TestARefusalNamesTheWayOnItsOwnSurface(t *testing.T) {
	_, tpl := fontSite(t)
	face := declaringFace(0, 700, false)
	if _, err := addFont(tpl, "Aster-700.ttf", face, "", false, fontFromCommand); err != nil {
		t.Fatal(err)
	}
	_, err := addFont(tpl, "Aster-700.ttf", face, "", false, fontFromCommand)
	if err == nil || !strings.Contains(err.Error(), "add --force to replace it") {
		t.Errorf("on the command line: %v", err)
	}
	dw := newDesignWatch(tpl, nil, nil)
	dw.say = func(string, ...any) {}
	_, err = adminDesignHooks(tpl, dw).AddFont("Aster-700.ttf", face, "", false)
	if err == nil || !strings.Contains(err.Error(), `tick "Replace a face already served under that name"`) {
		t.Errorf("on the Design screen: %v", err)
	}
	// A name that does not read, from a face that says nothing of itself.
	_, err = addFont(tpl, "Aster-Wide.ttf", trueTypeFace(0), "", false, fontFromCommand)
	if err == nil || !strings.Contains(err.Error(), "serve it under (--name)") {
		t.Errorf("on the command line: %v", err)
	}
	_, err = adminDesignHooks(tpl, dw).AddFont("Aster-Wide.ttf", trueTypeFace(0), "", false)
	if err == nil || !strings.Contains(err.Error(), "serve it under (Served as)") {
		t.Errorf("on the Design screen: %v", err)
	}
}

// A face put in the directory that is not served says why, and what to run,
// wherever somebody looks: `quilzo theme fonts` and the Design screen.
//
// With nothing served, `theme fonts` said "no fonts of your own" and stopped
// before the reasons, which it printed only under a list of faces; the
// screen never showed them; and the command it named was the bare filename,
// which from the site's directory finds nothing.
func TestAFaceThatIsNotServedSaysWhyWherePeopleLook(t *testing.T) {
	root, tpl := fontSite(t)
	fonts := filepath.Join(tpl, "fonts")
	if err := os.MkdirAll(fonts, 0o700); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(fonts, "Aster-Regular.ttf")
	if err := os.WriteFile(src, trueTypeFace(0), 0o600); err != nil {
		t.Fatal(err)
	}
	run := "quilzo theme font add " + src + " --dir " + tpl
	said, err := humanOutput(t, func() error { return cmdTheme(root, []string{"fonts", "--dir", tpl}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(said, "no fonts of your own") ||
		!strings.Contains(strings.Join(strings.Fields(said), " "), run) {
		t.Errorf("theme fonts does not say why, or what to run:\n%s", said)
	}
	dw := newDesignWatch(tpl, nil, nil)
	dw.say = func(string, ...any) {}
	if err := dw.Reload(); err != nil {
		t.Fatal(err)
	}
	notes := adminDesignHooks(tpl, dw).FontNotes()
	if len(notes) != 1 || !strings.Contains(notes[0], run) {
		t.Errorf("the Design screen is told %v", notes)
	}
	// And what it says to run, runs.
	args := strings.Fields(strings.TrimPrefix(run, "quilzo theme "))
	if err := cmdTheme(root, args); err != nil {
		t.Fatalf("%s: %v", run, err)
	}
	if set, err := webfont.Load(fonts); err != nil || set.Len() != 1 {
		t.Errorf("after running it: %v %v", set.Faces(), err)
	}
	// With a face served, the source left beside it is still named, and
	// the sentence is wrapped to the terminal rather than run off its edge.
	said, err = humanOutput(t, func() error { return cmdTheme(root, []string{"fonts", "--dir", tpl}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(said, "fonts served from this origin") ||
		!strings.Contains(said, "Aster-Regular.ttf is not a .woff2") {
		t.Errorf("theme fonts with a face served does not name the source:\n%s", said)
	}
	for _, line := range strings.Split(said, "\n") {
		if strings.Contains(line, "Aster-Regular.ttf is not") && len(line) > 100 {
			t.Errorf("a note runs to %d columns: %q", len(line), line)
		}
	}
}

// --json is one document saying what was written.
func TestAddingAFaceAnswersInJSON(t *testing.T) {
	root, tpl := fontSite(t)
	ttf := writeTemp(t, "Aster.ttf", trueTypeFace(0))
	old := w
	t.Cleanup(func() { w = old })
	var b strings.Builder
	w = &out.Writer{Mode: out.JSON, Out: &b, Err: io.Discard}
	if err := cmdTheme(root, []string{"font", "add", ttf, "--dir", tpl, "--name", "Aster-italic"}); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(b.String()), &got); err != nil {
		t.Fatalf("not one document: %v\n%s", err, b.String())
	}
	if got["file"] != "Aster-italic.woff" || got["style"] != "italic" || got["from"] != "truetype" ||
		got["served_bytes"].(float64) <= 0 {
		t.Errorf("answered %v", got)
	}
}

// testRun is the run `quilzo site` makes, for a store in a test.
func testRun(t *testing.T, root string) siteRun {
	t.Helper()
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	return siteRun{root: root, store: s, index: "index", ref: site.RefLive, shield: newShieldHost(root)}
}

// Asking a publisher for a typeface took nothing from an author or a reader.
//
// `theme font` asked for publish under a `theme` that asked an author's
// authority, which the table forbids (a specific key narrows its parent, so
// the next subcommand somebody adds arrives guarded). So `theme` is strict
// now, and each subcommand that fell through to it says what it asked
// before; a bare `quilzo theme` is asked as the `show` it runs.
func TestThemeSubcommandsAskWhatTheyAskedBefore(t *testing.T) {
	for args, want := range map[string]auth.Action{
		"":         auth.ActView,
		"show":     auth.ActView,
		"tokens":   auth.ActView,
		"check":    auth.ActView,
		"fonts":    auth.ActView,
		"css":      auth.ActView,
		"export":   auth.ActView,
		"set":      auth.ActEditDraft,
		"unset":    auth.ActEditDraft,
		"apply":    auth.ActEditDraft,
		"generate": auth.ActEditDraft,
		"import":   auth.ActEditDraft,
		"styles":   auth.ActEditDraft,
		"font add": auth.ActPublish,
		// One added later and not listed.
		"rename": auth.ActPublish,
	} {
		n, ok := lookupNeed("theme", strings.Fields(args))
		if !ok || n.action != want {
			t.Errorf("quilzo theme %s asks %q, want %q", args, n.action, want)
		}
	}
}

// Every command that changes the design says when readers get the change.
//
// The admin's preview reads templates/ again as soon as it changes and the
// public site takes the design with its next publish (designreload.go). Only
// `theme font add` said so; `theme set` and the rest said "primary = …" and
// stopped, which left somebody refreshing the live site for a palette that
// was waiting for them to publish, and reaching for the restart that used to
// be the answer.
func TestEveryDesignCommandSaysWhenReadersGetIt(t *testing.T) {
	root, tpl := fontSite(t)
	tokens := writeTemp(t, "tokens.json", []byte(`{"color": {"brand": {"$type": "color", "$value": "#1d4ed8"}}}`))
	for _, args := range [][]string{
		{"set", "radius", "6px"},
		{"unset", "radius"},
		{"generate", "#7c3aed"},
		{"unset", "--all"},
		{"import", tokens, "--set", "primary=color.brand", "--scheme", "light"},
		{"apply", "article", "--force"},
		{"font", "add", writeTemp(t, "Aster-Regular.ttf", declaringFace(0, 400, false))},
	} {
		args := append(args, "--dir", tpl)
		said, err := humanOutput(t, func() error { return cmdTheme(root, args) })
		if err != nil {
			t.Fatalf("theme %v: %v\n%s", args, err, said)
		}
		if !strings.Contains(said, "the site serves it from its next publish") {
			t.Errorf("theme %v does not say when readers get it:\n%s", args, said)
		}
	}
}

// a woff2 is the shortest file the WOFF2 check accepts: the signature and a
// length that agrees with the file. Its tables are Brotli and nothing here
// reads them, which is the point of the test that uses it.
func woff2() []byte {
	b := make([]byte, 64)
	copy(b, "wOF2")
	binary.BigEndian.PutUint32(b[8:12], uint32(len(b)))
	return b
}

// A .woff2 whose name says no weight is served as every weight, and the
// person adding it is told, on the command line and in --json.
//
// Its tables are Brotli, so the face cannot be asked what it is, as a .ttf
// or a .woff now is; Aster-Regular.woff2 from a foundry's web kit was served
// as covering 100 to 900 with nothing said, and bold text drawn in the
// regular glyphs looked like a browser fault.
func TestAWOFF2ThatCannotBeAskedSaysSo(t *testing.T) {
	root, tpl := fontSite(t)
	said, err := humanOutput(t, func() error {
		return cmdTheme(root, []string{"font", "add", writeTemp(t, "Aster-Regular.woff2", woff2()), "--dir", tpl})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(said, "/fonts/Aster-Regular.woff2") ||
		!strings.Contains(said, "cannot be read here") ||
		!strings.Contains(strings.Join(strings.Fields(said), " "), filepath.Join(tpl, "fonts", "Aster-400.woff2")) {
		t.Errorf("a .woff2 that says no weight was added without a word:\n%s", said)
	}
	for _, c := range []struct {
		file, name string
		unread     bool
	}{
		{"Aster-Light.woff2", "", false},
		{"Aster-Italic.woff2", "", true},
		{"Aster-Wide.woff2", "Aster-500", false},
	} {
		added, err := addFont(tpl, c.file, woff2(), c.name, false, fontFromCommand)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		if added.WeightUnread != c.unread {
			t.Errorf("%s named %q: weight unread %v, want %v", c.file, c.name, added.WeightUnread, c.unread)
		}
	}
	// A face whose tables are read is never said to be unread.
	added, err := addFont(tpl, "Other-Regular.ttf", declaringFace(0, 400, false), "", false, fontFromCommand)
	if err != nil || added.WeightUnread {
		t.Errorf("a TrueType face was said to be unread: %+v %v", added, err)
	}
}
