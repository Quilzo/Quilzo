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
func trueTypeFace(fsType uint16) []byte {
	be := binary.BigEndian
	head := make([]byte, 54)
	be.PutUint32(head[12:16], 0x5F0F3CF5)
	os2 := make([]byte, 96)
	be.PutUint16(os2[8:10], fsType)
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
