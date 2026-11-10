// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/starter"
)

// The layouts a page may name include the ones this site wrote.
//
// `quilzo template layouts` listed the layouts that ship and nothing else, so
// a site rendering its home page through templates/arena.html was told arena
// was not a layout it had: the question was which layouts a page may name,
// and the answer left out the one in use.
func TestTemplateLayoutsListsTheSitesOwn(t *testing.T) {
	tpl := filepath.Join(t.TempDir(), "templates")
	if err := os.MkdirAll(tpl, 0o700); err != nil {
		t.Fatal(err)
	}
	layout := `<!doctype html><html lang="en"><head><title>{{ page.title }}</title></head>` +
		`<body><main><h1>{{ page.title }}</h1></main></body></html>`
	for name, body := range map[string]string{
		"page.html": layout, "arena.html": layout,
		"notes.txt": "not a layout", "Bad Name.html": layout,
	} {
		if err := os.WriteFile(filepath.Join(tpl, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	said, err := humanOutput(t, func() error { return cmdTemplate("", []string{"layouts", "--dir", tpl}) })
	if err != nil {
		t.Fatal(err)
	}
	own := said[strings.Index(said, "this site's own"):]
	for _, want := range []string{"arena", "written for this site", "page", "a copy of the shipped one"} {
		if !strings.Contains(own, want) {
			t.Errorf("the site's own layouts do not say %q:\n%s", want, own)
		}
	}
	if strings.Contains(said, "Bad Name") || strings.Contains(said, "notes") {
		t.Errorf("a file no page can name was listed:\n%s", said)
	}
	for _, shipped := range starter.LayoutNames() {
		if !strings.Contains(said[:strings.Index(said, "this site's own")], shipped) {
			t.Errorf("the shipped %s layout went missing", shipped)
		}
	}

	// As one list, for a program: every name a page may use, once.
	old := w
	t.Cleanup(func() { w = old })
	var b strings.Builder
	w = &out.Writer{Mode: out.JSON, Out: &b, Err: io.Discard}
	if err := cmdTemplate("", []string{"layouts", "--dir", tpl}); err != nil {
		t.Fatal(err)
	}
	var names []string
	if err := json.Unmarshal([]byte(b.String()), &names); err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, n := range names {
		seen[n]++
	}
	if seen["arena"] != 1 || seen["page"] != 1 || len(names) != len(starter.LayoutNames())+1 {
		t.Errorf("listed %v", names)
	}

	// A site with no template directory yet is told how to make one, and
	// still gets the shipped ones.
	said, err = humanOutput(t, func() error {
		return cmdTemplate("", []string{"layouts", "--dir", filepath.Join(t.TempDir(), "none")})
	})
	if err != nil || !strings.Contains(said, "none yet") {
		t.Errorf("a site with no layouts of its own: %v\n%s", err, said)
	}
}

// A layout of the site's own that does not parse is named, with why.
//
// The listing's comment said it named one, and it named none: the files are
// read and not parsed until a page renders through them, so the first word
// of an unclosed {% if %} was a page that would not render.
func TestTemplateLayoutsNamesOneThatDoesNotParse(t *testing.T) {
	tpl := filepath.Join(t.TempDir(), "templates")
	if err := os.MkdirAll(tpl, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"page.html":    `<main>{{ page.title }}</main>`,
		"arena.html":   `<main>{% if page.title %}{{ page.title }}</main>`,
		"gallery.html": `<main>{% each page.items %}</main>`,
	} {
		if err := os.WriteFile(filepath.Join(tpl, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	said, err := humanOutput(t, func() error { return cmdTemplate("", []string{"layouts", "--dir", tpl}) })
	if err != nil {
		t.Fatal(err)
	}
	lines := map[string]string{}
	for _, line := range strings.Split(said[strings.Index(said, "this site's own"):], "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			lines[f[0]] = line
		}
	}
	for name, want := range map[string]string{"arena": "left open", "gallery": "unknown tag"} {
		if !strings.Contains(lines[name], "does not parse") || !strings.Contains(lines[name], want) {
			t.Errorf("%s is listed as %q", name, lines[name])
		}
	}
	if strings.Contains(lines["page"], "does not parse") {
		t.Errorf("a layout that parses is listed as broken: %q", lines["page"])
	}
}
