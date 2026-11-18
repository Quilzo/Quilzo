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

	"github.com/quilzo/quilzo/internal/auth"
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

// Writing a layout asks a publisher, on the command line as on the Design
// screen.
//
// `quilzo template use NAME --force` replaced page.html, which every page
// renders through, at an author's authority, while the Design screen's
// install refused the same person the same act: replacing the markup changes
// every page at once, including pages they may not edit. The help calls the
// two the same operation. Reading the starters stays a reader's, and adopting
// a layout of the site's own stays an author's until it would replace one a
// page may already render through.
func TestWritingALayoutAsksWhatTheDesignScreenAsks(t *testing.T) {
	root, secrets := storeWithTokenFor(t,
		auth.Binding{Principal: "pat", Role: auth.RolePublisher, Resource: "/"},
		auth.Binding{Principal: "ann", Role: auth.RoleAuthor, Resource: "/"},
		auth.Binding{Principal: "rae", Role: auth.RoleReader, Resource: "/"})
	for _, cmd := range []string{"template", "templates"} {
		for who, may := range map[string]bool{"pat": true, "ann": false, "rae": false} {
			t.Setenv("QUILZO_TOKEN", secrets[who])
			for _, args := range [][]string{
				{"use", "landing"}, {"use", "landing", "--force", "--dir", "templates"},
				{"use", "sections", "--all-layouts"},
				// One added later and not listed.
				{"a-subcommand-added-later"},
			} {
				if err := authoriseCommand(root, cmd, args); (err == nil) != may {
					t.Errorf("%s running %s %v: %v", who, cmd, args, err)
				}
			}
		}
		t.Setenv("QUILZO_TOKEN", secrets["rae"])
		for _, args := range [][]string{nil, {"list"}, {"show", "landing"}, {"layouts"}} {
			if err := authoriseCommand(root, cmd, args); err != nil {
				t.Errorf("a reader running %s %v: %v", cmd, args, err)
			}
		}
		t.Setenv("QUILZO_TOKEN", secrets["ann"])
		if err := authoriseCommand(root, cmd, []string{"adopt", "theirs.html"}); err != nil {
			t.Errorf("an author adopting a layout: %v", err)
		}
	}

	// Adopting over a layout the site already has is replacing the markup
	// its pages render through, and asks what template use asks.
	tpl := filepath.Join(t.TempDir(), "templates")
	if err := os.MkdirAll(tpl, 0o700); err != nil {
		t.Fatal(err)
	}
	mine := `<!doctype html><html lang="en"><head><title>{{ page.title }}</title></head>` +
		`<body><main><h1>{{ page.title }}</h1></main></body></html>`
	if err := os.WriteFile(filepath.Join(tpl, "page.html"), []byte(mine), 0o600); err != nil {
		t.Fatal(err)
	}
	theirs := writeTemp(t, "theirs.html", []byte(`<!doctype html><html lang="en"><head><title>Theirs</title></head>`+
		`<body><main><h1>Somebody else's markup</h1></main></body></html>`))
	t.Setenv("QUILZO_TOKEN", secrets["ann"])
	_, err := humanOutput(t, func() error {
		return cmdTemplate(root, []string{"adopt", theirs, "--as", "page", "--force", "--dir", tpl})
	})
	if err == nil || !strings.Contains(err.Error(), "publish") {
		t.Errorf("an author replaced page.html by adopting over it: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(tpl, "page.html")); string(b) != mine {
		t.Error("page.html was replaced by an author")
	}
	// A layout of its own, which no page renders through yet, is theirs.
	if _, err := humanOutput(t, func() error {
		return cmdTemplate(root, []string{"adopt", theirs, "--as", "theirs", "--dir", tpl})
	}); err != nil {
		t.Errorf("an author adopting a new layout: %v", err)
	}
	t.Setenv("QUILZO_TOKEN", secrets["pat"])
	if _, err := humanOutput(t, func() error {
		return cmdTemplate(root, []string{"adopt", theirs, "--as", "page", "--force", "--dir", tpl})
	}); err != nil {
		t.Errorf("a publisher replacing page.html: %v", err)
	}
}
