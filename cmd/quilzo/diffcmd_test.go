// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// quilzo diff and the agent interface's diff named the pages that changed
// and said "modified", and nothing of what changed in them, so whoever was
// to approve a change had no surface that showed it. Each now says the
// fields, before and after.
func TestDiffShowsWhatChangedInsideAPage(t *testing.T) {
	root := demoStore(t)
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	ret := pages["returns"].(map[string]any)
	ret["body"] = "Fourteen days, unused.\n\nMade-to-order items can be cancelled until they are cut."
	ret["title"] = "Returns policy"
	if _, err := site.SaveDraft(s, pages, "an edit", "test"); err != nil {
		t.Fatal(err)
	}

	_, done := captureStdout(t)
	err = cmdDiff(root)
	printed := done()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"returns", "title", "Returns policy", "+ Fourteen days, unused.", "- Thirty days"} {
		if !strings.Contains(printed, want) {
			t.Errorf("quilzo diff does not say %q:\n%s", want, printed)
		}
	}

	srv := buildMCP(root, s, asAdmin("rae"), t.TempDir())
	text, merr := callTool(t, srv, "quilzo_read", "diff", nil)
	if merr != nil {
		t.Fatal(merr.Message)
	}
	for _, want := range []string{"modified returns", "Returns policy", "+ Fourteen days, unused."} {
		if !strings.Contains(text, want) {
			t.Errorf("the agent interface's diff does not say %q:\n%s", want, text)
		}
	}
}

// quilzo diff shows the pages its caller may read, as the agent interface's
// diff does. A reader may run it, and it named every changed page; now that
// it shows what changed inside each, a reader denied redundancy-plan was
// shown the words of that page, before and after, by the command its deny
// was meant to hold against.
func TestDiffShowsOnlyThePagesItsCallerMayRead(t *testing.T) {
	root, secrets := storeWithTokenFor(t, auth.Binding{Principal: "rae", Role: auth.RoleReader, Resource: "/"})
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		return p.Grant(auth.Binding{Principal: "rae", Role: auth.RoleReader, Resource: "/redundancy-plan", Deny: true})
	}); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index":           map[string]any{"title": "Home"},
		"redundancy-plan": map[string]any{"title": "Who goes", "body": "Nobody yet."},
	}, "test", "dana"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index":           map[string]any{"title": "Home, again"},
		"redundancy-plan": map[string]any{"title": "Who goes", "body": "Tell the night shift last."},
	}, "test", "dana"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", secrets["rae"])
	if err := authoriseCommand(root, "diff", nil); err != nil {
		t.Fatalf("a reader may not run diff: %v", err)
	}

	_, done := captureStdout(t)
	err = cmdDiff(root)
	human := done()
	if err != nil {
		t.Fatal(err)
	}
	var asJSON strings.Builder
	old := w
	w = &out.Writer{Mode: out.JSON, Out: &asJSON, Err: io.Discard}
	err = cmdDiff(root)
	w = old
	if err != nil {
		t.Fatal(err)
	}
	for how, got := range map[string]string{"quilzo diff": human, "quilzo --json diff": asJSON.String()} {
		if strings.Contains(got, "redundancy") || strings.Contains(got, "night shift") || strings.Contains(got, "Nobody yet") {
			t.Errorf("%s showed the page out of reach:\n%s", how, got)
		}
		if !strings.Contains(got, "index") || !strings.Contains(got, "Home, again") {
			t.Errorf("%s left out the page the reader may read:\n%s", how, got)
		}
	}
	if !strings.Contains(human, "1 change(s)") {
		t.Errorf("quilzo diff counts a change it does not show:\n%s", human)
	}
}
