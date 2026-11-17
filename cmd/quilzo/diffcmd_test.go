// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

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
