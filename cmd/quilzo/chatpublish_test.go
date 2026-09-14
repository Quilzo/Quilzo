// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/quilzo/quilzo/internal/demo"
	"github.com/quilzo/quilzo/internal/site"
)

// Publishing from a chat window publishes that page, not the whole draft.
//
// It published the draft. The draft ref is one ref for the whole store — this
// file says so, a few hundred lines below, about a different problem — and
// Save read it, added the chat user's page, committed, and made the whole
// thing live.
//
// So an operator with unpublished work sitting on the draft (an embargoed
// announcement, a half-finished price change) had all of it go public the
// moment any chat user tapped Publish on their own page: from a surface that
// cannot show them what else is in there, by somebody who has no idea it
// exists, and with no confirmation step anywhere in between.
//
// Publishing one page means live plus that page, and the draft is left alone.
func TestPublishingFromAChatWindowDoesNotPublishSomebodyElsesDraft(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}

	// A published site.
	live, err := site.SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home", "body": "Welcome.", "layout": "page"},
	}, "first", "operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, live); err != nil {
		t.Fatal(err)
	}

	// And an embargoed page the operator has not published.
	draft, err := site.SaveDraft(s, map[string]any{
		"index":  map[string]any{"title": "Home", "body": "Welcome.", "layout": "page"},
		"prices": map[string]any{"title": "New prices", "body": "Not yet.", "layout": "page"},
	}, "not yet", "operator")
	if err != nil {
		t.Fatal(err)
	}

	// The accessibility gate renders, so it needs somewhere to render from.
	tpl := t.TempDir()
	d := demo.Marginalia()
	for name, body := range map[string]string{
		"page.html": d.Template, "site.css": d.CSS,
	} {
		if werr := os.WriteFile(filepath.Join(tpl, name),
			[]byte(body), 0o600); werr != nil {
			t.Fatal(werr)
		}
	}
	// The template's header links the site's name, and a link with no text
	// fails the accessibility gate this publish runs.
	cfg, cerr := loadConfig(root)
	if cerr != nil {
		t.Fatal(cerr)
	}
	cfg.Set("site.name", "Test site", "for the test", "test")
	if serr := saveConfig(root, cfg); serr != nil {
		t.Fatal(serr)
	}

	// And the provenance gate, which this surface refuses on rather than
	// inventing an answer to. Marked here so the test is about the draft.
	if merr := markGenerated(root, s, "operator", "for the test"); merr != nil {
		t.Fatal(merr)
	}

	c := &chatPublisher{root: root, store: s, tplDir: tpl}
	if _, err := c.Save("tg4212", map[string]any{
		"title": "My page", "body": "Hello.", "layout": "page",
	}, "@somebody", "published from a chat", true); err != nil {
		t.Fatal(err)
	}

	livePages, err := site.PagesAt(s, site.RefLive)
	if err != nil {
		t.Fatal(err)
	}
	if _, leaked := livePages["prices"]; leaked {
		t.Error("a chat user publishing their own page put the operator's " +
			"unpublished draft live. They cannot see it, were not asked " +
			"about it, and it was embargoed")
	}
	if _, there := livePages["tg4212"]; !there {
		t.Error("the page the person actually asked to publish is not live")
	}
	if _, there := livePages["index"]; !there {
		t.Error("publishing one page removed the rest of the site")
	}

	// And the draft is where it was, so the operator's work is not disturbed.
	if now := s.GetRef(site.RefDraft); now != draft {
		t.Errorf("the draft ref moved from %s to %s; somebody else's work in "+
			"progress is not part of this act and must not be moved by it",
			draft[:12], now[:12])
	}
}
