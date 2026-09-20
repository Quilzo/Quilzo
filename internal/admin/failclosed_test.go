// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/site"
)

// A gate that cannot run refuses, rather than exiting like a gate that passed.
//
// Both of these came back as an empty slice on every error — an unreadable
// provenance index, a draft that would not read, a page that would not
// assemble, a template that would not render. An empty slice reads to the
// caller as "nothing is wrong", so the publish handler reported zero blocking
// failures and zero unmarked pages over content it had never looked at, wrote
// an audit entry affirming a clean publish, and put it up.
//
// Corrupting the provenance index was therefore the way to publish unmarked
// AI content through the browser, which is the one surface an editor uses and
// the one most likely to be publishing what an assistant wrote.
//
// The command line has refused on a gate error for as long as somebody has
// been looking, and says why: "publishing would claim a check that did not
// happen".
func TestAGateThatCannotRunRefusesTheBrowserToo(t *testing.T) {
	t.Run("provenance", func(t *testing.T) {
		srv, token := setup(t)
		srv.LoadProvenance = func() (*provenance.Index, error) {
			return nil, errors.New("provenance.json is not valid JSON")
		}

		w := postForm(t, srv, "/publish", token, "reason=anything at all")
		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("publishing with an unreadable provenance index answered "+
				"%d, want 422. Corrupting that file is then the way to "+
				"publish unmarked content", w.Code)
		}
		if !strings.Contains(w.Body.String(), "could not run") {
			t.Error("the refusal does not say the check could not run, so it " +
				"reads as a finding somebody could argue with")
		}
	})

	t.Run("accessibility", func(t *testing.T) {
		srv, _ := setup(t)
		// A page asking for a layout this site has not got. It renders to
		// nothing for a reader, and used to contribute nothing to the count.
		pages, err := site.PagesAt(srv.Store, site.RefDraft)
		if err != nil {
			t.Fatal(err)
		}
		pages["broken"] = map[string]any{
			"title": "Broken", "body": "x", "layout": "not-a-layout"}
		if _, err := site.SaveDraft(srv.Store, pages, "add a broken layout",
			"test"); err != nil {
			t.Fatal(err)
		}

		reports, err := srv.checkAll(srv.Store.GetRef(site.RefDraft))
		if err != nil {
			t.Fatalf("the check errored rather than reporting the page: %v", err)
		}
		found := false
		for _, r := range reports {
			for _, f := range r.Findings {
				if f.Rule == "layout-not-found" {
					found = true
				}
			}
		}
		if !found {
			t.Error("a page naming a layout this site has not got produced no " +
				"finding. It renders to nothing for a reader, and the comment " +
				"here said it was reported as a blocking finding while the " +
				"code skipped it")
		}
	})
}

// A server with no template directory is not a failed check.
//
// It is a store that renders somewhere else, which the command line treats as
// the one legitimate reason to turn this gate off. Refusing here would leave
// that deployment with no way to publish at all.
func TestAServerWithNoLayoutsStillPublishes(t *testing.T) {
	srv, token := setup(t)
	srv.Layouts = render.Layouts{}

	w := postForm(t, srv, "/publish", token, "reason=nothing renders here")
	if w.Code != http.StatusOK {
		t.Errorf("publishing from a server with no templates answered %d; a "+
			"store that renders elsewhere has no way to publish at all", w.Code)
	}
}
