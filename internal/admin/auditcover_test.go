// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/site"
)

// A write through the browser is recorded, the same as a write from anywhere
// else.
//
// Three were not, and they were not the obscure ones. Saving a page is the
// most common write in the product and recorded nothing; rolling back moves
// what the public sees and recorded nothing; setting a provenance record —
// the assertion that later satisfies the Article 50 gate, so the one whose
// authorship somebody asking questions most needs — recorded nothing.
//
// Every other surface already did. `quilzo add` writes content.add, the agent
// interface writes mcp.write_page, the content API writes through OnWrite, a
// Telegram message writes telegram.publish. This interface recorded deleting a
// page, editing its sections and removing a selection of them, so the gap did
// not look like a policy — it looked like whichever handler somebody had in
// mind at the time.
//
// Driven rather than walked: what matters is that an entry comes out, not that
// a particular call appears in a particular function.
func TestEveryWriteThroughTheBrowserIsRecorded(t *testing.T) {
	for _, tc := range []struct {
		what, path, body, action string
	}{
		{"saving a page", "/save",
			"__name=index&__base=&title=Home&body=Edited", "content.save"},
		{"recording provenance", "/provenance/set",
			"page=index&source=humanEdits", "provenance.set"},
		{"deleting a page", "/page/delete", "name=about", "page.delete"},
	} {
		t.Run(tc.what, func(t *testing.T) {
			srv, token := setup(t)
			var got []string
			srv.Audit = func(action, resource string, _ map[string]string) {
				got = append(got, action+" "+resource)
			}

			w := postForm(t, srv, tc.path, token, tc.body)
			if w.Code >= 400 {
				t.Fatalf("%s answered %d: %s", tc.what, w.Code,
					strings.TrimSpace(w.Body.String())[:min(200, w.Body.Len())])
			}
			if !recorded(got, tc.action) {
				sort.Strings(got)
				t.Errorf("%s left no %q entry in the audit log; it recorded "+
					"%v. The same act from a script is recorded in full, so "+
					"the log is a record of who used which interface rather "+
					"than of what happened", tc.what, tc.action, got)
			}
		})
	}
}

// Rolling back is recorded. Separate because it needs something to roll back
// to, which means publishing first.
func TestRollingBackThroughTheBrowserIsRecorded(t *testing.T) {
	srv, token := setup(t)
	if w := postForm(t, srv, "/publish", token, "reason=a test needs something live"); w.Code != http.StatusOK {
		t.Fatalf("the first publish answered %d", w.Code)
	}
	live := srv.Store.GetRef(site.RefLive)
	if live == "" {
		t.Skip("nothing was published, so there is nothing to roll back to")
	}

	var got []string
	srv.Audit = func(action, resource string, _ map[string]string) {
		got = append(got, action+" "+resource)
	}
	if w := postForm(t, srv, "/rollback", token, "commit="+live); w.Code >= 400 {
		t.Fatalf("rollback answered %d", w.Code)
	}
	if !recorded(got, "rollback") {
		t.Errorf("rolling back left no entry; it recorded %v. `quilzo "+
			"rollback` records it, and this moves the same pointer", got)
	}
}

func recorded(entries []string, action string) bool {
	for _, e := range entries {
		if strings.HasPrefix(e, action+" ") {
			return true
		}
	}
	return false
}
