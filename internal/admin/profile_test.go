// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
)

// profileText is the profile page as somebody reads it: its words, with the
// template's line breaks and indentation run together.
func profileText(t *testing.T) string {
	t.Helper()
	srv, token := asRole(t, auth.RoleReader)
	w := get(t, srv, "/profile", token)
	if w.Code != 200 {
		t.Fatalf("the profile answered %d", w.Code)
	}
	return strings.Join(strings.Fields(w.Body.String()), " ")
}

// The profile does not offer a grant limited to content somebody created.
//
// "What you may do" said a grant "can be limited to a subtree or to content
// you created". Limiting to one's own content was withdrawn because nothing
// ever enforced it: the people screen marks such a binding "never enforced,
// ignored", and `quilzo auth grant --own-only` refuses. A page telling
// somebody their access may be narrower than it is was the whole problem.
func TestTheProfileOffersNoScopingToOwnContent(t *testing.T) {
	page := profileText(t)
	for _, offer := range []string{"content you created", "content they created", "your own content"} {
		if strings.Contains(page, offer) {
			t.Errorf("the profile says a grant can be limited to %q, which is withdrawn", offer)
		}
	}
}
