// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/url"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
)

// The last administrator is not denied from People either. The screen
// refused revoking your own last admin binding, and took a deny of it, or
// of the store's one other administrator's, as any other: nobody was left
// who could grant access to anybody.
func TestPeopleNeverDeniesTheLastAdministrator(t *testing.T) {
	srv, editor := setup(t)
	postForm(t, srv, "/people/grant", editor, url.Values{"principal": {"editor"}, "role": {"admin"},
		"resource": {"/"}, "deny": {"on"}}.Encode())
	if !srv.Policy.Evaluate("editor", auth.ActGrant, "/").Allowed {
		t.Fatal("the only administrator was denied admin from People")
	}
	postForm(t, srv, "/people/grant", editor, url.Values{"principal": {"editor"}, "role": {"reader"},
		"resource": {"/"}, "deny": {"on"}}.Encode())
	if !srv.Policy.Evaluate("editor", auth.ActGrant, "/").Allowed {
		t.Fatal("the only administrator was denied everything from People")
	}
}
