// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/enrol"
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

// An administrator granted before their passkey is given one from People,
// as from the command line: until they can sign in, the one administrator
// who can is the only one who could approve it. Once they can, a link for
// either waits for the other.
func TestPeopleGivesAnAdministratorWithNoWayInTheirFirstLink(t *testing.T) {
	srv, editor := setup(t)
	srv.Enrol = &enrol.Store{Path: filepath.Join(t.TempDir(), "enrolments.json")}
	if err := srv.Policy.Grant(auth.Binding{Principal: "theo", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	postForm(t, srv, "/people/enrol", editor, url.Values{"principal": {"theo"}}.Encode())
	if pend, _ := srv.Dual.Store.Pending(time.Now()); len(pend) != 0 {
		t.Fatalf("theo's first way in waits for theo: %+v", pend)
	}
	if links, _ := srv.Enrol.Waiting(time.Now()); len(links) != 1 || links[0].Principal != "theo" {
		t.Fatalf("no link for theo: %+v", links)
	}

	if _, _, err := srv.Tokens.IssueSession("theo", "theo", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin,
		auth.MethodPasskey); err != nil {
		t.Fatal(err)
	}
	postForm(t, srv, "/people/enrol", editor, url.Values{"principal": {"theo"}}.Encode())
	if pend, _ := srv.Dual.Store.Pending(time.Now()); len(pend) != 1 {
		t.Fatalf("a link for an administrator who can sign in did not wait: %+v", pend)
	}
}

// A token is shown on People and on a person's profile as it can be used,
// which is no more than its holder's role, as `quilzo token list` shows it.
func TestATokenIsShownWithNoMoreThanItsHoldersRole(t *testing.T) {
	srv, _ := setup(t)
	if err := srv.Policy.Grant(auth.Binding{Principal: "jun", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	if got := srv.carries(auth.Token{Principal: "jun", Role: auth.RolePublisher, Resource: "/"}); got != auth.RoleAuthor {
		t.Errorf("jun the author's publisher token is shown as %s", got)
	}
	if got := srv.carries(auth.Token{Principal: "jun", Role: auth.RoleReader, Resource: "/"}); got != auth.RoleReader {
		t.Errorf("a narrower token is shown as %s", got)
	}
}
