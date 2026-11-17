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
	"github.com/quilzo/quilzo/internal/saml"
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

// People gives no link alone for an administrator who has signed in, as
// the command line gives none: whose token the other administrator
// revoked, or who signs in through the identity provider and holds nothing
// here. Taken for somebody with no way in yet, their sign-in was the other
// administrator's to give herself, and with it she approved her own
// requests as them.
func TestPeopleGivesNoLinkAloneForAnAdministratorWhoHasSignedIn(t *testing.T) {
	for name, second := range map[string]func(t *testing.T, srv *Server) string{
		"whose token the other revoked": func(t *testing.T, srv *Server) string {
			secret, tok, err := srv.Tokens.Issue("lee-cli", "lee", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := srv.Tokens.Authenticate(secret, time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := srv.Tokens.Revoke(tok.ID); err != nil {
				t.Fatal(err)
			}
			return "lee"
		},
		"who signs in through SAML": func(t *testing.T, srv *Server) string {
			srv.SAML = &SAMLAdmin{Providers: func() ([]saml.Config, error) {
				return []saml.Config{{Name: "corp", Domains: []string{"northwind.example"}}}, nil
			}}
			return "lee@northwind.example"
		},
		"who signs in through OpenID Connect": func(t *testing.T, srv *Server) string {
			srv.OIDC = &OIDC{Claim: "email"}
			return "lee@northwind.example"
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv, editor := setup(t)
			srv.Enrol = &enrol.Store{Path: filepath.Join(t.TempDir(), "enrolments.json")}
			who := second(t, srv)
			if err := srv.Policy.Grant(auth.Binding{Principal: who, Role: auth.RoleAdmin, Resource: "/",
				GrantedAt: time.Now().Add(-time.Hour).Unix()}); err != nil {
				t.Fatal(err)
			}
			postForm(t, srv, "/people/enrol", editor, url.Values{"principal": {who}}.Encode())
			if links, _ := srv.Enrol.Waiting(time.Now()); len(links) != 0 {
				t.Fatalf("a link that signs in as %s was given on one administrator's word: %+v", who, links)
			}
			if pend, _ := srv.Dual.Store.Pending(time.Now()); len(pend) != 1 {
				t.Fatalf("the link for %s does not wait for them: %+v", who, pend)
			}
		})
	}
}
