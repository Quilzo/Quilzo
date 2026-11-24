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

// People gives the link alone for an administrator whose only token could
// not approve it, as the command line does: an author with a token, made
// an administrator, held nothing that decides a request, and the link that
// would add their passkey waited for them.
func TestPeopleGivesAnAdministratorWhoseTokenCannotApproveTheirFirstLink(t *testing.T) {
	srv, editor := setup(t)
	srv.Enrol = &enrol.Store{Path: filepath.Join(t.TempDir(), "enrolments.json")}
	secret, _, err := srv.Tokens.Issue("theo-cli", "theo", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Tokens.Authenticate(secret, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := srv.Policy.Grant(auth.Binding{Principal: "theo", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	postForm(t, srv, "/people/enrol", editor, url.Values{"principal": {"theo"}}.Encode())
	if pend, _ := srv.Dual.Store.Pending(time.Now()); len(pend) != 0 {
		t.Fatalf("theo's passkey waits for theo, whose token cannot approve it: %+v", pend)
	}
	if links, _ := srv.Enrol.Waiting(time.Now()); len(links) != 1 || links[0].Principal != "theo" {
		t.Fatalf("no link for theo: %+v", links)
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

// What a token or a session is shown with is what it can be used as
// somewhere it reaches, not only on the path it names: an analyst's
// session, which administers /@security, was shown as a reader's because
// they read the rest of the site, and a token is not shown with a grant
// that has ended.
func TestATokenIsShownWithWhatItsHolderHoldsWithinIt(t *testing.T) {
	srv, _ := setup(t)
	for _, b := range []auth.Binding{
		{Principal: "ana", Role: auth.RoleReader, Resource: "/"},
		{Principal: "ana", Role: auth.RoleAdmin, Resource: auth.AreaSecurity},
		{Principal: "kim", Role: auth.RoleAuthor, Resource: "/"},
		{Principal: "kim", Role: auth.RolePublisher, Resource: "/blog"},
		{Principal: "tam", Role: auth.RoleReader, Resource: "/"},
		{Principal: "tam", Role: auth.RolePublisher, Resource: "/blog", Expires: time.Now().Add(-time.Hour).Unix()},
	} {
		if err := srv.Policy.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		who      string
		role     auth.Role
		resource string
		want     auth.Role
	}{
		{"ana", auth.RoleAdmin, "/", auth.RoleAdmin},
		{"kim", auth.RolePublisher, "/", auth.RolePublisher},
		{"kim", auth.RoleAdmin, "/", auth.RolePublisher},
		{"kim", auth.RolePublisher, "/news", auth.RoleAuthor},
		{"tam", auth.RolePublisher, "/", auth.RoleReader},
	} {
		if got := srv.carries(auth.Token{Principal: c.who, Role: c.role, Resource: c.resource}); got != c.want {
			t.Errorf("%s's %s token on %s is shown as %s, not %s", c.who, c.role, c.resource, got, c.want)
		}
	}
}
