// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/scim"
)

type scimCalls struct {
	mapped, unmapped, by string
	tokens, revoked      int
}

func wireSCIM(t *testing.T, srv *Server) (*scimCalls, *scim.Store) {
	t.Helper()
	calls := &scimCalls{}
	st := &scim.Store{Path: filepath.Join(t.TempDir(), "scim.json")}
	srv.SCIM = &SCIMAdmin{
		Handler: &scim.Handler{Store: st, Authenticate: func(tok string) bool { return tok == "qzscim_right" }},
		Status: func() (bool, *scim.State, error) {
			s, err := st.Load()
			return calls.tokens > calls.revoked, s, err
		},
		Map: func(group, to, by string) error {
			calls.mapped, calls.by = group+"="+to, by
			return st.Update(func(s *scim.State) error { s.Mapping[group] = to; return nil })
		},
		Unmap:       func(group, by string) error { calls.unmapped, calls.by = group, by; return nil },
		NewToken:    func(by string) (string, error) { calls.tokens++; return "qzscim_shown-once", nil },
		RevokeToken: func(by string) error { calls.revoked++; return nil },
	}
	return calls, st
}

func TestTheProvisioningScreenMapsGroupsAndShowsTheTokenOnce(t *testing.T) {
	srv, token := setup(t)
	calls, st := wireSCIM(t, srv)
	_ = st.Update(func(s *scim.State) error {
		s.Users = append(s.Users, scim.User{ID: "u1", UserName: "ada@example.com", Active: true})
		s.Groups = append(s.Groups, scim.Group{ID: "g1", DisplayName: "<b>Ops</b>", Members: []string{"u1"}})
		return nil
	})
	body := get(t, srv, "/provisioning", token).Body.String()
	if !strings.Contains(body, "No token is set") || !strings.Contains(body, "&lt;b&gt;Ops&lt;/b&gt;") ||
		!strings.Contains(body, "ada@example.com") {
		t.Fatalf("the screen does not show the state, escaped:\n%s", body)
	}

	w := postForm(t, srv, "/provisioning/act", token, "do=token")
	if !strings.Contains(w.Body.String(), "qzscim_shown-once") {
		t.Fatal("a new token is not shown")
	}
	if strings.Contains(get(t, srv, "/provisioning", token).Body.String(), "qzscim_shown-once") {
		t.Error("the token is shown again")
	}

	postForm(t, srv, "/provisioning/act", token, "do=map&group=%3Cb%3EOps%3C%2Fb%3E&to=analyst")
	if calls.mapped != "<b>Ops</b>=analyst" || calls.by == "" {
		t.Errorf("mapping called %+v", calls)
	}
	if got := get(t, srv, "/provisioning", token).Body.String(); !strings.Contains(got, "analyst") {
		t.Error("the mapping is not shown")
	}
	postForm(t, srv, "/provisioning/act", token, "do=unmap&group=Ops")
	postForm(t, srv, "/provisioning/act", token, "do=revoke")
	if calls.unmapped != "Ops" || calls.revoked != 1 {
		t.Errorf("unmap or revoke did not reach provisioning: %+v", calls)
	}
}

// Deciding what a group means is deciding who is an administrator.
func TestOnlyAnAdministratorProvisions(t *testing.T) {
	for _, role := range []auth.Role{auth.RoleReader, auth.RoleAuthor, auth.RolePublisher} {
		srv, token := asRole(t, role)
		calls, _ := wireSCIM(t, srv)
		if code := get(t, srv, "/provisioning", token).Code; code != http.StatusForbidden {
			t.Errorf("a %s opened the screen: %d", role, code)
		}
		for _, form := range []string{"do=map&group=G&to=admin", "do=token", "do=revoke"} {
			postForm(t, srv, "/provisioning/act", token, form)
		}
		if calls.mapped != "" || calls.tokens != 0 || calls.revoked != 0 {
			t.Errorf("a %s changed provisioning: %+v", role, calls)
		}
	}
}

// The identity provider is a server, not a browser: no Origin, no
// Sec-Fetch-Site, its own token. The admin's defences for browsers let it
// through, and its own check refuses anything else.
func TestTheIdentityProviderReachesTheEndpointThroughTheAdmin(t *testing.T) {
	srv, token := setup(t)
	wireSCIM(t, srv)
	call := func(bearer, method, body string) int {
		req := httptest.NewRequest(method, "/scim/v2/Users", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("Content-Type", "application/scim+json")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w.Code
	}
	if code := call("qzscim_right", http.MethodPost, `{"userName":"ada@example.com"}`); code != http.StatusCreated {
		t.Errorf("the provider could not create a user: %d", code)
	}
	if code := call(token, http.MethodGet, ""); code != http.StatusUnauthorized {
		t.Errorf("an administrator's token reached provisioning: %d", code)
	}
}

// On the Provisioning screen too, a group mapped to an administrator's role
// waits for a second administrator, who sees it on People and approves it.
func TestMappingAGroupToAdminOnTheScreenTakesTwo(t *testing.T) {
	srv, editor := setup(t)
	calls, _ := wireSCIM(t, srv)
	if err := srv.Policy.Grant(auth.Binding{Principal: "lee", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	lee, _, err := srv.Tokens.IssueSession("lee", "lee", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	w := postForm(t, srv, "/provisioning/act", editor, "do=map&group=Ops&to=admin")
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); !strings.Contains(loc, "waits for a second administrator") {
		t.Fatalf("mapping: %d %s", w.Code, loc)
	}
	if calls.mapped != "" {
		t.Fatalf("a group was made administrators on one administrator's word: %+v", calls)
	}
	postForm(t, srv, "/provisioning/act", editor, "do=map&group=Editors&to=publisher")
	if calls.mapped != "Editors=publisher" {
		t.Fatalf("a mapping to less waited: %+v", calls)
	}
	pend, _ := srv.Dual.Store.Pending(time.Now())
	if len(pend) != 1 || pend[0].Kind != dual.Mapping {
		t.Fatalf("pending: %+v", pend)
	}
	postForm(t, srv, "/people/pending", lee, url.Values{"id": {pend[0].ID}, "do": {"approve"}}.Encode())
	if calls.mapped != "Ops=admin" || calls.by != "lee" {
		t.Fatalf("approved, and provisioning was told %+v", calls)
	}
}

// While a group makes administrators, the provisioning token makes them:
// whoever holds it puts anybody in that group. So making one waits for a
// second administrator, as an administrator's token does, and is received
// by whoever asked. It did not: either of two administrators alone made
// the token and, through 'IT admins' mapped to admin, made mallory one.
func TestAProvisioningTokenThatMakesAdministratorsTakesTwoOnTheScreen(t *testing.T) {
	srv, editor := setup(t)
	calls, st := wireSCIM(t, srv)
	if err := st.Update(func(s *scim.State) error { s.Mapping["IT admins"] = "admin"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := srv.Policy.Grant(auth.Binding{Principal: "lee", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	lee, _, err := srv.Tokens.IssueSession("lee", "lee", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	w := postForm(t, srv, "/provisioning/act", editor, "do=token")
	if strings.Contains(w.Body.String(), "qzscim_shown-once") || calls.tokens != 0 {
		t.Fatal("one administrator made a provisioning token that makes administrators, with nobody agreeing")
	}
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); !strings.Contains(loc, "waits for a second administrator") {
		t.Fatalf("the token did not wait: %d %s", w.Code, loc)
	}
	pend, _ := srv.Dual.Store.Pending(time.Now())
	if len(pend) != 1 || pend[0].Kind != dual.SCIMToken {
		t.Fatalf("pending: %+v", pend)
	}
	id := pend[0].ID
	if w := postForm(t, srv, "/people/pending", editor, "do=receive&id="+id); strings.Contains(w.Body.String(), "qzscim_shown-once") {
		t.Fatal("the token was received before anybody approved it")
	}
	postForm(t, srv, "/people/pending", lee, "do=approve&id="+id)
	if calls.tokens != 0 {
		t.Fatal("approving made the token for nobody to receive")
	}
	if w := postForm(t, srv, "/people/pending", lee, "do=receive&id="+id); strings.Contains(w.Body.String(), "qzscim_shown-once") {
		t.Fatal("the approver received the token somebody else asked for")
	}
	if !strings.Contains(get(t, srv, "/people", editor).Body.String(), `value="receive"`) {
		t.Error("the People screen does not offer the approved token to the one who asked")
	}
	if w := postForm(t, srv, "/people/pending", editor, "do=receive&id="+id); !strings.Contains(w.Body.String(), "qzscim_shown-once") || calls.tokens != 1 {
		t.Fatalf("the one who asked did not receive it: %d, %d made", w.Code, calls.tokens)
	}
	if postForm(t, srv, "/people/pending", editor, "do=receive&id="+id); calls.tokens != 1 {
		t.Error("an approved token was received twice")
	}
}

// The People screen says what an approved request gives the one who asked.
// A provisioning token waiting to be received was offered with the
// enrolment link's words, "Receive the link", on a request that gives no
// link, and the hint over the list did not name it among the changes that
// take two administrators.
func TestAnApprovedProvisioningTokenIsOfferedAsAToken(t *testing.T) {
	srv, editor := setup(t)
	wireSCIM(t, srv)
	now := time.Now()
	r, err := srv.Dual.Store.Propose(dual.SCIMToken, "a new provisioning token", dual.SCIMTokenChange{}, "", "editor", false, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Dual.Store.Decide(r.ID, "lee", true, false, now); err != nil {
		t.Fatal(err)
	}
	body := get(t, srv, "/people", editor).Body.String()
	if !strings.Contains(body, `value="receive"`) {
		t.Fatal("control: the approved token is not offered to the one who asked")
	}
	if strings.Contains(body, "Receive the link") || !strings.Contains(body, "Receive the token") {
		t.Error("an approved provisioning token is not offered as a token")
	}
	if !strings.Contains(body, "the provisioning token") {
		t.Error("the hint does not name the provisioning token among what takes two administrators")
	}
}
