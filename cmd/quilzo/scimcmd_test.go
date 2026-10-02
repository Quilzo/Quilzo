// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/scim"
)

type scimClient struct {
	t     *testing.T
	h     *scim.Handler
	token string
}

func (c scimClient) do(method, path, body string) (int, map[string]any) {
	c.t.Helper()
	req := httptest.NewRequest(method, "/scim/v2"+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/scim+json")
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func newSCIM(t *testing.T) (string, scimClient) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := demoStore(t)
	if err := cmdAuth(root, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	token, err := newSCIMToken(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range [][2]string{{"Security team", "analyst"}, {"Editors", "publisher"}} {
		if err := cmdSCIM(root, []string{"map", m[0], m[1]}); err != nil {
			t.Fatal(err)
		}
	}
	return root, scimClient{t: t, h: scimHandler(root), token: token}
}

func sessionFor(t *testing.T, root, who string) string {
	t.Helper()
	ts, _ := loadTokens(root)
	secret, _, err := ts.Issue("laptop", who, auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	return secret
}

func works(root, secret string) bool {
	ts, _ := loadTokens(root)
	_, err := ts.Authenticate(secret, time.Now())
	return err == nil
}

// The person who leaves: grants from groups, a grant made by hand, and a
// session. Deactivation ends all three; reactivation gives the first two
// back and leaves the session ended.
func TestDeactivationSuspendsSomebodyWhateverTheyWereGranted(t *testing.T) {
	root, c := newSCIM(t)
	if err := cmdAuth(root, []string{"grant", "ada@example.com", "author", "--on", "/blog"}); err != nil {
		t.Fatal(err)
	}
	_, u := c.do(http.MethodPost, "/Users", `{"userName":"ada@example.com","active":true}`)
	id := u["id"].(string)
	c.do(http.MethodPost, "/Groups", `{"displayName":"Security team","members":[{"value":"`+id+`"}]}`)

	p, _ := loadPolicy(root)
	if !p.Evaluate("ada@example.com", auth.ActGrant, auth.AreaSecurity).Allowed {
		t.Fatalf("the mapped group did not grant its job: %+v", p.Bindings)
	}
	session := sessionFor(t, root, "ada@example.com")

	c.do(http.MethodPatch, "/Users/"+id, `{"Operations":[{"op":"replace","value":{"active":false}}]}`)
	p, _ = loadPolicy(root)
	for _, where := range []string{auth.AreaSecurity, "/blog", "/"} {
		if p.Evaluate("ada@example.com", auth.ActView, where).Allowed {
			t.Errorf("deactivated, they can still see %s", where)
		}
	}
	if works(root, session) {
		t.Error("deactivated, their session still works")
	}
	hand := false
	for _, b := range p.Bindings {
		if b.Principal == "ada@example.com" && b.Resource == "/blog" && b.GrantedBy != scimBy {
			hand = true
		}
	}
	if !hand {
		t.Error("the grant made by hand was removed rather than outranked")
	}

	c.do(http.MethodPatch, "/Users/"+id, `{"Operations":[{"op":"replace","value":{"active":true}}]}`)
	p, _ = loadPolicy(root)
	if !p.Evaluate("ada@example.com", auth.ActEditDraft, "/blog").Allowed ||
		!p.Evaluate("ada@example.com", auth.ActView, auth.AreaSecurity).Allowed {
		t.Errorf("reactivated, they did not get their access back: %+v", p.Bindings)
	}
	if works(root, session) {
		t.Error("reactivation brought an ended session back")
	}
}

// Only provisioning's own grants move with the groups. Somebody who keeps a
// hand-made grant keeps their session; somebody left with nothing does not.
func TestLeavingAGroupWithdrawsOnlyWhatItGave(t *testing.T) {
	root, c := newSCIM(t)
	if err := cmdAuth(root, []string{"grant", "bo@example.com", "reader"}); err != nil {
		t.Fatal(err)
	}
	_, bo := c.do(http.MethodPost, "/Users", `{"userName":"bo@example.com"}`)
	_, cy := c.do(http.MethodPost, "/Users", `{"userName":"cy@example.com"}`)
	_, g := c.do(http.MethodPost, "/Groups", `{"displayName":"Editors","members":[{"value":"`+bo["id"].(string)+`"},{"value":"`+cy["id"].(string)+`"}]}`)
	boSession, cySession := sessionFor(t, root, "bo@example.com"), sessionFor(t, root, "cy@example.com")
	// Nothing changed: nothing is rewritten, so no grant's date moves.
	before, _ := loadPolicy(root)
	for i := range before.Bindings {
		before.Bindings[i].GrantedAt = 1000
	}
	_ = saveJSON(policyPath(root), before)
	if err := cmdSCIM(root, []string{"map", "Editors", "publisher"}); err != nil {
		t.Fatal(err)
	}
	again, _ := loadPolicy(root)
	if !again.Evaluate("bo@example.com", auth.ActPublish, "/").Allowed {
		t.Fatalf("re-applying the same mapping withdrew it: %+v", again.Bindings)
	}
	for _, b := range again.Bindings {
		if b.GrantedAt != 1000 {
			t.Errorf("re-applying the same mapping remade %+v", b)
		}
	}

	c.do(http.MethodPatch, "/Groups/"+g["id"].(string), `{"Operations":[{"op":"replace","path":"members","value":[]}]}`)
	p, _ := loadPolicy(root)
	if p.Evaluate("bo@example.com", auth.ActPublish, "/").Allowed {
		t.Error("out of the group, bo can still publish")
	}
	if !p.Evaluate("bo@example.com", auth.ActView, "/").Allowed || !works(root, boSession) {
		t.Error("bo lost the reader grant made by hand, or the session it keeps")
	}
	if p.Evaluate("cy@example.com", auth.ActView, "/").Allowed || works(root, cySession) {
		t.Error("cy holds nothing and still has access or a session")
	}
}

// Deleting somebody suspends every spelling of their name, because the
// policy compares names exactly and the identity provider does not.
func TestDeletingSomebodySuspendsEverySpellingOfThem(t *testing.T) {
	root, c := newSCIM(t)
	if err := cmdAuth(root, []string{"grant", "Dee@Example.com", "admin"}); err != nil {
		t.Fatal(err)
	}
	_, u := c.do(http.MethodPost, "/Users", `{"userName":"dee@example.com"}`)
	if code, _ := c.do(http.MethodDelete, "/Users/"+u["id"].(string), ""); code != http.StatusNoContent {
		t.Fatalf("deleting answered %d", code)
	}
	p, _ := loadPolicy(root)
	if p.Evaluate("Dee@Example.com", auth.ActView, "/").Allowed {
		t.Error("the hand-granted spelling of a deleted person still works")
	}
	if !p.Evaluate("boss", auth.ActGrant, "/").Allowed {
		t.Error("somebody else was suspended")
	}
}

// What a group may mean is checked, and the token is the only way in.
func TestProvisioningRefusesBadMappingsAndOtherTokens(t *testing.T) {
	root, c := newSCIM(t)
	for _, to := range []string{"owner", "", "ANALYST "} {
		if err := cmdSCIM(root, []string{"map", "X", to}); err == nil {
			t.Errorf("a group was mapped to %q", to)
		}
	}
	bad := c
	bad.token = "qzscim_not-it"
	if code, _ := bad.do(http.MethodGet, "/Users", ""); code != http.StatusUnauthorized {
		t.Errorf("a wrong token answered %d", code)
	}
	// A session token of an administrator is not a provisioning token.
	bad.token = sessionFor(t, root, "boss")
	if code, _ := bad.do(http.MethodGet, "/Users", ""); code != http.StatusUnauthorized {
		t.Errorf("an admin's own token answered %d", code)
	}
	if err := cmdSCIM(root, []string{"token", "--revoke"}); err != nil {
		t.Fatal(err)
	}
	if code, _ := c.do(http.MethodGet, "/Users", ""); code != http.StatusUnauthorized {
		t.Errorf("a revoked token answered %d", code)
	}
}

// A grant somebody already holds by hand is not made twice, and does not
// stop the rest of what provisioning gives them.
func TestAGrantAlreadyHeldByHandIsNotAnError(t *testing.T) {
	root, c := newSCIM(t)
	if err := cmdAuth(root, []string{"grant", "eve@example.com", "analyst"}); err != nil {
		t.Fatal(err)
	}
	_, u := c.do(http.MethodPost, "/Users", `{"userName":"eve@example.com"}`)
	for _, g := range []string{"Security team", "Editors"} {
		c.do(http.MethodPost, "/Groups", `{"displayName":"`+g+`","members":[{"value":"`+u["id"].(string)+`"}]}`)
	}
	p, _ := loadPolicy(root)
	if !p.Evaluate("eve@example.com", auth.ActPublish, "/").Allowed {
		t.Errorf("the hand-made analyst grant stopped the publisher one: %+v", p.Bindings)
	}
}
