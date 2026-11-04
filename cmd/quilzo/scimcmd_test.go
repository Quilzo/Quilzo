// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mail"
	"github.com/quilzo/quilzo/internal/memory"
	"github.com/quilzo/quilzo/internal/oauthas"
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
	// Mapped as a store is set up, before it has an administrator: a group
	// that makes administrators waits for a second one once there is a
	// first (TestMappingAGroupToAdministratorTakesTwo).
	for _, m := range [][2]string{{"Security team", "analyst"}, {"Editors", "publisher"}} {
		if err := cmdSCIM(root, []string{"map", m[0], m[1]}); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmdAuth(root, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	token, _, err := newSCIMToken(root, scimTokenDays)
	if err != nil {
		t.Fatal(err)
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

// writeGrants puts app connections in the store, as the consent screen
// would have.
func writeGrants(t *testing.T, root string, gs ...oauthas.Grant) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"grants": gs})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(oauthDir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oauthDir(root), "grants.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// An app somebody connected is connected to nobody once the identity
// provider suspends them: the connection ends with its tokens, and a
// refresh from before is refused because they no longer stand here.
func TestSuspensionEndsTheAppsSomebodyConnected(t *testing.T) {
	root, c := newSCIM(t)
	_, u := c.do(http.MethodPost, "/Users", `{"userName":"ada@example.com","active":true}`)
	id := u["id"].(string)
	c.do(http.MethodPost, "/Groups", `{"displayName":"Editors","members":[{"value":"`+id+`"}]}`)

	const res = "https://admin.example.org/mcp"
	now := time.Now()
	hers := oauthas.Grant{ID: "gr_00000000000000aa", Principal: "ada@example.com", Client: "https://app.example.com/meta",
		Resource: res, Created: now, Expires: now.Add(24 * time.Hour)}
	his := oauthas.Grant{ID: "gr_00000000000000bb", Principal: "boss", Client: "https://app.example.com/meta",
		Resource: res, Created: now, Expires: now.Add(24 * time.Hour)}
	writeGrants(t, root, hers, his)
	ts, _ := loadTokens(root)
	secret, _, err := ts.IssueForGrant(hers.Principal, auth.RolePublisher, auth.Scope{}, hers.Client, hers.ID, res, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	admit := admitGrant(root, nil)
	if err := admit(hers, now); err != nil {
		t.Fatalf("before the suspension her app was refused: %v", err)
	}

	c.do(http.MethodPatch, "/Users/"+id, `{"Operations":[{"op":"replace","value":{"active":false}}]}`)

	grants, err := (&oauthas.Store{Dir: oauthDir(root)}).Grants()
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range grants {
		switch g.ID {
		case hers.ID:
			if g.Live(now) || !strings.Contains(g.EndedWhy, "identity provider") || g.EndedBy != scimBy {
				t.Errorf("her connection: %+v", g)
			}
		case his.ID:
			if !g.Live(now) {
				t.Errorf("somebody else's connection ended with hers: %+v", g)
			}
		}
	}
	ts, _ = loadTokens(root)
	if _, err := ts.AuthenticateFor(secret, res, now); err == nil {
		t.Error("her app's access token still works")
	}
	if err := admit(hers, now); err == nil || !strings.Contains(err.Error(), "no longer has access") {
		t.Errorf("a refresh for somebody suspended: %v", err)
	}
	evs, _ := audit.Read(auditPath(root))
	found := false
	for _, e := range evs {
		if e.Action == "oauth.disconnected" && e.Detail["grant"] == hers.ID {
			found = true
		}
	}
	if !found {
		t.Error("ending her connection was not recorded")
	}
}

// Deleted by the identity provider, somebody is no longer anybody here, and
// no agent remembers them; suspended, they may come back, and it waits.
func TestDeletionByTheIdentityProviderErasesWhatAgentsRemember(t *testing.T) {
	root, c := newSCIM(t)
	_, u := c.do(http.MethodPost, "/Users", `{"userName":"ada@example.com","active":true}`)
	id := u["id"].(string)
	c.do(http.MethodPost, "/Groups", `{"displayName":"Editors","members":[{"value":"`+id+`"}]}`)
	if _, err := memoryStore(root).Remember(memory.Entry{Agent: "helper", About: "ada@example.com", Kind: memory.Semantic,
		Text: "Ada works Tuesdays", Run: "r", By: "ada@example.com"}, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	c.do(http.MethodPatch, "/Users/"+id, `{"Operations":[{"op":"replace","value":{"active":false}}]}`)
	if left, _ := memoryStore(root).List(memory.Filter{About: "ada@example.com"}); len(left) != 1 {
		t.Fatal("a suspension erased her memory")
	}
	if code, _ := c.do(http.MethodDelete, "/Users/"+id, ""); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if left, _ := memoryStore(root).List(memory.Filter{About: "ada@example.com"}); len(left) != 0 {
		t.Fatal("a deleted person is still remembered")
	}
}

// scimSecurityMail sets up the security contact and catches what it is
// sent.
func scimSecurityMail(t *testing.T, root string) func() []mail.Message {
	t.Helper()
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("security.contact", "mailto:security@example.com", "", "boss@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mailConfigPath(root), []byte(`{"host":"relay.example:587","from":"quilzo@example.com"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var sent []mail.Message
	old := deliverMail
	deliverMail = func(_ *mail.Mailer, m mail.Message) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, m)
		return nil
	}
	t.Cleanup(func() { deliverMail = old })
	// Registered last, so it runs first: a message still being sent
	// finishes before deliverMail is put back.
	t.Cleanup(func() { finishBackground(10 * time.Second) })
	return func() []mail.Message {
		finishBackground(10 * time.Second)
		mu.Lock()
		defer mu.Unlock()
		return append([]mail.Message(nil), sent...)
	}
}

// The identity provider deactivating every administrator leaves one who
// can grant access, by the rule the Shared Signals receiver keeps: the last
// of them is not denied and keeps what provisioning gave them, their
// sessions end, the refusal is recorded as a failure, and the security
// contact is told. Each was denied in turn, by whoever held the
// provisioning token or a provider set up wrong, and the store's only way
// back was editing the policy by hand.
func TestDeactivatingEveryAdministratorLeavesOneWhoCanGrant(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := demoStore(t)
	if err := cmdSCIM(root, []string{"map", "Admins", "admin"}); err != nil {
		t.Fatal(err)
	}
	mails := scimSecurityMail(t, root)
	token, _, err := newSCIMToken(root, scimTokenDays)
	if err != nil {
		t.Fatal(err)
	}
	c := scimClient{t: t, h: scimHandler(root), token: token}
	var ids []string
	for _, who := range []string{"boss@example.com", "dana@example.com"} {
		_, u := c.do(http.MethodPost, "/Users", `{"userName":"`+who+`","active":true}`)
		ids = append(ids, u["id"].(string))
	}
	c.do(http.MethodPost, "/Groups", `{"displayName":"Admins","members":[{"value":"`+ids[0]+`"},{"value":"`+ids[1]+`"}]}`)
	p, _ := loadPolicy(root)
	for _, who := range []string{"boss@example.com", "dana@example.com"} {
		if !p.Evaluate(who, auth.ActGrant, "/").Allowed {
			t.Fatalf("%s was not made an administrator: %+v", who, p.Bindings)
		}
	}
	sso := session(t, root, "oidc:dana@example.com", "dana@example.com", auth.MethodSSO)
	laptop := session(t, root, "laptop", "dana@example.com", "")

	for _, id := range ids {
		if code, _ := c.do(http.MethodPatch, "/Users/"+id, `{"Operations":[{"op":"replace","value":{"active":false}}]}`); code != http.StatusOK {
			t.Fatalf("deactivating answered %d", code)
		}
	}
	p, _ = loadPolicy(root)
	if p.Evaluate("boss@example.com", auth.ActView, "/").Allowed {
		t.Error("the first administrator deactivated was not suspended")
	}
	if !p.Evaluate("dana@example.com", auth.ActGrant, "/").Allowed {
		t.Fatalf("every administrator was suspended, and nobody can grant access: %+v", p.Bindings)
	}
	if works(root, sso) {
		t.Error("the last administrator's session still works")
	}
	if !works(root, laptop) {
		t.Error("the last administrator's long-lived token was revoked, which could leave nobody able to get in")
	}
	sent := mails()
	if len(sent) != 1 || !strings.Contains(sent[0].Body, "only person who can grant access") ||
		!strings.Contains(sent[0].Body, "dana@example.com") {
		t.Errorf("mailed %+v", sent)
	}
	evs, _ := audit.Read(auditPath(root))
	var refused []audit.Event
	for _, e := range evs {
		if e.Action == "scim.suspended" {
			refused = append(refused, e)
		}
	}
	if len(refused) != 1 || refused[0].Outcome != audit.Failure || refused[0].Detail["count"] != "1" {
		t.Errorf("recorded %+v", refused)
	}

	// Deleted rather than deactivated, the same: a deny for nobody, and
	// nothing more to tell than the deactivation did.
	if code, _ := c.do(http.MethodDelete, "/Users/"+ids[1], ""); code != http.StatusNoContent {
		t.Fatalf("deleting answered %d", code)
	}
	p, _ = loadPolicy(root)
	if !p.Evaluate("dana@example.com", auth.ActGrant, "/").Allowed {
		t.Fatal("deleted, the last administrator was suspended")
	}
	if sent := mails(); len(sent) != 2 {
		t.Errorf("the deletion mailed %d times in all", len(sent))
	}
}
