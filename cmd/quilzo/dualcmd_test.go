// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"maps"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/scim"
	"github.com/quilzo/quilzo/internal/shield"
)

func waiting(t *testing.T, root string) dual.Request {
	t.Helper()
	pend, err := dualStore(root).Pending(time.Now())
	if err != nil || len(pend) != 1 {
		t.Fatalf("waiting: %+v %v", pend, err)
	}
	return pend[0]
}

// Making somebody an administrator, weakening a setting and moving the
// audit log each wait for a second administrator, who makes the change on
// approving it; nobody approves their own.
func TestAPrivilegedChangeWaitsForASecondAdministrator(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, boss, lee := twoAdmins(t)
	t.Setenv("QUILZO_TOKEN", boss)
	if err := cmdAuth(root, []string{"grant", "pat", "admin"}); err != nil {
		t.Fatal(err)
	}
	isAdmin := func() bool {
		pol, _ := loadPolicy(root)
		return pol.Evaluate("pat", auth.ActGrant, "/").Allowed
	}
	if isAdmin() {
		t.Fatal("pat became an administrator on one administrator's word")
	}
	r := waiting(t, root)
	if err := cmdPending(root, []string{"approve", r.ID}); err == nil {
		t.Fatal("dana approved her own request")
	}
	t.Setenv("QUILZO_TOKEN", lee)
	if err := cmdPending(root, []string{"approve", r.ID}); err != nil {
		t.Fatal(err)
	}
	if !isAdmin() {
		t.Fatal("approved, and pat is not an administrator")
	}

	t.Setenv("QUILZO_TOKEN", boss)
	if err := cmdConfig(root, []string{"set", "publish.require_a11y", "false", "--accept-risk", "a migration"}); err != nil {
		t.Fatal(err)
	}
	if !mustConfig(root).Bool("publish.require_a11y") {
		t.Fatal("a weaker setting took effect on one administrator's word")
	}
	t.Setenv("QUILZO_TOKEN", lee)
	if err := cmdPending(root, []string{"approve", waiting(t, root).ID}); err != nil {
		t.Fatal(err)
	}
	if mustConfig(root).Bool("publish.require_a11y") {
		t.Fatal("approved, and the setting did not change")
	}

	// Raising how many approve a change is one administrator's; lowering
	// it, or putting it back to a lower default, is two.
	t.Setenv("QUILZO_TOKEN", boss)
	if err := cmdConfig(root, []string{"set", "review.required_approvals", "2"}); err != nil {
		t.Fatal(err)
	}
	if mustConfig(root).Int("review.required_approvals") != 2 {
		t.Fatal("raising the approvals waited")
	}
	for _, args := range [][]string{{"set", "review.required_approvals", "1"}, {"unset", "review.required_approvals"}} {
		if err := cmdConfig(root, args); err != nil {
			t.Fatal(err)
		}
		if mustConfig(root).Int("review.required_approvals") != 2 {
			t.Fatalf("%v took effect on one administrator's word", args)
		}
		t.Setenv("QUILZO_TOKEN", lee)
		_ = cmdPending(root, []string{"decline", waiting(t, root).ID})
		t.Setenv("QUILZO_TOKEN", boss)
	}

	dir := t.TempDir()
	if err := cmdAuditDir(root, []string{dir}); err != nil {
		t.Fatal(err)
	}
	if auditDir(root) == dir {
		t.Fatal("the audit log moved on one administrator's word")
	}
	t.Setenv("QUILZO_TOKEN", lee)
	r = waiting(t, root)
	if err := cmdPending(root, []string{"decline", r.ID}); err != nil {
		t.Fatal(err)
	}
	if auditDir(root) == dir {
		t.Fatal("a declined move happened")
	}
	body, _ := os.ReadFile(auditPath(root))
	for _, want := range []string{"dual.proposed", "dual.approved", "dual.declined"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("%s was not recorded", want)
		}
	}
}

// A setting that was raised or switched with nobody asked now waits like
// any other weaker one: refused with no reason, and with one it waits for
// a second administrator, who makes it on approving. Putting it back is
// one administrator's.
//
// Each of these was taken at once from one administrator, with no reason
// and nothing for the posture scan to report.
func TestALimitOrSwitchThatGivesSomethingUpWaitsForASecondAdministrator(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, boss, lee := twoAdmins(t)
	for _, tc := range [][2]string{
		{"api.rate.burst", "500"},
	} {
		key, value := tc[0], tc[1]
		t.Setenv("QUILZO_TOKEN", boss)
		before := mustConfig(root).Raw(key)
		if err := cmdConfig(root, []string{"set", key, value}); err == nil {
			t.Errorf("%s = %s was set with no reason", key, value)
		}
		if err := cmdConfig(root, []string{"set", key, value, "--accept-risk", "a test"}); err != nil {
			t.Fatalf("%s = %s: %v", key, value, err)
		}
		if got := mustConfig(root).Raw(key); got != before {
			t.Fatalf("%s = %s took effect on one administrator's word", key, got)
		}
		t.Setenv("QUILZO_TOKEN", lee)
		if err := cmdPending(root, []string{"approve", waiting(t, root).ID}); err != nil {
			t.Fatal(err)
		}
		if got := mustConfig(root).Raw(key); got != value {
			t.Fatalf("approved, and %s is %s", key, got)
		}
		t.Setenv("QUILZO_TOKEN", boss)
		if err := cmdConfig(root, []string{"unset", key}); err != nil {
			t.Fatal(err)
		}
		if !mustConfig(root).IsDefault(key) {
			t.Errorf("putting %s back waited for a second administrator", key)
		}
	}
}

// An administrator's token is issued to whoever asked, once another
// administrator agrees, and to nobody else.
func TestAnAdministratorsTokenWaitsAndGoesToWhoeverAsked(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, boss, lee := twoAdmins(t)
	t.Setenv("QUILZO_TOKEN", boss)
	count := func() int { ts, _ := loadTokens(root); return len(ts.Tokens) }
	before := count()
	if err := cmdToken(root, []string{"issue", "deploy", "--principal", "dana", "--role", "admin"}); err != nil {
		t.Fatal(err)
	}
	if count() != before {
		t.Fatal("an administrator's token was issued on one administrator's word")
	}
	r := waiting(t, root)
	t.Setenv("QUILZO_TOKEN", lee)
	if err := cmdPending(root, []string{"approve", r.ID}); err != nil {
		t.Fatal(err)
	}
	if err := cmdPending(root, []string{"redeem", r.ID}); err == nil {
		t.Fatal("the approver received the token")
	}
	t.Setenv("QUILZO_TOKEN", boss)
	if err := cmdPending(root, []string{"redeem", r.ID}); err != nil {
		t.Fatal(err)
	}
	if count() != before+1 {
		t.Fatal("redeemed, and no token was issued")
	}
	if err := cmdPending(root, []string{"redeem", r.ID}); err == nil {
		t.Error("a token was redeemed twice")
	}
}

// A store with one administrator is not left unable to change anything:
// their change is made as they make it, and the record says alone.
func TestTheOnlyAdministratorChangesAlone(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if err := cmdAuth(root, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(root)
	boss, _, _ := ts.Issue("b", "boss", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	_ = saveJSON(tokensPath(root), ts)
	t.Setenv("QUILZO_TOKEN", boss)
	if err := cmdAuth(root, []string{"grant", "pat", "admin"}); err != nil {
		t.Fatal(err)
	}
	pol, _ := loadPolicy(root)
	if !pol.Evaluate("pat", auth.ActGrant, "/").Allowed {
		t.Fatal("the only administrator could not make another")
	}
	body, _ := os.ReadFile(auditPath(root))
	if !strings.Contains(string(body), `"alone":"true"`) {
		t.Error("the record does not say it was approved alone")
	}
}

// A shield playbook change waits for a second administrator, and the only
// administrator's is approved as they make it.
func TestAPlaybookChangeTakesTwoOrSaysAlone(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, dana, _ := twoAdmins(t)
	t.Setenv("QUILZO_TOKEN", dana)
	if err := cmdShield(root, []string{"playbook", "mode", "admin-hunting", "watch", "--why", "a test"}); err != nil {
		t.Fatal(err)
	}
	bk, _ := shield.LoadBook(root)
	if len(bk.Pending) != 1 || len(bk.Playbooks) != 0 {
		t.Fatalf("with two administrators: %d waiting, %d changed", len(bk.Pending), len(bk.Playbooks))
	}

	solo := demoStore(t)
	if err := cmdAuth(solo, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(solo)
	boss, _, _ := ts.Issue("b", "boss", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	_ = saveJSON(tokensPath(solo), ts)
	t.Setenv("QUILZO_TOKEN", boss)
	if err := cmdShield(solo, []string{"playbook", "mode", "admin-hunting", "watch", "--why", "a test"}); err != nil {
		t.Fatal(err)
	}
	bk, _ = shield.LoadBook(solo)
	if len(bk.Pending) != 0 || len(bk.Decided) != 1 || !bk.Decided[0].Alone {
		t.Fatalf("alone: %d waiting, %+v", len(bk.Pending), bk.Decided)
	}
}

// seedPolicy grants straight into the policy, as a test's setup does: a
// second administrator granted by a command waits for a third.
func seedPolicy(t *testing.T, root string, grants ...[2]string) {
	t.Helper()
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		for _, g := range grants {
			if err := p.Grant(auth.Binding{Principal: g[0], Role: auth.Role(g[1]), Resource: "/"}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// asOnly acts as who, with a token of their own, for a test whose store
// they alone administer.
func asOnly(t *testing.T, root, who string) {
	t.Helper()
	ts, _ := loadTokens(root)
	secret, _, err := ts.Issue(who, who, auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", secret)
}

// A group mapped to admin, or to a job with admin in it, makes whoever the
// identity provider puts in it an administrator, so the mapping waits for a
// second administrator as a grant does. A group mapped to less is one
// administrator's to map.
func TestMappingAGroupToAdministratorTakesTwo(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, dana, lee := twoAdmins(t)
	mapped := func() map[string]string {
		var m map[string]string
		if err := scimStore(root).Read(func(st *scim.State) { m = maps.Clone(st.Mapping) }); err != nil {
			t.Fatal(err)
		}
		return m
	}
	t.Setenv("QUILZO_TOKEN", dana)
	for _, to := range []string{"admin", "analyst", "compliance"} {
		if err := cmdSCIM(root, []string{"map", "Ops " + to, to}); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmdSCIM(root, []string{"map", "Editors", "publisher"}); err != nil {
		t.Fatal(err)
	}
	if m := mapped(); len(m) != 1 || m["Editors"] != "publisher" {
		t.Fatalf("a group that makes administrators was mapped on one administrator's word: %v", m)
	}
	pend, err := dualStore(root).Pending(time.Now())
	if err != nil || len(pend) != 3 {
		t.Fatalf("pending: %+v %v", pend, err)
	}
	if pend[0].Kind != dual.Mapping || !strings.Contains(pend[0].What, `"Ops admin"`) {
		t.Fatalf("the request: %+v", pend[0])
	}
	if err := cmdPending(root, []string{"approve", pend[0].ID}); err == nil {
		t.Fatal("dana approved her own mapping")
	}
	t.Setenv("QUILZO_TOKEN", lee)
	if err := cmdPending(root, []string{"approve", pend[0].ID}); err != nil {
		t.Fatal(err)
	}
	if m := mapped(); m["Ops admin"] != "admin" || len(m) != 2 {
		t.Fatalf("approved, and the mapping is %v", m)
	}
	if err := cmdPending(root, []string{"decline", pend[1].ID}); err != nil {
		t.Fatal(err)
	}
	if _, ok := mapped()["Ops analyst"]; ok {
		t.Fatal("a declined mapping was made")
	}
}

// While a group makes administrators, the provisioning token makes them,
// so making one waits for a second administrator and goes to whoever
// asked. It did not: with 'IT admins' mapped to admin, either of two
// administrators alone made the token and, through the identity provider's
// door, put mallory in the group and so made her an administrator.
func TestAProvisioningTokenThatMakesAdministratorsTakesTwo(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, dana, lee := twoAdmins(t)
	old := w
	t.Cleanup(func() { w = old })
	var buf bytes.Buffer
	w = out.New(false)
	w.Out = &buf
	t.Setenv("QUILZO_TOKEN", dana)
	if err := cmdSCIM(root, []string{"map", "IT admins", "admin"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", lee)
	if err := cmdPending(root, []string{"approve", waiting(t, root).ID}); err != nil {
		t.Fatal(err)
	}
	mallory := func(token string) bool {
		c := scimClient{t: t, h: scimHandler(root), token: token}
		_, u := c.do(http.MethodPost, "/Users", `{"userName":"mallory","active":true}`)
		id, _ := u["id"].(string)
		c.do(http.MethodPost, "/Groups", `{"displayName":"IT admins","members":[{"value":"`+id+`"}]}`)
		pol, _ := loadPolicy(root)
		return pol.Evaluate("mallory", auth.ActGrant, "/").Allowed
	}
	tokenIn := func(s string) string {
		i := strings.Index(s, "qzscim_")
		if i < 0 {
			return ""
		}
		return strings.Fields(s[i:])[0]
	}

	t.Setenv("QUILZO_TOKEN", dana)
	buf.Reset()
	if err := cmdSCIM(root, []string{"token", "--days", "30"}); err != nil {
		t.Fatal(err)
	}
	if token := tokenIn(buf.String()); token != "" {
		if mallory(token) {
			t.Fatal("one administrator, with a second present, made mallory an administrator with no second approval")
		}
		t.Fatal("one administrator made a provisioning token that makes administrators, with nobody agreeing")
	}
	if _, set, _ := readSCIMToken(root, time.Now()); set {
		t.Fatal("a provisioning token was kept on one administrator's word")
	}
	r := waiting(t, root)
	if r.Kind != dual.SCIMToken {
		t.Fatalf("the request waiting is a %s", r.Kind)
	}
	if err := cmdPending(root, []string{"redeem", r.ID}); err == nil {
		t.Fatal("the token was received before anybody approved it")
	}
	t.Setenv("QUILZO_TOKEN", lee)
	if err := cmdPending(root, []string{"approve", r.ID}); err != nil {
		t.Fatal(err)
	}
	if err := cmdPending(root, []string{"redeem", r.ID}); err == nil {
		t.Fatal("the approver received the token somebody else asked for")
	}
	t.Setenv("QUILZO_TOKEN", dana)
	buf.Reset()
	if err := cmdPending(root, []string{"redeem", r.ID}); err != nil {
		t.Fatal(err)
	}
	tok, set, _ := readSCIMToken(root, time.Now())
	if !set || time.Until(tok.Expires) > 31*24*time.Hour {
		t.Fatalf("the token received: %+v %v", tok, set)
	}
	if !mallory(tokenIn(buf.String())) {
		t.Error("the token received does not work")
	}
	if err := cmdPending(root, []string{"redeem", r.ID}); err == nil {
		t.Error("an approved token was received twice")
	}

	// A group that makes nobody an administrator leaves the token one
	// administrator's to make.
	if err := cmdSCIM(root, []string{"unmap", "IT admins"}); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := cmdSCIM(root, []string{"token"}); err != nil || tokenIn(buf.String()) == "" {
		t.Fatalf("a token with no administrators to make waited: %v", err)
	}
}

// removalAt moves the stored record of the last administrator removed to
// ago, as though it had happened then.
func removalAt(t *testing.T, root string, ago time.Duration) {
	t.Helper()
	var f map[string]any
	if err := loadJSON(dualStore(root).Path, &f); err != nil {
		t.Fatal(err)
	}
	rm, ok := f["removed"].(map[string]any)
	if !ok {
		t.Fatalf("no removal is recorded: %v", f)
	}
	rm["at"] = time.Now().Add(-ago).UTC().Format(time.RFC3339Nano)
	if err := saveJSON(dualStore(root).Path, f); err != nil {
		t.Fatal(err)
	}
}

// The administrator left after removing the other does not approve alone
// for a day.
//
// One administrator may remove another, and that is not dual-controlled.
// The only administrator approves alone, so a store with one is not left
// unable to change anything. Together those made removing the other the
// way to approve anything alone: dana asked for pat to be made an
// administrator, removed lee, who would have decided it, and approved it
// herself as the only administrator there was.
func TestRemovingTheOtherAdministratorDoesNotLetTheOneLeftApproveAlone(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, dana, _ := twoAdmins(t)
	t.Setenv("QUILZO_TOKEN", dana)
	isAdmin := func(who string) bool {
		pol, _ := loadPolicy(root)
		return pol.Evaluate(who, auth.ActGrant, "/").Allowed
	}
	if err := cmdAuth(root, []string{"grant", "pat", "admin"}); err != nil {
		t.Fatal(err)
	}
	r := waiting(t, root)
	if err := cmdAuth(root, []string{"revoke", "lee", "admin"}); err != nil {
		t.Fatal(err)
	}

	err := cmdPending(root, []string{"approve", r.ID})
	if isAdmin("pat") {
		t.Fatal("dana removed the other administrator and approved her own request alone")
	}
	if err == nil || !strings.Contains(err.Error(), "until") {
		t.Fatalf("the refusal does not say why and until when: %v", err)
	}
	// A change she asks for now waits as well, rather than being approved
	// as she makes it.
	if err := cmdConfig(root, []string{"set", "publish.require_a11y", "false", "--accept-risk", "a migration"}); err != nil {
		t.Fatal(err)
	}
	if !mustConfig(root).Bool("publish.require_a11y") {
		t.Fatal("a weaker setting took effect alone a moment after the other administrator was removed")
	}
	body, _ := os.ReadFile(auditPath(root))
	if !strings.Contains(string(body), "dual.alone-refused") {
		t.Error("the refusal was not recorded")
	}

	removalAt(t, root, 23*time.Hour)
	if err := cmdPending(root, []string{"approve", r.ID}); err == nil || isAdmin("pat") {
		t.Fatalf("approved alone 23 hours after the removal: %v", err)
	}
	removalAt(t, root, 24*time.Hour+time.Minute)
	if err := cmdPending(root, []string{"approve", r.ID}); err != nil || !isAdmin("pat") {
		t.Fatalf("still refused a day after the removal: %v", err)
	}
}

// Two administrators again, and nobody approves alone: the other decides.
// The day's wait is for the administrator left alone, and ends as soon as
// there is a second.
func TestASecondAdministratorEndsTheWait(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, dana, _ := twoAdmins(t)
	t.Setenv("QUILZO_TOKEN", dana)
	if err := cmdAuth(root, []string{"revoke", "lee", "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdConfig(root, []string{"set", "publish.require_a11y", "false", "--accept-risk", "a migration"}); err != nil {
		t.Fatal(err)
	}
	if !mustConfig(root).Bool("publish.require_a11y") {
		t.Fatal("control: a change was approved alone straight after a removal")
	}
	// sam is enrolled and made an administrator as the identity provider
	// makes one, by a group already mapped: nobody here approves it.
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		return p.Grant(auth.Binding{Principal: "sam", Role: auth.RoleAdmin, Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	if err := loadJSON(dualStore(root).Path, &f); err != nil || f["removed"] != nil {
		t.Fatalf("two administrators again, and the removal still holds: %v %v", f["removed"], err)
	}
	// sam leaves the same way, by the provider; dana is alone again, and
	// waits a day from then.
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		p.Revoke("sam", auth.RoleAdmin, "/")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if onlyAdministrator(root, "dana") {
		t.Fatal("the second removal did not start a new day's wait")
	}
}

// A store that has only ever had one administrator is as it was: they
// approve alone, even after somebody else's access is removed.
func TestAStoreWithOneAdministratorStillApprovesAlone(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if w == nil {
		w = out.New(false)
		t.Cleanup(func() { w = nil })
	}
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		for _, b := range []auth.Binding{
			{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"},
			{Principal: "pat", Role: auth.RolePublisher, Resource: "/"},
			{Principal: "lee", Role: auth.RoleAdmin, Resource: "/blog"},
		} {
			if err := p.Grant(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(root)
	dana, _, err := ts.Issue("dana", "dana", auth.RoleAdmin, "", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", dana)
	for _, args := range [][]string{{"revoke", "pat", "publisher"}, {"revoke", "lee", "admin", "--on", "/blog"}} {
		if err := cmdAuth(root, args); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmdConfig(root, []string{"set", "publish.require_a11y", "false", "--accept-risk", "a migration"}); err != nil {
		t.Fatal(err)
	}
	if mustConfig(root).Bool("publish.require_a11y") {
		t.Fatal("the only administrator there has ever been could not approve alone")
	}
}
