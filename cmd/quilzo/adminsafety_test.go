// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/gateway"
	"github.com/quilzo/quilzo/internal/out"
)

func onlyOwner(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	root := connectStore(t)
	// What the commands say goes nowhere: a token issued here is printed
	// under --json, and a credential is not written to the test's output.
	w.Out = &bytes.Buffer{}
	seedPolicy(t, root, [2]string{"owner", "admin"})
	asOnly(t, root, "owner")
	if err := cmdAuth(root, []string{"grant", "dana", "author"}); err != nil {
		t.Fatal(err)
	}
	return root
}

func administers(t *testing.T, root, who string) bool {
	t.Helper()
	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	return pol.Evaluate(who, auth.ActGrant, "/").Allowed
}

func TestTheLastAdministratorIsNeverRevokedOrDeniedFromTheCommandLine(t *testing.T) {
	root := onlyOwner(t)
	if err := cmdAuth(root, []string{"revoke", "owner", "admin"}); err == nil {
		t.Error("the only administrator's admin binding was revoked")
	}
	if !administers(t, root, "owner") {
		t.Fatal("nobody administers the store after a revoke")
	}
	if err := cmdAuth(root, []string{"deny", "owner", "admin"}); err == nil {
		t.Error("the only administrator was denied admin")
	}
	if !administers(t, root, "owner") {
		t.Fatal("nobody administers the store after a deny")
	}

	// With nothing else in the policy, revoking it would have emptied it.
	bare := t.TempDir() + "/st"
	if err := cmdInit(bare); err != nil {
		t.Fatal(err)
	}
	seedPolicy(t, bare, [2]string{"owner", "admin"})
	asOnly(t, bare, "owner")
	if err := cmdAuth(bare, []string{"revoke", "owner", "admin"}); err == nil {
		t.Error("the only binding of the only administrator was revoked")
	}
	if pol, _ := loadPolicy(bare); len(pol.Bindings) == 0 {
		t.Fatal("the policy was emptied, which turns access control off")
	}

	// A second administrator may be removed, and either may then not be.
	seedPolicy(t, root, [2]string{"lee", "admin"})
	if err := cmdAuth(root, []string{"revoke", "lee", "admin"}); err != nil {
		t.Fatalf("one of two administrators could not be removed: %v", err)
	}
}

func TestARecoveryIsNotRefusedOverATokenThatCanNoLongerAdminister(t *testing.T) {
	root := onlyOwner(t)
	// Written by hand, as a store would be left by anything that took the
	// last administrator away before the guard did.
	pol, _ := loadPolicy(root)
	pol.Bindings = []auth.Binding{{Principal: "owner", Role: auth.RoleAuthor, Resource: "/"},
		{Principal: "dana", Role: auth.RoleAuthor, Resource: "/"}}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", "")
	_, printed := captureStdout(t)
	err := cmdRecover(root, []string{"--principal", "owner", "--reason", "locked out", "--i-have-filesystem-access"})
	_ = printed()
	if err != nil && strings.Contains(err.Error(), "still usable") {
		t.Fatalf("the recovery counted a token that administers nothing: %v", err)
	}
	if !administers(t, root, "owner") {
		t.Fatalf("the recovery did not give the store an administrator back: %v", err)
	}
}

func TestAStoreNobodyHasEnteredGetsTwoFactorsFromInit(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	old := w
	t.Cleanup(func() { w = old })
	w = out.New(false)
	w.Out = &bytes.Buffer{}

	root := demoStore(t)
	w.Out = &bytes.Buffer{}
	if err := runInit(root, []string{"--admin", "owner"}); err != nil {
		t.Fatal(err)
	}
	if from, ok := mfaFromIfSet(root); !ok || time.Until(from) > time.Minute {
		t.Errorf("a store made by demo gets two factors from %v (%v), not now", from, ok)
	}

	typo := t.TempDir() + "/st"
	if err := runInit(typo, []string{"--admni", "owner"}); err == nil {
		t.Fatal("a mistyped flag was accepted")
	}
	if isStore(typo) {
		t.Error("a mistyped flag made a store before it was refused")
	}
	if err := runInit(typo, []string{"--admin", "owner"}); err != nil {
		t.Fatal(err)
	}
	if from, ok := mfaFromIfSet(typo); !ok || time.Until(from) > time.Minute {
		t.Errorf("after a mistyped init, two factors start at %v (%v), not now", from, ok)
	}

	// A store somebody already signs in to keeps whatever it was given.
	used := onlyOwner(t)
	if err := runInit(used, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := mfaFromIfSet(used); ok {
		t.Error("init wrote a date for a store people already sign in to")
	}
}

func TestAnyNameTypedAfterByIsCreditedNotRecorded(t *testing.T) {
	root := onlyOwner(t)
	granted := auditFor(t, root, "auth.granted")
	if len(granted) == 0 {
		t.Fatal("no grant on the record to compare with")
	}
	owner := granted[0].Principal

	if err := postureSuppress(root, []string{"mfa.no-second-factor", "--reason", "accepted by the board",
		"--by", "Dana (CISO)", "--days", "90"}); err != nil {
		t.Fatal(err)
	}
	got := auditFor(t, root, "posture.suppress")
	if len(got) != 1 || got[0].Principal != owner || !got[0].Verified {
		t.Errorf("the suppression is recorded as %+v, not as the administrator who made it", got)
	}
	f := &suppressionFile{}
	_ = loadJSON(suppressPath(root), f)
	if len(f.Suppressions) != 1 || !strings.HasPrefix(f.Suppressions[0].By, "owner") ||
		!strings.Contains(f.Suppressions[0].By, "Dana (CISO)") {
		t.Errorf("the suppression is by %+v", f.Suppressions)
	}

	if err := cmdAuth(root, []string{"grant", "mallory", "reader", "--by", "Dana (CISO)"}); err != nil {
		t.Fatal(err)
	}
	pol, _ := loadPolicy(root)
	for _, b := range pol.Snapshot() {
		if b.Principal == "mallory" && (b.GrantedBy != "owner" || !strings.Contains(b.Note, "Dana (CISO)")) {
			t.Errorf("mallory's grant is by %q, noted %q", b.GrantedBy, b.Note)
		}
	}

	pages, _ := draftPageIDs(root)
	if len(pages) == 0 {
		// The store has no draft pages; a demonstration gives it some.
		if err := cmdDemo(root, []string{"-publish=false", "-templates", t.TempDir() + "/tpl"}); err != nil {
			t.Fatal(err)
		}
		pages, _ = draftPageIDs(root)
	}
	ts, _ := loadTokens(root)
	dana, _, err := ts.Issue("dana", "dana", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	_ = saveJSON(tokensPath(root), ts)
	t.Setenv("QUILZO_TOKEN", dana)
	if err := checkedSet(root, []string{pages[0], "--by", "Priya (Compliance)", "--note", "legal reviewed"}); err != nil {
		t.Fatal(err)
	}
	st, _ := openChecked(root)
	r, err := st.Get(pages[0])
	if err != nil || r.By != "dana" || !strings.Contains(r.Note, "Priya (Compliance)") {
		t.Errorf("the check is recorded as %+v %v", r, err)
	}
}

func TestAGatewayBudgetIsShownAndChangedOneLimitAtATime(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := connectStore(t)
	var buf bytes.Buffer
	w.Out = &buf
	budget := func() gateway.Budget {
		t.Helper()
		cfg, err := gateway.Load(gatewayPath(root))
		if err != nil || cfg == nil {
			t.Fatalf("%v %v", cfg, err)
		}
		for _, b := range cfg.Budgets {
			if b.Consumer == "chatbot:help" {
				return b
			}
		}
		return gateway.Budget{}
	}
	if err := cmdGateway(root, []string{"budget", "chatbot:help", "--per-minute", "5",
		"--chars-per-day", "20000", "--tokens-per-day", "9000"}); err != nil {
		t.Fatal(err)
	}
	set := gateway.Budget{Consumer: "chatbot:help", PerMinute: 5, CharsPerDay: 20000, TokensPerDay: 9000}
	if budget() != set {
		t.Fatalf("the budget set is %+v", budget())
	}
	buf.Reset()
	if err := cmdGateway(root, []string{"budget", "chatbot:help"}); err != nil {
		t.Fatal(err)
	}
	if budget() != set {
		t.Errorf("asking for the budget changed it to %+v", budget())
	}
	var shown gateway.Budget
	if err := json.Unmarshal(buf.Bytes(), &shown); err != nil || shown != set {
		t.Errorf("the budget shown is %q (%v)", buf.String(), err)
	}
	if err := cmdGateway(root, []string{"budget", "chatbot:help", "--per-minute", "10"}); err != nil {
		t.Fatal(err)
	}
	set.PerMinute = 10
	if budget() != set {
		t.Errorf("one limit changed left %+v", budget())
	}
	if err := cmdGateway(root, []string{"budget", "chatbot:help", "--tokens-per-day", "0"}); err != nil {
		t.Fatal(err)
	}
	set.TokensPerDay = 0
	if budget() != set {
		t.Errorf("a limit set to unlimited left %+v", budget())
	}
}

func adminSafetyToken(t *testing.T, root, who string, role auth.Role) string {
	t.Helper()
	ts, _ := loadTokens(root)
	secret, _, err := ts.Issue(who, who, role, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	return secret
}

func TestASecondAdministratorIsSetUpInEitherOrder(t *testing.T) {
	root := onlyOwner(t)
	if err := cmdAuth(root, []string{"grant", "theo", "admin"}); err != nil {
		t.Fatal(err)
	}
	if !administers(t, root, "theo") {
		t.Fatal("the only administrator could not make theo one")
	}
	w.Out = &bytes.Buffer{}
	if err := cmdAuth(root, []string{"enrol", "theo", "--for", "1h"}); err != nil {
		t.Fatal(err)
	}
	if links, _ := enrolStore(root).Waiting(time.Now()); len(links) != 1 || links[0].Principal != "theo" {
		t.Fatalf("theo, an administrator with no way in, was given no link: %+v", links)
	}
	if pend, _ := dualStore(root).Pending(time.Now()); len(pend) != 0 {
		t.Fatalf("it waits for theo to approve his own way in: %+v", pend)
	}

	// The token, in the same order, on another store.
	other := onlyOwner(t)
	if err := cmdAuth(other, []string{"grant", "theo", "admin"}); err != nil {
		t.Fatal(err)
	}
	_, printed := captureStdout(t)
	err := tokenIssue(other, []string{"theo-cli", "--principal", "theo", "--role", "admin", "--ttl", "1h"})
	_ = printed()
	if err != nil {
		t.Fatal(err)
	}
	if pend, _ := dualStore(other).Pending(time.Now()); len(pend) != 0 {
		t.Fatalf("theo's first token waits for theo: %+v", pend)
	}

	// Theo now has a way in, so there are two administrators, and another
	// way in for either waits for the other.
	w.Out = &bytes.Buffer{}
	if err := cmdAuth(other, []string{"enrol", "theo", "--for", "1h"}); err != nil {
		t.Fatal(err)
	}
	if pend, _ := dualStore(other).Pending(time.Now()); len(pend) != 1 || pend[0].Kind != dual.Enrol {
		t.Fatalf("a link for an administrator who can sign in did not wait: %+v", pend)
	}

	// An administrator with a way in already is not given another alone.
	third := onlyOwner(t)
	seedPolicy(t, third, [2]string{"lee", "admin"})
	adminSafetyToken(t, third, "lee", auth.RoleAdmin)
	if err := cmdAuth(third, []string{"enrol", "lee", "--for", "1h"}); err != nil {
		t.Fatal(err)
	}
	if links, _ := enrolStore(third).Waiting(time.Now()); len(links) != 0 {
		t.Fatalf("one administrator gave herself another's sign-in: %+v", links)
	}

	// Nor while a request of hers waits for the one with no way in: given
	// his sign-in, she would approve it as him.
	fourth := onlyOwner(t)
	seedPolicy(t, fourth, [2]string{"theo", "admin"})
	if err := cmdAuth(fourth, []string{"grant", "pat", "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(fourth, []string{"enrol", "theo", "--for", "1h"}); err != nil {
		t.Fatal(err)
	}
	if links, _ := enrolStore(fourth).Waiting(time.Now()); len(links) != 0 {
		t.Fatalf("a link was given alone for the administrator a waiting request is for: %+v", links)
	}
}

func TestTheBootstrapDoesNotNameAnAdministratorNobodyIs(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := connectStore(t)
	var buf bytes.Buffer
	w = out.New(false)
	w.Out = &buf
	t.Cleanup(func() { w = nil })
	apply, err := proposeSecond(root, resolveCaller(root, ""), dual.AuditLog, "move the audit log",
		dual.AuditLogChange{Dir: t.TempDir()}, "")
	if err != nil || !apply {
		t.Fatalf("%v %v", apply, err)
	}
	if strings.Contains(buf.String(), "only administrator") {
		t.Errorf("before anybody administers the store, it says: %s", buf.String())
	}
}
