// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/travel"
)

// What a sign-in has to do follows from what it looks like and whose it
// is: somebody else is stepped up, and the worst of it is told.
func TestARiskySignInHasToConfirmItIsItsPerson(t *testing.T) {
	sig := func(kinds ...string) []travel.Signal {
		var out []travel.Signal
		for _, k := range kinds {
			out = append(out, travel.Signal{Kind: k, Detail: k})
		}
		return out
	}
	for _, c := range []struct {
		name         string
		role         auth.Role
		j            travel.Judged
		stepUp, tell bool
	}{
		{"impossible travel", auth.RoleAuthor, travel.Judged{Signals: sig("impossible-travel"), Risk: "high"}, true, true},
		{"a session copied elsewhere", auth.RoleReader, travel.Judged{Signals: sig("session-moved"), Risk: "high"}, true, true},
		{"through Tor", auth.RoleAuthor, travel.Judged{Signals: sig("anonymous-network"), Risk: "medium"}, true, false},
		{"from a rented server", auth.RoleAuthor, travel.Judged{Signals: sig("hosting-network"), Risk: "medium"}, true, false},
		{"a reader abroad", auth.RoleReader, travel.Judged{Signals: sig("new-country"), Risk: "medium"}, false, false},
		{"an administrator abroad", auth.RoleAdmin, travel.Judged{Signals: sig("new-country"), Risk: "medium"}, true, false},
		{"three unfamiliar things at once", auth.RoleAuthor, travel.Judged{Signals: sig("new-ip", "new-device", "unusual-hour"), Risk: "high"}, true, true},
		{"a new address alone", auth.RoleAuthor, travel.Judged{Signals: sig("new-ip"), Risk: "low"}, false, false},
	} {
		d := decideSignIn(c.role, c.j)
		if d.StepUp != c.stepUp || d.Tell != c.tell || (d.StepUp && d.Why == "") {
			t.Errorf("%s: %+v, want step up %v, tell %v", c.name, d, c.stepUp, c.tell)
		}
	}
}

// The policy is on in a new store, every signal is on the record whatever
// it decides, and off is a decision that lets the same sign-in in.
func TestTheSignInPolicyIsOnUntilSomebodyTurnsItOff(t *testing.T) {
	root := connectStore(t)
	if !adaptiveSignIn(root) {
		t.Fatal("a new store does not check sign-ins")
	}
	f := admin.SignInFacts{Principal: "dana", Role: auth.RoleAuthor, How: "passkey"}
	j := travel.Judged{Signals: []travel.Signal{{Kind: "anonymous-network", Detail: "through Tor"}}, Risk: "medium"}
	if v := judgeSignIn(root, f, travel.SignIn{At: time.Now()}, j); !v.StepUp || v.Reason != "through Tor" {
		t.Fatalf("a sign-in through Tor got in: %+v", v)
	}
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("signin.adaptive", "false", "tested off", "dana"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	if v := judgeSignIn(root, f, travel.SignIn{At: time.Now()}, j); v.StepUp {
		t.Fatal("the policy stepped a sign-in up while it was off")
	}
	finishBackground(10 * time.Second)
	evs, _ := audit.Read(auditPath(root))
	n := 0
	for _, e := range evs {
		// The person is the pseudonym the log keeps for them, never their name.
		if e.Action == "signin.signal" && e.Detail["signal"] == "anonymous-network" && e.Detail["subject"] != "dana" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d of the two sign-ins' signals are on the record", n)
	}
}

// Only a session asked to confirm it is its person is said to be. Every
// mail about a sign-in used to end "The session must confirm it is them
// before it can do anything", so a locked account, where nobody got in and
// there is no session, and a person whose sessions were all ended, told the
// security contact to wait for a confirmation that would never come.
func TestEachSignInMailSaysWhatHappensNext(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := connectStore(t)
	box := securityMailbox(t, root)
	_, moved, reported, signal := sessionHooks(root)
	last := func() string {
		sent := box.read()
		if len(sent) == 0 {
			t.Fatal("the security contact was told nothing")
		}
		return sent[len(sent)-1].Body
	}
	confirm := "must confirm it is them"
	signal("dana", "account-locked", "repeated failed sign-ins from places this account is not used from")
	if b := last(); strings.Contains(b, confirm) || !strings.Contains(b, "quilzo auth unlock dana") {
		t.Errorf("the account-locked mail: %q", b)
	}
	signal("dana", "verification-failing", "three failed passkey confirmations from a session asked to confirm it is them")
	if b := last(); strings.Contains(b, confirm) || !strings.Contains(b, "Nothing has proved it is them") {
		t.Errorf("the verification-failing mail: %q", b)
	}
	reported("dana", "s1")
	if b := last(); strings.Contains(b, confirm) {
		t.Errorf("the mail about a sign-in reported as not them: %q", b)
	}
	// A session that moved is stepped up, and is the one that must confirm.
	moved(admin.SessionMove{Principal: "dana"})
	if b := last(); !strings.Contains(b, confirm) {
		t.Errorf("the mail about a session that moved: %q", b)
	}
	if n := len(box.read()); n != 4 {
		t.Errorf("four sign-in alerts made %d mails", n)
	}
}

// "This wasn't me" ends what the reported sign-in reached: every session
// its person is signed in to the admin with, and the token that sign-in
// was made with. Their other tokens, a program's among them, are left
// working, for the security contact, who is told, to decide about.
//
// It revoked every token the person held, long-lived ones and programs'
// included, while the page said only "this session ends now". Whoever held
// a session stepped up for not looking like its person could press it, and
// every integration that person had issued a token for stopped.
func TestReportingASignInEndsWhatItReachedAndNoMore(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := connectStore(t)
	_ = securityMailbox(t, root)
	_, _, reported, _ := sessionHooks(root)

	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	pasted, pastedTok, err := ts.Issue("laptop", "dana", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	_, ci, err := ts.Issue("ci", "dana", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	_, own, err := ts.Issue("desktop", "dana", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	// The reported sign-in: the laptop token pasted into the sign-in form.
	_, held, err := ts.Exchange(pasted, auth.RoleNone, "", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.MarkSignIn(held.ID); err != nil {
		t.Fatal(err)
	}
	// Another sign-in of hers, with a passkey.
	_, passkey, err := ts.IssueSession("passkey:dana", "dana", auth.RoleAuthor, "/", time.Hour,
		auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := ts.Issue("ci", "sam", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []struct {
		id, kind string
	}{{pastedTok.ID, auth.KindPerson}, {ci.ID, auth.KindProgram}, {own.ID, auth.KindPerson}} {
		if err := ts.RecordKind(k.id, k.kind); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}

	reported("dana", held.ID)
	finishBackground(10 * time.Second)

	after, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	revoked := map[string]bool{}
	for _, k := range after.Snapshot() {
		revoked[k.ID] = k.Revoked
	}
	for _, c := range []struct {
		what string
		id   string
		ends bool
	}{
		{"the reported session", held.ID, true},
		{"the token it was signed in with", pastedTok.ID, true},
		{"her other sign-in", passkey.ID, true},
		{"her program's token", ci.ID, false},
		{"her own other token", own.ID, false},
		{"somebody else's token", other.ID, false},
	} {
		if revoked[c.id] != c.ends {
			t.Errorf("%s: revoked %v, want %v", c.what, revoked[c.id], c.ends)
		}
	}
}
