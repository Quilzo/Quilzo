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
	"github.com/quilzo/quilzo/internal/enrol"
	"github.com/quilzo/quilzo/internal/out"
)

// A new store made with --admin has its first administrator, two factors
// from the first day, and the one link that gives that administrator a
// passkey; nobody is left holding a token to get in with.
func TestANewStoreStartsWithTwoFactorsAndAnEnrolmentLink(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	old := w
	t.Cleanup(func() { w = old })
	var buf bytes.Buffer
	w = out.New(true)
	w.Out = &buf
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := initAdmin(root, []string{"--admin", "dana@quilzo.io"}, true); err != nil {
		t.Fatal(err)
	}
	var got struct {
		For  string `json:"for"`
		Link string `json:"link"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil || got.For != "dana@quilzo.io" ||
		!strings.Contains(got.Link, "/enrol/"+enrol.Prefix) {
		t.Fatalf("%v %s", err, buf.String())
	}
	pol, _ := loadPolicy(root)
	if !holdsAny(pol, "dana@quilzo.io") {
		t.Error("the first administrator was not granted")
	}
	if from, ok := mfaFromIfSet(root); !ok || time.Since(from) > time.Minute || time.Until(from) > time.Minute {
		t.Errorf("a new store's two factors start at %s %v, not now", from, ok)
	}
	secret := got.Link[strings.Index(got.Link, enrol.Prefix):]
	if l, err := enrolStore(root).Peek(secret, time.Now()); err != nil || l.Principal != "dana@quilzo.io" {
		t.Errorf("the link printed is not waiting: %+v %v", l, err)
	}
	// A store that already has people is not taken over by naming
	// somebody new as its first administrator.
	if err := initAdmin(root, []string{"--admin", "mallory@quilzo.io"}, false); err == nil {
		t.Error("init --admin made a second first administrator")
	}
}

// quilzo auth enrol gives a link only to somebody with access, and takes
// it back on --revoke.
func TestAuthEnrolGivesALinkToSomebodyWithAccess(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if err := cmdAuth(root, []string{"enrol", "nobody"}); err == nil {
		t.Error("a link was made for somebody with no access")
	}
	for _, g := range [][]string{{"grant", "boss", "admin"}, {"grant", "pat", "author"}} {
		if err := cmdAuth(root, g); err != nil {
			t.Fatal(err)
		}
	}
	ts, _ := loadTokens(root)
	secret, _, err := ts.Issue("t", "boss", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", secret)
	if err := cmdAuth(root, []string{"enrol", "pat", "--for", "2h"}); err != nil {
		t.Fatal(err)
	}
	waiting, _ := enrolStore(root).Waiting(time.Now())
	if len(waiting) != 1 || waiting[0].Principal != "pat" || time.Until(waiting[0].Expires) > 2*time.Hour {
		t.Fatalf("%+v", waiting)
	}
	if err := cmdAuth(root, []string{"enrol", "pat", "--for", "48h"}); err == nil {
		t.Error("a link longer than a day was made")
	}
	if err := cmdAuth(root, []string{"enrol", "pat", "--revoke"}); err != nil {
		t.Fatal(err)
	}
	if waiting, _ := enrolStore(root).Waiting(time.Now()); len(waiting) != 0 {
		t.Errorf("a revoked link is still waiting: %+v", waiting)
	}
}

// An enrolment link is a credential for the person it names: one for an
// administrator waits for a second administrator, as an administrator's
// token does, and goes to whoever asked. Before, dana alone could give
// herself a link for lee, open it with her own authenticator, and sign in
// as lee to approve her own requests.
func TestAnEnrolmentLinkForAnAdministratorWaitsForASecond(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, dana, lee := twoAdmins(t)
	t.Setenv("QUILZO_TOKEN", dana)
	if err := cmdAuth(root, []string{"enrol", "lee", "--for", "2h"}); err != nil {
		t.Fatal(err)
	}
	if links, _ := enrolStore(root).Waiting(time.Now()); len(links) != 0 {
		t.Fatalf("one administrator was given a link for another with nobody agreeing: %+v", links)
	}
	r := waiting(t, root)
	if r.Kind != dual.Enrol {
		t.Fatalf("the request waiting is a %s", r.Kind)
	}
	if err := cmdPending(root, []string{"redeem", r.ID}); err == nil {
		t.Fatal("the link was received before anybody approved it")
	}
	t.Setenv("QUILZO_TOKEN", lee)
	if err := cmdPending(root, []string{"approve", r.ID}); err != nil {
		t.Fatal(err)
	}
	if err := cmdPending(root, []string{"redeem", r.ID}); err == nil {
		t.Fatal("the approver received the link somebody else asked for")
	}
	t.Setenv("QUILZO_TOKEN", dana)
	if err := cmdPending(root, []string{"redeem", r.ID}); err != nil {
		t.Fatal(err)
	}
	links, _ := enrolStore(root).Waiting(time.Now())
	if len(links) != 1 || links[0].Principal != "lee" || links[0].By != "dana" || time.Until(links[0].Expires) > 2*time.Hour {
		t.Fatalf("the link received: %+v", links)
	}
	if err := cmdPending(root, []string{"redeem", r.ID}); err == nil {
		t.Error("an approved link was received twice")
	}
}

// quilzo init --admin names a store's first administrator and prints the
// link for their passkey; run again on a store nobody has signed in to, it
// gives a fresh link. It asked nothing of whoever ran it, so on a store in
// use anybody at the machine, with no credential at all, was printed a
// link that signs in as an existing administrator.
func TestInitAdminGivesNoLinkOnAStoreInUse(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, _, _ := twoAdmins(t)
	t.Setenv("QUILZO_TOKEN", "")
	_ = initAdmin(root, []string{"--admin", "lee"}, false)
	if links, _ := enrolStore(root).Waiting(time.Now()); len(links) != 0 {
		t.Fatalf("init --admin gave a link for an administrator of a store in use: %+v", links)
	}

	// A store nobody has signed in to yet still gets its first link again.
	fresh := t.TempDir() + "/st"
	if err := cmdInit(fresh); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := initAdmin(fresh, []string{"--admin", "dana"}, false); err != nil {
			t.Fatal(err)
		}
	}
	if links, _ := enrolStore(fresh).Waiting(time.Now()); len(links) != 1 || links[0].Principal != "dana" {
		t.Fatalf("the first administrator's link: %+v", links)
	}
}
