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
