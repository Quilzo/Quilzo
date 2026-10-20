// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/memory"
	"github.com/quilzo/quilzo/internal/webhook"
)

// A copy of the token store read before a revocation, written back after
// it, as a sign-in in the admin does, leaves the token revoked.
func TestAStaleTokenStoreDoesNotBringARevokedTokenBack(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	ts, _ := loadTokens(root)
	_, tok, err := ts.Issue("ci", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	stale, _ := loadTokens(root)
	fresh, _ := loadTokens(root)
	if _, err := fresh.Revoke(tok.ID); err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, fresh); err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, stale); err != nil {
		t.Fatal(err)
	}
	after, _ := loadTokens(root)
	for _, x := range after.Snapshot() {
		if x.ID == tok.ID && !x.Revoked {
			t.Fatal("writing back a stale copy brought a revoked token back to life")
		}
	}
}

// Sending a webhook takes seconds; an endpoint removed meanwhile stays
// removed when the delivery is recorded.
func TestRecordingADeliveryDoesNotPutBackARemovedEndpoint(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	url := "https://hooks.quilzo.io/x"
	if err := updateHooks(root, func(f *hookFile) error {
		f.Endpoints = append(f.Endpoints, webhook.Endpoint{URL: url, Secret: "s"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := hookRemove(root, []string{url}); err != nil {
		t.Fatal(err)
	}
	recordDeliveries(root, []webhook.Delivery{{URL: url, Succeeded: true}})
	f, _ := loadHooks(root)
	for _, e := range f.Endpoints {
		if e.URL == url {
			t.Fatal("recording a delivery put back an endpoint removed while it was being sent")
		}
	}
	if len(f.Deliveries) != 1 {
		t.Errorf("the delivery was not recorded: %+v", f.Deliveries)
	}
}

// Grants made at once from separate writers are all kept, and a
// revocation among them is not undone.
func TestPolicyChangesAtOnceLoseNothingAndUndoNothing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		return p.Grant(auth.Binding{Principal: "leaver", Role: auth.RoleAdmin, Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := updatePolicy(root, func(p *auth.Policy) error {
				return p.Grant(auth.Binding{Principal: fmt.Sprint("person-", i), Role: auth.RoleReader, Resource: "/"})
			}); err != nil {
				t.Error(err)
			}
		}(i)
		if i == 10 {
			if _, err := updatePolicy(root, func(p *auth.Policy) error {
				p.Revoke("leaver", auth.RoleAdmin, "/")
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	wg.Wait()
	p, _ := loadPolicy(root)
	people := map[string]bool{}
	for _, b := range p.Snapshot() {
		people[b.Principal] = true
	}
	for i := 0; i < 20; i++ {
		if !people[fmt.Sprint("person-", i)] {
			t.Errorf("person-%d's grant was lost", i)
		}
	}
	if people["leaver"] {
		t.Error("a revocation was undone by a writer that read the policy before it")
	}
}

// Two provisioning requests at once both take effect.
func TestProvisioningRequestsAtOnceBothApply(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	var wg sync.WaitGroup
	for _, who := range []string{"ana", "ben", "cho", "dev"} {
		wg.Add(1)
		go func(who string) {
			defer wg.Done()
			if err := scimSync(root, who, []string{"author"}, false); err != nil {
				t.Error(err)
			}
		}(who)
	}
	wg.Wait()
	p, _ := loadPolicy(root)
	for _, who := range []string{"ana", "ben", "cho", "dev"} {
		if !p.Evaluate(who, auth.ActEditDraft, "/").Allowed {
			t.Errorf("%s's provisioning was lost to another request", who)
		}
	}
}

// What separate stores remember at once, as runs in separate processes
// do, is all kept, and a person forgotten stays forgotten.
func TestMemoryWrittenAtOnceLosesNothingAndForgettingHolds(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	now := time.Now()
	remember := func(about, text string) error {
		_, err := memoryStore(root).Remember(memory.Entry{Agent: "tidy", About: about, Kind: memory.Semantic,
			Text: text}, 24*time.Hour, now)
		return err
	}
	if err := remember("pat", "pat prefers email"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := remember(fmt.Sprint("person", i), fmt.Sprint("fact number ", i)); err != nil {
				t.Error(err)
			}
		}(i)
		if i == 10 {
			if _, err := memoryStore(root).Forget("pat"); err != nil {
				t.Fatal(err)
			}
		}
	}
	wg.Wait()
	all, err := memoryStore(root).List(memory.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range all {
		if e.About == "pat" {
			t.Error("a forgotten person's memory came back")
		}
		n++
	}
	if n != 20 {
		t.Errorf("%d of 20 memories survived writers at once", n)
	}
}
