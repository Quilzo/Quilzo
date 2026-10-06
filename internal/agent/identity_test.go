// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"strings"
	"testing"
	"time"
)

func TestAnIdentityHasASponsorAndAnEnd(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	id, err := NewIdentity("dana", "dana", 0, now)
	if err != nil || !id.Expires.Equal(now.Add(DefaultLifetime)) {
		t.Fatalf("%+v %v", id, err)
	}
	for name, bad := range map[string]func() (Identity, error){
		"no sponsor":    func() (Identity, error) { return NewIdentity(" ", "dana", 0, now) },
		"agent sponsor": func() (Identity, error) { return NewIdentity("agent/other", "dana", 0, now) },
		"two words":     func() (Identity, error) { return NewIdentity("dana smith", "dana", 0, now) },
		"too long":      func() (Identity, error) { return NewIdentity("dana", "dana", MaxLifetime+time.Hour, now) },
		"already over":  func() (Identity, error) { return NewIdentity("dana", "dana", -time.Hour, now) },
	} {
		if _, err := bad(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := id.MayRun(true, now); err != nil {
		t.Fatal(err)
	}
	if err := id.MayRun(false, now); err == nil || !strings.Contains(err.Error(), "dana") {
		t.Fatalf("a sponsor who left: %v", err)
	}
	later := now.Add(DefaultLifetime)
	if err := id.MayRun(true, later); err == nil || !strings.Contains(err.Error(), "renew") {
		t.Fatalf("expired: %v", err)
	}
	renewed, err := id.Renew("sam", 30*24*time.Hour, later)
	if err != nil || renewed.MayRun(true, later) != nil || renewed.RenewedBy != "sam" {
		t.Fatalf("renewed: %+v %v", renewed, err)
	}
	if _, err := id.Renew("sam", MaxLifetime+24*time.Hour, later); err == nil {
		t.Fatal("renewed beyond a year")
	}
	var none *Identity
	if none.MayRun(false, now) != nil {
		t.Fatal("an agent from before identities was stopped")
	}
	if (&Identity{}).MayRun(true, now) != ErrNoSponsor {
		t.Fatal("an identity with no sponsor ran")
	}
	if Principal("triage") != "agent/triage" {
		t.Fatal(Principal("triage"))
	}
}

func TestSubtreesAreWholeSegments(t *testing.T) {
	for _, c := range []struct{ a, b, want string }{
		{"/blog", "/blog/2026", "/blog/2026"},
		{"/blog", "/blogger", pathNothing},
		{"blog", "/Blog/post", "/Blog/post"},
		{"", "/docs", "/docs"},
		{"/docs", "/", "/docs"},
	} {
		if got := longerPath(c.a, c.b); got != c.want {
			t.Errorf("%q, %q: %q, want %q", c.a, c.b, got, c.want)
		}
	}
}
