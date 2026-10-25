// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
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
