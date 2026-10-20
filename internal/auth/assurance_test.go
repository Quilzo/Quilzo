// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"testing"
	"time"
)

// A session is worth to a thief what the token it came from is worth: a
// copied month-long bearer token exchanged for minutes, even with a key
// of the copier's choosing, is still a month-long bearer token. A session
// from a bound token, whose own key had to prove the exchange, is short
// and bound.
func TestASessionIsWorthWhatItCameFrom(t *testing.T) {
	ts := &TokenStore{}
	now := time.Now()
	month := 30 * 24 * time.Hour
	long, _, err := ts.Issue("ci", "dana", RoleAdmin, "/", month, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	_, plain, err := ts.Exchange(long, RoleNone, "", 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if life, bound := plain.Assurance(); bound || life != month {
		t.Errorf("a session from a bearer token is worth %s, bound %v", life, bound)
	}
	_, keyed, err := ts.ExchangeProved(long, RoleNone, "", 0, "copiers-key", now)
	if err != nil {
		t.Fatal(err)
	}
	if keyed.Key != "copiers-key" {
		t.Fatalf("the session is not bound to the key that proved the exchange: %+v", keyed)
	}
	if life, bound := keyed.Assurance(); bound || life != month {
		t.Errorf("a key the copier chose made the session worth %s, bound %v", life, bound)
	}

	owned, ot, err := ts.Issue("program", "dana", RoleAdmin, "/", 7*24*time.Hour, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.BindKey(ot.ID, "owners-key"); err != nil {
		t.Fatal(err)
	}
	_, fromBound, err := ts.ExchangeProved(owned, RoleNone, "", 0, "owners-key", now)
	if err != nil {
		t.Fatal(err)
	}
	if life, bound := fromBound.Assurance(); !bound || life > DefaultSessionTTL || fromBound.Inherits != 0 {
		t.Errorf("a session from a bound token is worth %s, bound %v", life, bound)
	}
	if _, _, err := ts.ExchangeProved(owned, RoleNone, "", 0, "copiers-key", now); err == nil {
		t.Error("a bound token was exchanged with another key")
	}

	short, _, err := ts.Issue("job", "ci", RolePublisher, "/", 30*time.Minute, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	_, fromShort, err := ts.Exchange(short, RoleNone, "", 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if life, _ := fromShort.Assurance(); life != 30*time.Minute {
		t.Errorf("a session from a half-hour token is worth %s", life)
	}
}
