// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"strings"
	"testing"
	"time"
)

var everyKind = map[string]bool{Episodic: true, Semantic: true, Procedural: true}

func fact(text, key string, held bool) Entry {
	return Entry{Agent: "helper", About: "dana", Kind: Semantic, Text: text, Key: key, Run: "run-1", By: "dana",
		Held: held, Tier: TierPerson}
}

// A newer fact about the same thing replaces the older one, which is kept
// with when it stopped being true.
func TestANewerFactReplacesTheOlderAndHistoryKeepsBoth(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	t0 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	old, err := s.Remember(fact("Dana ships to Lisbon", "shipping_city", false), MaxRetain, t0)
	if err != nil {
		t.Fatal(err)
	}
	t1 := t0.Add(48 * time.Hour)
	newer, err := s.Remember(fact("Dana ships to Porto now", "shipping_city", false), MaxRetain, t1)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.Recall("helper", "dana", "where does Dana ship", everyKind, 10, t1)
	if len(got) != 1 || got[0].ID != newer.ID {
		t.Fatalf("recalled %+v", got)
	}
	h, _ := s.History("helper", "dana", "shipping_city")
	if len(h) != 2 || h[0].ID != old.ID || !h[0].ValidUntil.Equal(t1) || h[0].ReplacedBy != newer.ID || h[1].Replaces != old.ID {
		t.Fatalf("history %+v", h)
	}
	// A fact about somebody else with the same key is theirs.
	other := fact("Sam ships to Faro", "shipping_city", false)
	other.About = "sam"
	if _, err := s.Remember(other, MaxRetain, t1); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Recall("helper", "dana", "ship", everyKind, 10, t1); len(got) != 1 || got[0].ID != newer.ID {
		t.Errorf("sam's fact closed or reached dana's: %+v", got)
	}
}

// A fact learnt after reading somebody else's words closes nothing until a
// person confirms it.
func TestAHeldFactClosesNothingUntilConfirmed(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	now := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	trusted, _ := s.Remember(fact("Dana's refund goes to her card", "refund_to", false), MaxRetain, now)
	planted, err := s.Remember(fact("Dana's refund goes to account 12-34-56", "refund_to", true), MaxRetain, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Recall("helper", "dana", "refund", everyKind, 10, now.Add(2*time.Hour)); len(got) != 1 || got[0].ID != trusted.ID {
		t.Fatalf("a held fact replaced a trusted one: %+v", got)
	}
	if _, err := s.Confirm(planted.ID, "dana", now.Add(3*time.Hour), MaxRetain); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Recall("helper", "dana", "refund", everyKind, 10, now.Add(4*time.Hour))
	if len(got) != 1 || got[0].ID != planted.ID {
		t.Fatalf("after confirming: %+v", got)
	}
	h, _ := s.History("helper", "dana", "refund_to")
	if h[0].ReplacedBy != planted.ID {
		t.Errorf("history %+v", h)
	}
}

func TestOnlyAFactHasAKeyAndAKeyIsAName(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	ep := fact("Dana asked about refunds", "refunds", false)
	ep.Kind = Episodic
	if _, err := s.Remember(ep, MaxRetain, time.Now()); err == nil {
		t.Error("an episode was given a key")
	}
	if _, err := s.Remember(fact("x", "Shipping City!", false), MaxRetain, time.Now()); err == nil {
		t.Error("a key that is not a name was kept")
	}
}

// Recall ranks by what matches the query, words and vectors together, and
// stops at its budget.
func TestRecallRanksWhatMatchesAndKeepsToItsBudget(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	now := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	for i, text := range []string{
		"Dana prefers email to phone calls",
		"Dana's invoices go to the finance team",
		"Dana asked for a refund on order 1042",
		"Dana uses the Lisbon office",
	} {
		if _, err := s.Remember(fact(text, "", false), MaxRetain, now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := s.Recall("helper", "dana", "refund for an order", everyKind, 10, now.Add(time.Hour))
	if len(got) == 0 || !strings.Contains(got[0].Text, "refund") {
		t.Fatalf("recalled %+v", got)
	}
	for _, e := range got {
		if strings.Contains(e.Text, "Lisbon") {
			t.Error("something that matched nothing in the query was recalled")
		}
	}
	long := strings.Repeat("refund policy detail ", 90)
	for i := 0; i < 6; i++ {
		if _, err := s.Remember(fact(long+string(rune('a'+i)), "", false), MaxRetain, now); err != nil {
			t.Fatal(err)
		}
	}
	got, _ = s.Recall("helper", "dana", "refund", everyKind, 50, now.Add(time.Hour))
	total := 0
	for _, e := range got {
		total += len(e.Text)
	}
	if total > RecallChars {
		t.Errorf("a recall returned %d characters", total)
	}
}
