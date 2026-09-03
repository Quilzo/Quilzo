package chat

import (
	"testing"
	"time"
)

// The spender forgets a nonce once its link would have expired anyway, or the
// map grows forever. And it refuses rather than evicting at the ceiling —
// evicting would let a flood of forged links push a real spent nonce out and
// make it replayable.
func TestTheSpenderForgetsExpiredNoncesAndRefusesRatherThanEvicting(t *testing.T) {
	now := time.Now()
	m := NewMemory()
	m.Now = func() time.Time { return now }

	if !m.Spend("a", now.Add(time.Minute)) {
		t.Fatal("a fresh nonce was refused")
	}
	if m.Spend("a", now.Add(time.Minute)) {
		t.Fatal("a spent nonce was accepted again")
	}

	now = now.Add(2 * time.Minute)
	if !m.Spend("b", now.Add(time.Minute)) {
		t.Fatal("a fresh nonce was refused after the sweep")
	}
	if m.Len() != 1 {
		t.Errorf("the expired nonce was not swept; %d remembered", m.Len())
	}

	tight := &Memory{spent: map[string]time.Time{}, MaxEntries: 2,
		Now: func() time.Time { return now }}
	if !tight.Spend("one", now.Add(time.Hour)) || !tight.Spend("two", now.Add(time.Hour)) {
		t.Fatal("the first two nonces were refused")
	}
	if tight.Spend("three", now.Add(time.Hour)) {
		t.Error("a nonce was accepted past the ceiling; the map is unbounded")
	}
	// "one" must still be remembered: refusing at the ceiling rather than
	// evicting is what stops a flood making a real token replayable.
	if tight.Spend("one", now.Add(time.Hour)) {
		t.Error("a previously spent nonce became replayable at the ceiling")
	}
}
