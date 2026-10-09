// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package rate

import (
	"fmt"
	"testing"
	"time"
)

// A burst at once, then the steady pace, and another key is not affected.
func TestABurstThenASteadyPace(t *testing.T) {
	l := PerHour(120, 20) // one every 30s, twenty at once
	now := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		if ok, _ := l.Allow("a", now); !ok {
			t.Fatalf("question %d of the burst refused", i+1)
		}
	}
	ok, wait := l.Allow("a", now)
	if ok || wait <= 0 || wait > 30*time.Second {
		t.Fatalf("the 21st at once: ok=%v wait=%s", ok, wait)
	}
	if ok, _ := l.Allow("b", now); !ok {
		t.Fatal("another visitor paid for the first one's questions")
	}
	if ok, _ := l.Allow("a", now.Add(30*time.Second)); !ok {
		t.Fatal("the steady pace did not refill")
	}
	// Steady use at the rate is never refused.
	m := PerHour(120, 20)
	for i := 0; i < 500; i++ {
		if ok, _ := m.Allow("c", now.Add(time.Duration(i)*30*time.Second)); !ok {
			t.Fatalf("question %d at the steady rate refused", i)
		}
	}
}

func TestKeysAreBounded(t *testing.T) {
	l := PerHour(60, 1)
	l.MaxKeys = 100
	now := time.Now()
	for i := 0; i < 1000; i++ {
		l.Allow(fmt.Sprint(i), now)
	}
	if len(l.tat) > 100 {
		t.Fatalf("%d keys kept", len(l.tat))
	}
}
