// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package posture

import (
	"strings"
	"testing"
	"time"
)

// A stream failing for an hour is reported, more urgently after a day; one
// that is not set, or fails for a moment, is not.
func TestAStreamThatKeepsFailingIsReported(t *testing.T) {
	r := ruleByID(t, "siem.stream-failing")
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	failing := func(since time.Duration) State {
		return State{Now: now, Stream: StreamFacts{Set: true, Sent: 40, Failures: 3,
			Since: now.Add(-since), Error: "the receiver answered 503"}}
	}
	if got := r.Check(State{Now: now}); len(got) != 0 {
		t.Errorf("no stream: %+v", got)
	}
	if got := r.Check(failing(10 * time.Minute)); len(got) != 0 {
		t.Errorf("a moment's failure: %+v", got)
	}
	got := r.Check(failing(2 * time.Hour))
	if len(got) != 1 || got[0].Severity != Medium || !strings.Contains(got[0].Detail, "503") ||
		!strings.Contains(got[0].Detail, "after record 40") {
		t.Errorf("two hours: %+v", got)
	}
	if got := r.Check(failing(30 * time.Hour)); len(got) != 1 || got[0].Severity != High {
		t.Errorf("a day: %+v", got)
	}
}
