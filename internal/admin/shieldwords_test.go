// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/shield"
	"github.com/quilzo/quilzo/internal/throttle"
)

// The Shield screen counts a playbook's verdicts in agreement with their
// number: it said "2 a mistake".
func TestTheShieldScreenCountsVerdictsInWords(t *testing.T) {
	for _, c := range []struct {
		r    shield.Record
		want string
	}{
		{shield.Record{Applied: 1, Mistakes: 1}, "0 judged right, 1 judged a mistake:"},
		{shield.Record{Applied: 3, Right: 1, Mistakes: 2}, "1 judged right, 2 judged mistakes:"},
	} {
		if got := shieldPrecision(c.r, 0, time.Time{}); !strings.Contains(got, c.want) {
			t.Errorf("%q, not %q", got, c.want)
		}
	}
}

// The Security screen's sign-ins being slowed down say how long, and how
// long until the next attempt, in words. They were time.Duration values
// written straight into the page: "Over 3m12.348276112s".
func TestTheSlowedSignInsAreTimedInWords(t *testing.T) {
	srv, token := setup(t)
	withPosture(srv, brokenPosture())
	first := time.Now()
	now := first
	srv.Throttle = throttle.New(throttle.Default()).WithClock(func() time.Time { return now })
	for range 8 {
		srv.Throttle.Fail(throttle.Subject{Source: "203.0.113.5"})
	}
	now = first.Add(3*time.Minute + 12348276112*time.Nanosecond - 3*time.Second)
	body := get(t, srv, "/security", token).Body.String()
	if !strings.Contains(body, "Sign-ins being slowed down") {
		t.Fatal("the screen does not show the slowed sign-ins")
	}
	if raw := regexp.MustCompile(`<td>[0-9.]+(ns|µs|ms|s|m[0-9.]+s|h[0-9.]+m[0-9.]+s)</td>`).FindString(body); raw != "" {
		t.Errorf("a time is Go's own rendering: %s", raw)
	}
	if !strings.Contains(body, "<td>3 minutes</td>") {
		t.Errorf("the time the failures have gone on is not in words")
	}
}
