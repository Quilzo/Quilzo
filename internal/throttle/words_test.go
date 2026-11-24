// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package throttle

import (
	"strings"
	"testing"
	"time"
)

// How long to wait is said as a person says it, and never shorter than it
// is. It was Go's own rendering, which a person signing in read on the
// sign-in page: "Try again in 1s", "Nothing further is accepted for
// 59m32s".
func TestHowLongToWaitIsSaidInWords(t *testing.T) {
	now := start
	l := at(New(Default()), &now)
	s := Subject{Source: "203.0.113.9"}
	for range 6 {
		l.Fail(s)
	}
	if d := l.Check(s); !strings.HasSuffix(d.Why, "Try again in 1 second.") {
		t.Errorf("slowed: %q", d.Why)
	}
	for range 94 {
		l.Fail(s)
	}
	now = now.Add(28 * time.Second)
	if d := l.Check(s); !d.Locked || !strings.Contains(d.Why, "Nothing further is accepted for an hour.") {
		t.Errorf("at the ceiling: %q", d.Why)
	}
	for _, c := range []struct {
		d    time.Duration
		want string
	}{
		{300 * time.Millisecond, "1 second"}, {2 * time.Second, "2 seconds"}, {59*time.Second + time.Millisecond, "1 minute"},
		{90 * time.Second, "2 minutes"}, {59*time.Minute + 32*time.Second, "an hour"}, {15 * time.Minute, "15 minutes"},
	} {
		if got := inWords(c.d); got != c.want {
			t.Errorf("%s is %q, not %q", c.d, got, c.want)
		}
	}
	// And as a screen shows who is being slowed down.
	for _, c := range []struct{ got, want string }{
		{Snapshot{Since: 500 * time.Millisecond}.Over(), "under a second"},
		{Snapshot{Since: 42*time.Second + time.Millisecond}.Over(), "42 seconds"},
		{Snapshot{Since: 3*time.Minute + 12348*time.Millisecond}.Over(), "3 minutes"},
		{Snapshot{RetryIn: 1500 * time.Millisecond}.Next(), "2 seconds"},
		{Snapshot{}.Next(), ""},
	} {
		if c.got != c.want {
			t.Errorf("%q, not %q", c.got, c.want)
		}
	}
}
