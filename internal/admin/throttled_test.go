// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/throttle"
)

// throttle.Snapshot and Limiter.State were written "for `quilzo auth
// throttled`", which does not exist — and could not, as written: the counters
// live in the memory of the process holding the limiter, and the command line
// is a different process. So auth.lockout.hard could be switched on and its
// consequences were unobservable on every surface.
func TestTheSecurityScreenShowsWhoIsBeingSlowedDown(t *testing.T) {
	s := &Server{}
	if got := s.throttled(); got != nil {
		t.Errorf("a server with no limiter reported %d subject(s)", len(got))
	}

	policy := throttle.Default()
	policy.After = 1
	s.Throttle = throttle.New(policy)
	if got := s.throttled(); len(got) != 0 {
		t.Fatalf("a quiet limiter reported %d subject(s)", len(got))
	}

	sub := throttle.Subject{Source: "203.0.113.5"}
	for i := 0; i < 8; i++ {
		s.Throttle.Fail(sub)
	}

	got := s.throttled()
	if len(got) == 0 {
		t.Fatal("eight failures from one address and the screen shows nothing")
	}
	if got[0].Failures != 8 {
		t.Errorf("%d failures on record, eight were made", got[0].Failures)
	}
	if got[0].RetryIn <= 0 {
		t.Error("the subject is past its free attempts and is not being delayed")
	}
}

// The alert threshold has to be visible, or crossing it is something only the
// audit log knows.
func TestCrossingTheAlertThresholdIsVisible(t *testing.T) {
	policy := throttle.Default()
	policy.After, policy.Alert = 1, 3
	s := &Server{Throttle: throttle.New(policy)}

	sub := throttle.Subject{Source: "198.51.100.9"}
	for i := 0; i < 6; i++ {
		s.Throttle.Fail(sub)
	}
	got := s.throttled()
	if len(got) == 0 {
		t.Fatal("nothing on record")
	}
	if !got[0].Alerted {
		t.Error("six failures against an alert threshold of three is not marked")
	}
}

// The screen has to render it, not merely have it in the map.
func TestTheSecurityTemplateRendersTheThrottleState(t *testing.T) {
	src, err := assets.ReadFile("assets/security.html")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	for _, want := range []string{".Throttled", ".Failures", ".Locked", ".Alerted"} {
		if !strings.Contains(body, want) {
			t.Errorf("the security screen does not render %s", want)
		}
	}
	// And it must not claim to name anybody: the limiter holds HMACs, so the
	// screen cannot say who and must not imply it can.
	if strings.Contains(body, "{{.Principal}}</td>") {
		t.Error("the throttle table appears to name principals, and the " +
			"limiter cannot say who")
	}
}
