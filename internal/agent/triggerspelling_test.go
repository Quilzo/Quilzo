// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"

	"github.com/quilzo/quilzo/internal/event"
)

// A trigger names its event by either spelling, and starts from the same
// events whichever it used. `quilzo agent trigger add --on published` was
// refused, while `quilzo webhook add --types page.published` was refused
// the other way round.
func TestATriggerOnEitherSpellingStartsFromTheSameEvent(t *testing.T) {
	published := event.Event{Type: event.PagePublished, Pages: []string{"blog/hello"}}
	for _, on := range []string{"page.published", "published"} {
		tr := Trigger{On: on, Where: "/blog", Goal: "g"}
		if err := tr.Validate(); err != nil {
			t.Errorf("on %s: %v", on, err)
		}
		if !tr.Matches(published) {
			t.Errorf("on %s did not start from a blog post going live", on)
		}
		if got := tr.Describe(); got != "when pages go live (/blog)" {
			t.Errorf("on %s: %q", on, got)
		}
	}
	for _, on := range []string{"publish", "approval.waiting", "scheduled", "publish.scheduled"} {
		if (Trigger{On: on, Goal: "g"}).Validate() == nil {
			t.Errorf("a trigger on %q was accepted", on)
		}
	}
}
