// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

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

// One event by its two names is one trigger, not two.
//
// A manifest refuses a trigger that is the same as an earlier one, by its
// Key, and the Key hashed the event as it was typed. Once either spelling
// was taken, an agent could carry page.published and published side by
// side: both passed as different triggers, both matched every page going
// live, and the agent started twice for each publish, with two days' worth
// of runs between them.
func TestOneEventByBothItsNamesIsOneTrigger(t *testing.T) {
	byEvent := Trigger{On: "page.published", Where: "/blog", Goal: "g"}
	byWire := Trigger{On: "published", Where: "/blog", Goal: "g"}
	if byEvent.Key() != byWire.Key() {
		t.Errorf("one event by two names has two keys: %s and %s", byEvent.Key(), byWire.Key())
	}
	if err := validateTriggers([]Trigger{byEvent, byWire}); err == nil {
		t.Error("an agent was let start twice from one event, named both ways")
	}
	// A trigger that was declared before either spelling was taken keeps
	// its key, so its count for the day and its next time are its own.
	if byEvent.Key() != keyAsDeclared(byEvent) {
		t.Errorf("a trigger on page.published changed its key to %s", byEvent.Key())
	}
	sched := Trigger{On: OnSchedule, Every: Duration(time.Hour), Goal: "g"}
	if sched.Key() != keyAsDeclared(sched) {
		t.Errorf("a schedule changed its key to %s", sched.Key())
	}
}

// keyAsDeclared is Key as it was before an event could be named two ways:
// the trigger's fields as they were typed.
func keyAsDeclared(t Trigger) string {
	h := sha256.Sum256([]byte(strings.Join([]string{t.On, t.Where, time.Duration(t.Every).String(),
		t.At, t.Zone, t.Goal}, "\x00")))
	return hex.EncodeToString(h[:6])
}
