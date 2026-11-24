// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package event

import (
	"slices"
	"testing"
)

// Both spellings of an event are the same event, and nothing else is one.
func TestBothSpellingsOfAnEventAreTheSameEvent(t *testing.T) {
	for wire, want := range map[string]Type{
		"published": PagePublished, "rolled-back": PageRolledBack, "scheduled": PublishScheduled,
		"submitted": FormSubmitted, "proposed": DraftProposed, "booked": BookingMade,
		"booking-cancelled": BookingCancelled, "subscribed": SubscriberJoined, "unsubscribed": SubscriberLeft,
	} {
		if got, ok := Parse(wire); !ok || got != want {
			t.Errorf("Parse(%q) = %q, %v; want %q", wire, got, ok, want)
		}
		if got, ok := Parse(string(want)); !ok || got != want {
			t.Errorf("Parse(%q) = %q, %v", want, got, ok)
		}
		if back, ok := WebhookName(want); !ok || back != wire {
			t.Errorf("WebhookName(%q) = %q, %v; want %q", want, back, ok, wire)
		}
	}
	for _, t2 := range []Type{RecordChanged, HandoffRequested, ChatbotUnanswered, ApprovalWaiting} {
		if got, ok := Parse(string(t2)); !ok || got != t2 {
			t.Errorf("Parse(%q) = %q, %v", t2, got, ok)
		}
		if _, ok := WebhookName(t2); ok {
			t.Errorf("%s is told to webhooks", t2)
		}
	}
	for _, never := range []string{"", "publish", "PUBLISHED", "page.deleted", "test"} {
		if _, ok := Parse(never); ok {
			t.Errorf("%q was read as an event", never)
		}
	}
}

// What an agent can start from is what it could, the same eleven, and a
// scheduled publish, an event now, is not among them.
func TestTheEventsAnAgentCanStartFromAreUnchanged(t *testing.T) {
	want := []Type{PagePublished, PageRolledBack, DraftProposed, RecordChanged, FormSubmitted,
		HandoffRequested, ChatbotUnanswered, BookingMade, BookingCancelled, SubscriberJoined, SubscriberLeft}
	if !slices.Equal(Types(), want) {
		t.Errorf("Types() = %v", Types())
	}
	for _, e := range want {
		if !Triggerable(e) {
			t.Errorf("%s is no longer something an agent starts from", e)
		}
	}
	if Triggerable(PublishScheduled) || Triggerable(ApprovalWaiting) || !Known(PublishScheduled) {
		t.Error("publish.scheduled is not an event no agent starts from")
	}
}
