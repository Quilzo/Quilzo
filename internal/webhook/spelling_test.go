// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"slices"
	"testing"
)

// An endpoint subscribes to an event by either of its names, and hears the
// same events whichever it used.
//
// The webhook names (published, booked) and the event names agents and
// staff notices use (page.published, booking.made) were two lists, and
// each surface refused the other's: `quilzo webhook add --types
// page.published` said it was not an event this sends.
func TestAnEndpointSubscribedByEitherSpellingIsToldTheSameEvents(t *testing.T) {
	pairs := [][2]string{{"published", "page.published"}, {"rolled-back", "page.rolled-back"},
		{"submitted", "form.submitted"}, {"proposed", "draft.proposed"}, {"booked", "booking.made"},
		{"booking-cancelled", "booking.cancelled"}, {"subscribed", "subscriber.joined"},
		{"unsubscribed", "subscriber.left"}, {"scheduled", "publish.scheduled"}}
	for _, p := range pairs {
		if !KnownType(p[0]) || !KnownType(p[1]) {
			t.Errorf("%s is known %v and %s %v", p[0], KnownType(p[0]), p[1], KnownType(p[1]))
		}
		byWire, byEvent := Endpoint{Types: []string{p[0]}}, Endpoint{Types: []string{p[1]}}
		for _, sent := range EventTypes {
			if byWire.Wants(sent) != byEvent.Wants(sent) {
				t.Errorf("subscribed as %s and as %s, told %s differently", p[0], p[1], sent)
			}
		}
		if !byEvent.Wants(p[0]) {
			t.Errorf("an endpoint subscribed to %s is not told %s", p[1], p[0])
		}
	}
	// An event webhooks are never told of is not a subscription, by either
	// name, and a name that never existed still hears nothing.
	for _, never := range []string{"record.changed", "approval.waiting", "handoff.requested", "page.deleted"} {
		if KnownType(never) {
			t.Errorf("%q was accepted as something webhooks are told", never)
		}
	}
	stale := Endpoint{Types: []string{"publish"}}
	for _, sent := range EventTypes {
		if stale.Wants(sent) {
			t.Errorf("a subscription to a name that never existed was told %s", sent)
		}
	}
}

// The nine names webhooks are told events by are the nine they were, in
// the order they were: a receiver's configuration and the admin's list
// both depend on them.
func TestTheWebhookNamesAreTheNineTheyWereInTheSameOrder(t *testing.T) {
	want := []string{"published", "rolled-back", "scheduled", "submitted", "proposed",
		"booked", "booking-cancelled", "subscribed", "unsubscribed"}
	if !slices.Equal(EventTypes, want) {
		t.Errorf("EventTypes = %v", EventTypes)
	}
}
