// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package event

// One vocabulary, two spellings.
//
// Webhooks were told of events by names of their own (published, booked)
// before this package existed, and receivers are configured for them, so
// those names stay on the wire. Agents' triggers and staff notices use the
// names here (page.published, booking.made). They were two lists, bridged
// one way by a switch in the command line that had no case for
// "scheduled", and every surface refused the other's spelling: `quilzo
// webhook add --types page.published` was "not an event this sends", and
// `quilzo config set notify.events published` was "not an event".
//
// This table is the bridge, the only one. Parse reads either spelling; the
// webhook package takes its list, its check and its filter from here.
var webhookNames = []struct {
	wire string
	t    Type
}{
	{"published", PagePublished},
	{"rolled-back", PageRolledBack},
	{"scheduled", PublishScheduled},
	{"submitted", FormSubmitted},
	// A change is waiting for somebody to agree to it.
	//
	// Dual authorisation only works if the people it waits on find out they
	// are being waited on. Without this the approval screen is a page
	// somebody has to think to open, which means a proposal sits until its
	// author asks in person -- and the reliable way to stop being asked in
	// person is to turn the requirement off.
	//
	// It carries who proposed and whether a machine wrote it. That second
	// part is the one that decides whether a person has to read it, so it is
	// the part worth putting in front of them rather than behind a click.
	{"proposed", DraftProposed},
	// A visitor booked a time, or cancelled one: the moment a business
	// taking bookings needs to hear about, as a form's "submitted" is.
	{"booked", BookingMade},
	{"booking-cancelled", BookingCancelled},
	// Somebody confirmed they want the newsletter, or left it: which, and
	// never the address.
	{"subscribed", SubscriberJoined},
	{"unsubscribed", SubscriberLeft},
}

// WebhookNames lists the names webhooks are told events by, in the order
// they have always been listed.
func WebhookNames() []string {
	out := make([]string, len(webhookNames))
	for i, n := range webhookNames {
		out[i] = n.wire
	}
	return out
}

// WebhookName is the name webhooks are told t by, and whether they are
// told of it at all.
func WebhookName(t Type) (string, bool) {
	for _, n := range webhookNames {
		if n.t == t {
			return n.wire, true
		}
	}
	return "", false
}

// Parse reads an event by either of its names: its own (page.published)
// or the one webhooks are told it by (published). Anything else is no
// event, as before: the list is closed so that nothing subscribes to what
// never happens.
func Parse(s string) (Type, bool) {
	if Known(Type(s)) {
		return Type(s), true
	}
	for _, n := range webhookNames {
		if n.wire == s {
			return n.t, true
		}
	}
	return "", false
}
