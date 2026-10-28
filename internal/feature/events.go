// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import "fmt"

// The events block: which of the package's listings is the site's events
// (site.events), so a site built or proposed with an events page arrives
// with its calendar at /events.ics and Event data on each event's page.
// One site has one events listing, so one package owns it, and one somebody
// set by hand is theirs.

// EventsRef is the events block's ref.
var EventsRef = Ref{Kind: "events", Name: "events"}

func validateEvents(p *Package, bad func(string, ...any)) {
	if p.Events == "" {
		return
	}
	for _, l := range p.Listings {
		if l.Name != p.Events {
			continue
		}
		if l.Exposes() {
			return
		}
		have := map[string]bool{}
		for _, f := range l.Fields {
			have[f] = true
		}
		for _, need := range []string{"title", "date"} {
			if !have[need] {
				bad("events: listing %q does not show %q, which every event needs", l.Name, need)
			}
		}
		return
	}
	bad("events: %q is not a listing this package declares", p.Events)
}

// eventsLine is what the card says the block shows.
func eventsLine(p *Package) Line {
	return Line{Text: fmt.Sprintf("Listing %q is the site's events: a calendar anybody can subscribe to at "+
		"/events.ics, and when and where on each event's page for search engines and assistants", p.Events),
		Flag: "public"}
}
