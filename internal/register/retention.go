// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import "time"

// How long the side store keeps what each kind's records name.
//
// A record is kept for good: it is evidence, and the register cannot forget
// it without breaking every hash above it. What it names by digest, the
// free text a person wrote and the raw file a fact was read from, is kept
// beside it in the side store, and that is what a retention period is
// about. When every kind whose records named an entry has kept it for as
// long as it says, the server's upkeep deletes it (ExpireSide), and the
// record says its words are gone.
//
// A period is counted from the last time a record of the kind named the
// entry, so a fact read again today keeps today's raw file. A kind with no
// period keeps what it names until a person erases it: a decision's words
// and a risk's description are the record of why, and an organisation
// decides when those go, not a timer.
//
// The periods are written here, by kind, so the data inventory, the
// command line and the screens read one table, and the kinds' own files
// are not edited to say them.
var retention = map[Kind]int{
	// A raw file a fact was read from: a year of an audit period, and a
	// month to finish the audit in.
	KindObservation: 400,
	// What a model read out of a document, and the quote: as long as the
	// facts it may become.
	KindExtracted: 400,
	// The raw evidence behind a statement about a control: three years, an
	// ISO 27001 certification cycle.
	KindEvidence: 1096,
	// What is known about an incident: six years, the period most
	// regulators' record keeping asks of a notifiable one.
	KindIncident: 2192,
}

func init() {
	for k, days := range retention {
		kinds[k].RetainDays = days
	}
}

// RetentionOf is how long the side store keeps what a kind's records name,
// or zero for a kind that keeps it until a person erases it.
func RetentionOf(k Kind) time.Duration {
	s, ok := kinds[k]
	if !ok {
		return 0
	}
	return time.Duration(s.RetainDays) * 24 * time.Hour
}
