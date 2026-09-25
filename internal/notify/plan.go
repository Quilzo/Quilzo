// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package notify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Deciding who gets a notice, showing the decision, and only then sending.
//
// # Two phases, for the same reason retention has two
//
// A notice cannot be recalled. Plan works out who would be told and who would
// not and why; Send takes a plan. In between, a person reads it — and during
// a breach, when this is used in anger, that reading is the only thing
// standing between a hurried incident lead and a message telling four
// thousand unaffected customers that their data has leaked.
//
// # One delivery each, never a recipient list
//
// Every delivery is addressed to exactly one contact. The single commonest
// data breach caused by breach notification is the notification itself: a
// mail to two hundred affected customers with the addresses in Cc, which
// discloses to each of them that the others are customers and were affected.
// There is no API here that takes more than one address, so it cannot be
// done by being in a hurry.
//
// # Sending twice is a harm
//
// Every delivery carries a key derived from the notice and the contact, and
// the outbox refuses a key it has already accepted. A retry after a crash
// re-sends nothing. Telling somebody twice that their data has leaked is not
// a duplicate email; it is a second shock, and for a customer relaying it to
// their own users it is a second false alarm.

// Delivery is one notice going to one contact.
type Delivery struct {
	// Key is the idempotency handle: notice and contact, nothing else.
	Key     string       `json:"key"`
	Notice  string       `json:"notice"`
	To      telemetry.ID `json:"to"`
	Channel Channel      `json:"channel"`
	// Address is where it goes. Present in a plan and never in a record.
	Address string `json:"address,omitempty"`
	// Fingerprint is what the record keeps instead.
	Fingerprint string    `json:"fingerprint,omitempty"`
	At          time.Time `json:"at,omitempty"`
}

// DeliveryKey derives the idempotency handle.
func DeliveryKey(notice string, to telemetry.ID) string {
	sum := sha256.Sum256([]byte(notice + "\x00" + to.String()))
	return hex.EncodeToString(sum[:])[:24]
}

// Withheld is somebody who is not being told, and why.
type Withheld struct {
	To  telemetry.ID `json:"to"`
	Why string       `json:"why"`
}

// Plan is who would be told.
type Plan struct {
	Notice string     `json:"notice"`
	Kind   Kind       `json:"kind"`
	Send   []Delivery `json:"send,omitempty"`
	Hold   []Withheld `json:"hold,omitempty"`
	// Unreachable counts people who are affected and cannot be reached.
	//
	// Separated from the rest of Hold because for a breach it is the number
	// that decides whether Article 34(3)(c) applies, and a plan that buried
	// it among ordinary opt-outs would be hiding the one figure a regulator
	// asks about.
	Unreachable int `json:"unreachable"`
	// Missing names affected identifiers that are not on the list at all.
	Missing []telemetry.ID `json:"missing,omitempty"`
	Made    time.Time      `json:"made"`
}

// Empty reports whether the plan would send nothing.
func (p Plan) Empty() bool { return len(p.Send) == 0 }

// Why explains a plan in one line.
func (p Plan) Why() string {
	switch {
	case p.Empty() && p.Unreachable > 0:
		return fmt.Sprintf(
			"nobody would be told: %d of the people affected cannot be "+
				"reached, which is the Article 34(3)(c) conversation",
			p.Unreachable)
	case p.Empty():
		return "nobody on the list may lawfully be sent this"
	case p.Unreachable > 0:
		return fmt.Sprintf(
			"%d contact(s) would be told and %d of the people affected "+
				"cannot be reached at all", len(p.Send), p.Unreachable)
	case len(p.Hold) > 0:
		return fmt.Sprintf("%d contact(s) would be told, %d withheld",
			len(p.Send), len(p.Hold))
	default:
		return fmt.Sprintf("%d contact(s) would be told", len(p.Send))
	}
}

// Prepare works out who gets a notice. It sends nothing.
func Prepare(n Notice, a *Audience, now time.Time) (Plan, error) {
	if err := n.Validate(); err != nil {
		return Plan{}, err
	}
	p := Plan{Notice: n.ID, Kind: n.Kind, Made: now}

	want := a.All()
	if len(n.Affected) > 0 {
		want = nil
		for _, id := range n.Affected {
			c, ok := a.Find(id)
			if !ok {
				// Named as affected and not on the list. For a breach this
				// is the most important line in the output: somebody whose
				// data leaked and who cannot be told.
				p.Missing = append(p.Missing, id)
				p.Unreachable++
				continue
			}
			want = append(want, *c)
		}
	}

	seen := map[string]bool{}
	for _, c := range want {
		ok, why := c.MayReceive(n.Kind)
		if !ok {
			p.Hold = append(p.Hold, Withheld{To: c.ID, Why: why})
			if len(n.Affected) > 0 && !c.Objects(n.Kind) {
				// Affected, and no lawful route to them. An objection is not
				// unreachability — for a breach it does not apply at all,
				// and MayReceive has already said so.
				p.Unreachable++
			}
			continue
		}
		key := DeliveryKey(n.ID, c.ID)
		if seen[key] {
			continue
		}
		seen[key] = true
		p.Send = append(p.Send, Delivery{
			Key: key, Notice: n.ID, To: c.ID, Channel: c.Channel,
			Address: c.Address, Fingerprint: c.Fingerprint,
		})
	}
	sort.Slice(p.Send, func(i, j int) bool { return p.Send[i].Key < p.Send[j].Key })
	sort.Slice(p.Hold, func(i, j int) bool {
		return p.Hold[i].To.String() < p.Hold[j].To.String()
	})
	return p, nil
}

// Sender delivers one notice to one address.
//
// One at a time, on purpose. A sender that took a list would be an API that
// lets a hurried person put two hundred affected customers in one mail, and
// that mail is itself a breach.
type Sender interface {
	Send(n Notice, d Delivery) error
}

// Outbox records what has been sent and refuses to send it twice.
type Outbox struct {
	done map[string]time.Time
}

// NewOutbox starts an empty one.
func NewOutbox() *Outbox { return &Outbox{done: map[string]time.Time{}} }

// Load restores what a previous run sent.
func (o *Outbox) Load(done map[string]time.Time) {
	for k, v := range done {
		o.done[k] = v
	}
}

// Done returns what has been sent.
func (o *Outbox) Done() map[string]time.Time {
	out := make(map[string]time.Time, len(o.done))
	for k, v := range o.done {
		out[k] = v
	}
	return out
}

// Sent reports whether a delivery has already gone.
func (o *Outbox) Sent(key string) bool {
	_, yes := o.done[key]
	return yes
}

// Result is what a send run did.
type Result struct {
	Sent    []Delivery `json:"sent,omitempty"`
	Skipped []Delivery `json:"skipped,omitempty"`
	// Failed carries the deliveries that did not go, with why. A failure is
	// not a reason to stop: the other nine hundred people affected are still
	// entitled to be told, and a loop that aborted on the first bad address
	// would make one stale mailbox into a failure to notify.
	Failed []Failure `json:"failed,omitempty"`
}

// Failure is one delivery that did not go.
type Failure struct {
	Delivery Delivery `json:"delivery"`
	Why      string   `json:"why"`
}

// Deliver carries out a plan.
//
// Refuses a plan made against a different audience than the one in front of
// it: between planning and sending, somebody may have been erased, objected
// or been added, and the list a person approved has to be the list that goes.
func Deliver(n Notice, p Plan, o *Outbox, s Sender, now time.Time) (
	Result, error) {

	var r Result
	if p.Made.IsZero() {
		return r, fmt.Errorf(
			"that plan was never made by Prepare, so nobody has seen who it " +
				"would tell")
	}
	if p.Notice != n.ID {
		return r, fmt.Errorf(
			"the plan is for notice %s and this is %s", p.Notice, n.ID)
	}
	if err := n.Validate(); err != nil {
		return r, err
	}
	for _, d := range p.Send {
		if o.Sent(d.Key) {
			r.Skipped = append(r.Skipped, d)
			continue
		}
		d.At = now
		if err := s.Send(n, d); err != nil {
			r.Failed = append(r.Failed, Failure{Delivery: d, Why: err.Error()})
			continue
		}
		// Recorded after the send, never before. A record written first and
		// then a crash means somebody was never told and the system believes
		// they were, which for a breach notice is the failure that matters.
		o.done[d.Key] = now
		r.Sent = append(r.Sent, d)
	}
	return r, nil
}

// Record is the audit entry for one delivery.
//
// The fingerprint, never the address. A log of who was told about a breach
// that also holds their email addresses is a second copy of the list, kept
// for years, in the file an auditor is given.
func (d Delivery) Record(n Notice, author string, kind audit.Kind) audit.Record {
	return audit.Record{
		Action: "notice.delivered", Resource: "/notice/" + n.ID,
		Outcome: audit.Success, Principal: author, Kind: kind,
		Verified: kind != audit.KindUnknown,
		Detail: map[string]string{
			"notice":    n.ID,
			"notice_of": string(n.Kind),
			"channel":   string(d.Channel),
			// The contact, pseudonymously. Enough to prove somebody was
			// told and to answer them when they ask, and not a copy of the
			// address.
			"contact": contactHandle(d),
		},
	}
}

func contactHandle(d Delivery) string {
	if d.Fingerprint != "" {
		return d.Fingerprint
	}
	// An in-app contact has no address to fingerprint. The identifier is
	// already pseudonymous as far as this log is concerned, and the audit
	// log pseudonymises principals rather than details, so it is hashed here.
	sum := sha256.Sum256([]byte(d.To.String()))
	return "c_" + hex.EncodeToString(sum[:])[:32]
}

// Summary is a one-line description of what a result did.
func (r Result) Summary() string {
	parts := []string{fmt.Sprintf("%d sent", len(r.Sent))}
	if len(r.Skipped) > 0 {
		parts = append(parts,
			fmt.Sprintf("%d already told", len(r.Skipped)))
	}
	if len(r.Failed) > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", len(r.Failed)))
	}
	return strings.Join(parts, ", ")
}
