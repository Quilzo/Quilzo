// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package incident

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Rung is one step of an escalation ladder.
type Rung struct {
	// Who is paged at this step.
	Who []string `json:"who"`
	// After is how long to wait for an acknowledgement before the next
	// step. Zero on the last rung means it stops there.
	After time.Duration `json:"after,omitempty"`
	// Why says what this rung is for, so somebody woken at the third step
	// knows why it reached them.
	Why string `json:"why,omitempty"`
}

// Ladder is who gets woken, in what order.
type Ladder struct {
	Name  string `json:"name"`
	Rungs []Rung `json:"rungs"`
}

// MaxWait is the longest a rung may wait before escalating.
//
// Fifteen minutes. A ladder whose first step waits an hour is a ladder that
// has not escalated during the hour that mattered, and the argument for a
// long wait is always that the first person is probably on it — which is
// the assumption acknowledgement exists to replace with a fact.
const MaxWait = 15 * time.Minute

// Validate refuses a ladder that would not escalate.
func (l Ladder) Validate() error {
	if strings.TrimSpace(l.Name) == "" {
		return fmt.Errorf("a ladder needs a name")
	}
	if len(l.Rungs) == 0 {
		return fmt.Errorf("a ladder with no rungs pages nobody")
	}
	if len(l.Rungs) == 1 {
		return fmt.Errorf(
			"%q has one rung, so it does not escalate. A page that goes "+
				"to one person and stops is a message, and the whole "+
				"question is what happens when they are asleep", l.Name)
	}
	seen := map[string]bool{}
	for n, r := range l.Rungs {
		if len(r.Who) == 0 {
			return fmt.Errorf("rung %d of %q pages nobody", n+1, l.Name)
		}
		for _, w := range r.Who {
			if strings.TrimSpace(w) == "" {
				return fmt.Errorf("rung %d of %q pages a blank name",
					n+1, l.Name)
			}
		}
		last := n == len(l.Rungs)-1
		switch {
		case last && r.After != 0:
			return fmt.Errorf(
				"the last rung of %q waits %s and then does what? Either "+
					"it is the end or there is another rung", l.Name,
				plainly(r.After))
		case !last && r.After <= 0:
			return fmt.Errorf(
				"rung %d of %q waits no time before escalating, so every "+
					"rung fires at once and the ladder is one large page",
				n+1, l.Name)
		case !last && r.After > MaxWait:
			return fmt.Errorf(
				"rung %d of %q waits %s and the cap is %s. A ladder whose "+
					"first step waits that long has not escalated during "+
					"the time that mattered", n+1, l.Name,
				plainly(r.After), plainly(MaxWait))
		}
		// The same person twice is not redundancy.
		for _, w := range r.Who {
			k := strings.ToLower(strings.TrimSpace(w))
			if seen[k] && n > 0 {
				return fmt.Errorf(
					"%s is on rung %d of %q and an earlier one. Escalating "+
						"to somebody who has already not answered is the "+
						"ladder pretending to escalate", w, n+1, l.Name)
			}
			seen[k] = true
		}
	}
	return nil
}

// Page is one attempt to reach somebody.
type Page struct {
	Rung int       `json:"rung"`
	Who  []string  `json:"who"`
	Sent time.Time `json:"sent"`
	// Acked is who took it, and when. An empty Acked is the failure this
	// package is about: a page that was sent and not answered has notified
	// nobody, whatever the delivery report says.
	Acked   string    `json:"acked,omitempty"`
	AckedAt time.Time `json:"acked_at,omitzero"`
	Why     string    `json:"why,omitempty"`
}

// Answered reports whether a person took this page.
func (p Page) Answered() bool { return strings.TrimSpace(p.Acked) != "" }

// Raise starts an escalation.
func (i *Incident) Raise(l Ladder, at time.Time) error {
	if err := l.Validate(); err != nil {
		return err
	}
	if i.State == Closed {
		return fmt.Errorf("this incident is closed")
	}
	i.Pages = append(i.Pages, Page{
		Rung: 1, Who: append([]string(nil), l.Rungs[0].Who...),
		Sent: at.UTC(), Why: l.Rungs[0].Why,
	})
	i.note("system", fmt.Sprintf("paged %s",
		strings.Join(l.Rungs[0].Who, ", ")), at)
	return nil
}

// Ack records that somebody has it.
//
// Anybody on the incident may acknowledge, not only the person paged: the
// point is that a human is engaged, and refusing an acknowledgement from
// the colleague who saw it first would mean escalating past somebody who
// is already working.
func (i *Incident) Ack(who string, at time.Time) error {
	who = strings.TrimSpace(who)
	if who == "" {
		return fmt.Errorf("an acknowledgement is somebody's")
	}
	for n := len(i.Pages) - 1; n >= 0; n-- {
		if i.Pages[n].Answered() {
			continue
		}
		i.Pages[n].Acked, i.Pages[n].AckedAt = who, at.UTC()
		i.note(who, "acknowledged", at)
		return nil
	}
	return fmt.Errorf("there is no page outstanding")
}

// Escalate moves to the next rung when the current one has not answered.
//
// Returns whether it moved. A ladder that has run out is not an error and
// is the most serious thing this package reports: everybody on it has been
// paged and nobody has said they have it.
func (i *Incident) Escalate(l Ladder, at time.Time) (bool, error) {
	if err := l.Validate(); err != nil {
		return false, err
	}
	if len(i.Pages) == 0 {
		return false, fmt.Errorf("nothing has been paged yet")
	}
	last := &i.Pages[len(i.Pages)-1]
	if last.Answered() {
		return false, nil
	}
	rung := l.Rungs[last.Rung-1]
	if at.Sub(last.Sent) < rung.After {
		return false, nil // still within the wait
	}
	if last.Rung >= len(l.Rungs) {
		return false, nil // out of ladder
	}
	next := l.Rungs[last.Rung]
	i.Pages = append(i.Pages, Page{
		Rung: last.Rung + 1, Who: append([]string(nil), next.Who...),
		Sent: at.UTC(), Why: next.Why,
	})
	i.note("system", fmt.Sprintf("escalated to %s",
		strings.Join(next.Who, ", ")), at)
	return true, nil
}

// Unanswered is every page nobody took.
func (i *Incident) Unanswered() []Page {
	var out []Page
	for _, p := range i.Pages {
		if !p.Answered() {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		return out[a].Sent.Before(out[b].Sent)
	})
	return out
}

// Engaged reports whether a human has confirmed they have this.
func (i *Incident) Engaged() bool {
	for _, p := range i.Pages {
		if p.Answered() {
			return true
		}
	}
	return false
}

// Exhausted reports whether the ladder ran out with nobody answering.
//
// The worst thing here. Everybody on the ladder has been paged, none of
// them has said they have it, and there is nobody left to escalate to —
// which means the response depends on somebody noticing rather than on
// anything the system did.
func (i *Incident) Exhausted(l Ladder) bool {
	if i.Engaged() || len(i.Pages) == 0 {
		return false
	}
	return i.Pages[len(i.Pages)-1].Rung >= len(l.Rungs)
}

// Silence is how long nobody has answered.
func (i *Incident) Silence(now time.Time) time.Duration {
	if i.Engaged() || len(i.Pages) == 0 {
		return 0
	}
	return now.Sub(i.Pages[0].Sent)
}

// Trouble is what is wrong with the response itself, worst first.
//
// The response to an incident is a process that can fail, and it fails
// quietly: nobody acknowledged, nobody is commanding, a clock nobody
// started. Each of those is invisible from inside the incident, because
// everybody is busy with the incident.
type Trouble struct {
	What   string `json:"what"`
	Weight int    `json:"weight"`
	Detail string `json:"detail,omitempty"`
}

// Weights, stated rather than buried in comparisons.
const (
	// NobodyHasIt: paged, unanswered, ladder exhausted.
	NobodyHasIt = 100
	// Overdue: a regulatory deadline has passed.
	Overdue = 90
	// Unanswered: paged and not yet acknowledged.
	Unanswered = 80
	// Imminent: a deadline inside the hour.
	Imminent = 70
	// NoClock: an obligation whose trigger nobody has recorded.
	NoClock = 60
	// NoCommander: a declared incident nobody is running.
	NoCommander = 50
)

// Look reports what is wrong with the response.
func (i *Incident) Look(l Ladder, now time.Time) []Trouble {
	var out []Trouble
	if i.State == Closed {
		return nil
	}
	if i.Exhausted(l) {
		out = append(out, Trouble{Weight: NobodyHasIt,
			What: "the ladder is exhausted and nobody has acknowledged",
			Detail: fmt.Sprintf("%s of silence since the first page. The "+
				"response now depends on somebody noticing rather than on "+
				"anything this did", plainly(i.Silence(now)))})
	} else if len(i.Unanswered()) > 0 && !i.Engaged() {
		out = append(out, Trouble{Weight: Unanswered,
			What: fmt.Sprintf("%d page(s) unanswered",
				len(i.Unanswered())),
			Detail: "a page that was sent and not answered has notified " +
				"nobody, whatever the delivery report says"})
	}
	for _, d := range i.Duties(now) {
		switch {
		case d.Late():
			out = append(out, Trouble{Weight: Overdue,
				What:   d.Regime + " is " + d.Says(),
				Detail: "tell " + d.Who + ": " + d.What})
		case d.Soon():
			out = append(out, Trouble{Weight: Imminent,
				What:   d.Regime + ", " + d.Says(),
				Detail: "tell " + d.Who + ": " + d.What})
		}
	}
	for _, d := range i.Unstarted(now) {
		out = append(out, Trouble{Weight: NoClock,
			What:   "no clock on " + d.Regime,
			Detail: d.Says()})
	}
	if i.Grade.Wakes() && strings.TrimSpace(i.Filled[Commander]) == "" {
		out = append(out, Trouble{Weight: NoCommander,
			What: "nobody is commanding this",
			Detail: "a " + string(i.Grade) + " with no commander is " +
				"several people fixing what each of them thinks is wrong"})
	}
	sort.SliceStable(out, func(a, b int) bool {
		return out[a].Weight > out[b].Weight
	})
	return out
}
