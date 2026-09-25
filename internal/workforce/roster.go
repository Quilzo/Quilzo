// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package workforce

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

// The roster, the one automatic rule, and the count that decides whether any
// other count means anything.

// StaleAfter is how long a device may go without checking in before it stops
// being evidence of anything.
//
// Thirty days. A laptop that has not checked in for a month is either a
// laptop somebody stopped using, one that fell off management, or one
// somebody took with them — and the MDM console reports all three as
// "enrolled", which is why this exists.
const StaleAfter = 30 * 24 * time.Hour

// roleAccounts are local parts that belong to a function rather than a person.
//
// An email match on one of these joins everybody who has ever used the
// mailbox into a single person, which then reports as fully compliant
// because at least one of them did everything.
var roleAccounts = []string{
	"admin", "administrator", "info", "support", "help", "helpdesk",
	"security", "abuse", "postmaster", "noreply", "no-reply", "donotreply",
	"hr", "it", "ops", "sales", "billing", "accounts", "finance", "legal",
	"marketing", "press", "contact", "team", "office", "hello", "careers",
	"jobs", "dpo", "privacy", "compliance",
}

// Roster holds what every system said, and what anybody has asserted about it.
type Roster struct {
	byID  map[string]Identity
	order []string
	links []Link
	// parent is a union-find over identifier strings.
	parent map[string]string
}

// New starts an empty roster.
func New() *Roster {
	return &Roster{byID: map[string]Identity{}, parent: map[string]string{}}
}

// Observe records one system's view of one identity.
//
// The newer observation wins. Two exports of the same directory taken an hour
// apart disagree about who is active, and the older one is not a second
// opinion, it is a stale one.
func (r *Roster) Observe(i Identity) error {
	if err := i.Validate(); err != nil {
		return err
	}
	key := i.ID.String()
	if existing, seen := r.byID[key]; seen {
		if existing.Observed.After(i.Observed) {
			return nil
		}
	} else {
		r.order = append(r.order, key)
		r.parent[key] = key
	}
	r.byID[key] = i
	return nil
}

// Len is how many identities have been observed.
func (r *Roster) Len() int { return len(r.byID) }

// Issuers lists the systems that have been read, sorted.
func (r *Roster) Issuers() []string {
	seen := map[string]bool{}
	for _, i := range r.byID {
		seen[i.ID.Issuer] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (r *Roster) find(k string) string {
	for r.parent[k] != k {
		r.parent[k] = r.parent[r.parent[k]]
		k = r.parent[k]
	}
	return k
}

// Link records an assertion that two identifiers are one person.
func (r *Roster) Link(l Link) error {
	if err := l.Validate(); err != nil {
		return err
	}
	for _, side := range []telemetry.ID{l.A, l.B} {
		if _, seen := r.byID[side.String()]; !seen {
			return fmt.Errorf(
				"%s has not been observed in any system, so linking it joins "+
					"a person to a record nobody has read", side)
		}
	}
	a, b := r.find(l.A.String()), r.find(l.B.String())
	if a != b {
		// The lower string wins, so a person's key does not depend on the
		// order the systems happened to be read in.
		if b < a {
			a, b = b, a
		}
		r.parent[b] = a
	}
	r.links = append(r.links, l)
	return nil
}

// Links returns every assertion made, in the order they were made.
func (r *Roster) Links() []Link { return append([]Link(nil), r.links...) }

// People folds the identities into the sets somebody has asserted.
//
// People only. A service account grouped in here inherits every control that
// asks something of a human — it has no laptop, it has never done the
// training — and the usual fix is an exclusion list that also quietly
// excludes the contractor somebody added to it once.
func (r *Roster) People() []Person {
	groups := map[string]*Person{}
	var devices []Identity
	for _, key := range r.order {
		i := r.byID[key]
		if i.Subject == ADevice {
			devices = append(devices, i)
			continue
		}
		if i.Subject != APerson {
			continue
		}
		root := r.find(key)
		p, ok := groups[root]
		if !ok {
			p = &Person{Key: root, Identities: map[string]Identity{}}
			groups[root] = p
		}
		p.Identities[key] = i
	}
	// Devices hang off whoever their owner resolves to. A device whose owner
	// is unknown belongs to nobody and is reported separately; see Orphans.
	for _, d := range devices {
		if d.Owner.Zero() {
			continue
		}
		owner := d.Owner.String()
		if _, seen := r.byID[owner]; !seen {
			continue
		}
		if p, ok := groups[r.find(owner)]; ok {
			p.Devices = append(p.Devices, d)
		}
	}
	for _, l := range r.links {
		if p, ok := groups[r.find(l.A.String())]; ok {
			p.Links = append(p.Links, l)
		}
	}

	out := make([]Person, 0, len(groups))
	for _, p := range groups {
		sort.Slice(p.Devices, func(i, j int) bool {
			return p.Devices[i].ID.String() < p.Devices[j].ID.String()
		})
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Orphans are the records that joined to nothing.
type Orphans struct {
	// Alone are people present in exactly one system.
	//
	// Not necessarily wrong — a contractor may genuinely only be in the
	// directory — and always worth seeing, because the alternative
	// explanation is that the join failed and nothing else will ever be
	// reported about them.
	Alone []Identity `json:"alone,omitempty"`
	// Unowned are devices whose owner is not a record anybody has read.
	//
	// The worst of the three. A laptop with no owner is outside every
	// per-person control, and the MDM console still counts it as enrolled.
	Unowned []Identity `json:"unowned,omitempty"`
	// Dangling are devices naming an owner in a system that was never read.
	Dangling []Identity `json:"dangling,omitempty"`
}

// Total is how many records joined to nothing.
func (o Orphans) Total() int {
	return len(o.Alone) + len(o.Unowned) + len(o.Dangling)
}

// Services returns the accounts nobody logs into, sorted.
//
// Returned rather than discarded: a service account is still something with
// access, and a deployment that cannot list them cannot review them. It is
// simply not a person, and every control phrased about a person produces a
// wrong answer for it.
func (r *Roster) Services() []Identity {
	var out []Identity
	for _, key := range r.order {
		if i := r.byID[key]; i.Subject == AService {
			out = append(out, i)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID.String() < out[j].ID.String()
	})
	return out
}

// Orphans reports what the join did not manage.
func (r *Roster) Orphans() Orphans {
	var o Orphans
	for _, key := range r.order {
		i := r.byID[key]
		if i.Subject == AService {
			// Not a join failure. A service account existing in one system
			// is a service account.
			continue
		}
		if i.Subject == ADevice {
			switch {
			case i.Owner.Zero():
				o.Unowned = append(o.Unowned, i)
			default:
				if _, seen := r.byID[i.Owner.String()]; !seen {
					o.Dangling = append(o.Dangling, i)
				}
			}
			continue
		}
		root := r.find(key)
		var members int
		for _, other := range r.order {
			if r.byID[other].Subject != APerson {
				continue
			}
			if r.find(other) == root {
				members++
			}
		}
		if members == 1 && len(r.Issuers()) > 1 {
			o.Alone = append(o.Alone, i)
		}
	}
	return o
}

// Proposal is a link this program thinks is probably right.
type Proposal struct {
	A telemetry.ID `json:"a"`
	B telemetry.ID `json:"b"`
	// Rule names what produced it.
	Rule string `json:"rule"`
	// Because is the evidence.
	Because string `json:"because"`
	// Doubt is what would make it wrong.
	//
	// Every proposal carries one. A suggestion with no stated way of being
	// wrong is one somebody accepts in a batch of forty without reading, and
	// the one that was wrong is the shared mailbox that has now joined six
	// people into a single fully-compliant person.
	Doubt string `json:"doubt"`
}

// Propose suggests links from the one automatic rule there is.
//
// Exact match on a normalised email address, across different systems, where
// the address belongs to exactly one identity in each. Deliberately narrow:
// fuzzy name matching is how a reconciliation merges the two Chens, and a
// merge is much harder to notice than a miss.
func (r *Roster) Propose() []Proposal {
	byEmail := map[string][]Identity{}
	for _, key := range r.order {
		i := r.byID[key]
		if i.Subject != APerson {
			continue
		}
		email := normaliseEmail(i.Email)
		if email == "" {
			continue
		}
		byEmail[email] = append(byEmail[email], i)
	}

	var out []Proposal
	for email, ids := range byEmail {
		if len(ids) < 2 {
			continue
		}
		sort.Slice(ids, func(a, b int) bool {
			return ids[a].ID.String() < ids[b].ID.String()
		})
		if role := roleAccount(email); role != "" {
			// Not proposed at all. A role mailbox joins everybody who ever
			// used it into one person who then reports as fully compliant,
			// because at least one of them did everything.
			continue
		}
		perIssuer := map[string]int{}
		for _, i := range ids {
			perIssuer[i.ID.Issuer]++
		}
		var ambiguous bool
		for _, n := range perIssuer {
			if n > 1 {
				ambiguous = true
			}
		}
		if ambiguous || len(perIssuer) < 2 {
			continue
		}
		for n := 1; n < len(ids); n++ {
			if r.find(ids[0].ID.String()) == r.find(ids[n].ID.String()) {
				continue
			}
			out = append(out, Proposal{
				A: ids[0].ID, B: ids[n].ID, Rule: "email",
				Because: fmt.Sprintf(
					"both systems hold %s, and it is the only record with "+
						"that address in either", email),
				Doubt: "an address that was reassigned after somebody left " +
					"joins the leaver's history to whoever has it now",
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].A != out[j].A {
			return out[i].A.String() < out[j].A.String()
		}
		return out[i].B.String() < out[j].B.String()
	})
	return out
}

// Skipped reports the email addresses Propose deliberately refused, and why.
//
// Reported rather than silently dropped. A role mailbox nobody was told about
// looks exactly like a join that simply found nothing, and the two need
// different work.
func (r *Roster) Skipped() map[string]string {
	out := map[string]string{}
	byEmail := map[string][]Identity{}
	for _, key := range r.order {
		i := r.byID[key]
		if i.Subject != APerson {
			continue
		}
		if email := normaliseEmail(i.Email); email != "" {
			byEmail[email] = append(byEmail[email], i)
		}
	}
	for email, ids := range byEmail {
		if len(ids) < 2 {
			continue
		}
		if role := roleAccount(email); role != "" {
			out[email] = fmt.Sprintf(
				"%q is a role mailbox. Joining on it would merge everybody "+
					"who has ever used it into one person, who then reports "+
					"as compliant because at least one of them was", role)
			continue
		}
		perIssuer := map[string]int{}
		for _, i := range ids {
			perIssuer[i.ID.Issuer]++
		}
		for issuer, n := range perIssuer {
			if n > 1 {
				out[email] = fmt.Sprintf(
					"%s holds %d records with this address, so which one "+
						"the other systems mean is that system's question "+
						"to answer first", issuer, n)
			}
		}
	}
	return out
}

func normaliseEmail(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !strings.Contains(s, "@") {
		return ""
	}
	return s
}

// roleAccount returns the matched role local part, or empty.
func roleAccount(email string) string {
	local, _, _ := strings.Cut(email, "@")
	// A plus tag is not part of the identity: security+kandji@ is the
	// security mailbox wearing a label.
	if tagged, _, ok := strings.Cut(local, "+"); ok {
		local = tagged
	}
	for _, r := range roleAccounts {
		if local == r {
			return r
		}
	}
	return ""
}

// Coverage is how much of the join worked, which decides whether anything
// else here means anything.
type Coverage struct {
	Issuers []string `json:"issuers"`
	// People is how many distinct people the join produced.
	People int `json:"people"`
	// Complete is how many appear in every system that was read.
	Complete int `json:"complete"`
	// Partial is how many appear in some but not all.
	Partial int `json:"partial"`
	// Orphaned is how many people appear in only one system.
	//
	// People, not records, because this is compared against People and a
	// figure that mixes the two produces sentences like "11 of 10 records
	// joined to nothing" and "the -1 the join worked for". Devices that
	// belong to nobody are counted in Unowned, which is a different problem
	// with a different fix.
	Orphaned int `json:"orphaned"`
	// Devices and Unowned count the hardware.
	Devices int `json:"devices"`
	Unowned int `json:"unowned"`
	// Services are the accounts nobody logs into, counted apart from people
	// so that a figure about the workforce is about the workforce.
	Services int `json:"services"`
}

// Joined is the share of people present in every system read.
func (c Coverage) Joined() float64 {
	if c.People == 0 {
		return 0
	}
	return float64(c.Complete) / float64(c.People)
}

// Trustworthy reports whether a reconciliation over this is worth quoting.
//
// Two systems at minimum — one system is not a reconciliation — no more than
// a tenth of the people appearing in only one, and no more than a tenth of
// the devices belonging to nobody. Above either, every per-person figure
// derived from this is a figure about the people the join happened to work
// for, and the ones it did not are exactly where the problems are.
func (c Coverage) Trustworthy() bool {
	if len(c.Issuers) < 2 || c.People == 0 {
		return false
	}
	if float64(c.Orphaned) > float64(c.People)/10 {
		return false
	}
	return c.Devices == 0 || float64(c.Unowned) <= float64(c.Devices)/10
}

// Why explains the coverage, leading with what did not join.
func (c Coverage) Why() string {
	switch {
	case len(c.Issuers) < 2:
		return fmt.Sprintf(
			"only %s has been read. One system is an export, not a "+
				"reconciliation", strings.Join(c.Issuers, ", "))
	case c.People == 0:
		return "no people were found in any system"
	case c.Orphaned*10 > c.People:
		return fmt.Sprintf(
			"%d of %d people appear in only one system. Every figure below "+
				"is a figure about the %d the join worked for, and the "+
				"ones it did not are where the problems are",
			c.Orphaned, c.People, c.People-c.Orphaned)
	case !c.Trustworthy():
		return fmt.Sprintf(
			"%d of %d device(s) belong to nobody. A device outside every "+
				"per-person control is still counted as enrolled by the "+
				"console that manages it", c.Unowned, c.Devices)
	case c.Orphaned > 0 || c.Unowned > 0:
		return fmt.Sprintf(
			"%d of %d people appear in all %d systems; %d appear in only "+
				"one, and %d device(s) belong to nobody", c.Complete,
			c.People, len(c.Issuers), c.Orphaned, c.Unowned)
	default:
		return fmt.Sprintf("%d of %d people appear in all %d systems",
			c.Complete, c.People, len(c.Issuers))
	}
}

// Coverage measures the join.
func (r *Roster) Coverage() Coverage {
	issuers := r.Issuers()
	people := r.People()
	orphans := r.Orphans()

	c := Coverage{
		Issuers: issuers, People: len(people),
		Orphaned: len(orphans.Alone),
		Unowned:  len(orphans.Unowned) + len(orphans.Dangling),
	}
	for _, i := range r.byID {
		if i.Subject == ADevice {
			c.Devices++
		}
	}
	for _, i := range r.byID {
		if i.Subject == AService {
			c.Services++
		}
	}
	// Only the systems that hold people count towards completeness: an MDM
	// that holds nothing but devices is not a system somebody is missing
	// from.
	var peopleIssuers []string
	for _, issuer := range issuers {
		for _, i := range r.byID {
			if i.ID.Issuer == issuer && i.Subject == APerson {
				peopleIssuers = append(peopleIssuers, issuer)
				break
			}
		}
	}
	for _, p := range people {
		if len(p.Issuers()) == len(peopleIssuers) {
			c.Complete++
			continue
		}
		c.Partial++
	}
	return c
}
