// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package review is the access review, and the four ways one is completed
// without happening.
//
// # The rubber stamp
//
// A manager is sent forty people and clicks approve on all of them in ninety
// seconds. The campaign closes at a hundred per cent. The evidence shows a
// completed review, the auditor sees a completed review, and nothing was
// reviewed.
//
// Every product in this space reports completion rate, because completion
// rate is what a customer asks for and what a dashboard can show. Nothing
// reports the shape of the completion, which is the only part that
// distinguishes a review from a formality.
//
// So this measures it: how long each decision took, how many went one way,
// and whether the whole campaign was decided in a single sitting. Not as an
// accusation — as a property of the evidence, the way internal/assurance
// reports a control that has never failed. An auditor sampling this asks the
// question anyway, and the version where they ask it first is the expensive
// one.
//
// # The reviewer is the wrong person
//
// The review is usually run by whoever can export the account list, and they
// are precisely the people who do not know whether this person needs access
// to the finance system. Worse, and common: somebody reviews their own
// access. That is refused here, because a review nobody independent
// performed is a self-certification with extra steps.
//
// # The revocation is never verified
//
// The control is review *and* remediate, and the second half is where it
// fails. The review says remove Bob from Salesforce, and six weeks later
// nobody looked. An item here is not closed by the reviewer deciding: it is
// closed by the access being gone from the next import. The reviewer's
// decision is a commitment with a date on it, and the connector closes it.
//
// # The scope is what somebody exported
//
// A review covers the accounts in the export that happened to be pulled. If a
// system was missed the review is silently narrower than it claims, and
// nothing says so. The campaign declares which issuers it covers and the
// identities are matched against that, so a campaign covering three systems
// with identities from two reports the third rather than passing.
package review

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// MinThought is how long a decision has to take to be one.
//
// Three seconds. Not a claim that three seconds is enough to think — it is
// the floor below which a person cannot have read the row, and a run of
// decisions under it is a held-down key rather than a judgement. Reported
// rather than refused: a reviewer who genuinely knows the answer should not
// be made to wait, and the shape of a whole campaign is what tells you.
const MinThought = 3 * time.Second

// MaxSitting is how long a campaign decided in one unbroken run may be
// before the run itself is the finding.
//
// Forty decisions in ninety seconds is a rubber stamp whatever each one took.
const MaxSitting = 5 * time.Minute

// Verdict is what a reviewer decided about one person's access.
type Verdict string

const (
	// Keep is this access is still right.
	Keep Verdict = "keep"
	// Revoke is it should go entirely.
	Revoke Verdict = "revoke"
	// Reduce is the person stays and the privilege goes.
	//
	// Kept apart from Revoke because they are verified differently: a
	// revoked account should be absent from the next import and a reduced
	// one should be present without the privilege, and a system that
	// treated them the same would report every reduction as unremediated
	// for ever.
	Reduce Verdict = "reduce"
)

// Verdicts lists them.
func Verdicts() []Verdict { return []Verdict{Keep, Revoke, Reduce} }

func (v Verdict) known() bool {
	for _, x := range Verdicts() {
		if x == v {
			return true
		}
	}
	return false
}

// Changes reports whether this verdict commits somebody to doing something.
func (v Verdict) Changes() bool { return v == Revoke || v == Reduce }

// Campaign is one round of review.
type Campaign struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Scope is the issuers under review: "okta", "github", "aws". Declared,
	// so a campaign that covers three systems and receives identities from
	// two reports the third rather than quietly reviewing less.
	Scope []string `json:"scope"`
	// Entity is the company this covers, where a group is configured.
	Entity string `json:"entity,omitempty"`

	Opened time.Time `json:"opened"`
	// Due is when the decisions have to be in, and Remediate when the
	// changes have to have happened. Two dates, because they are two
	// different pieces of work and the second is the one that fails.
	Due       time.Time `json:"due"`
	Remediate time.Time `json:"remediate"`

	By   string     `json:"by"`
	Kind audit.Kind `json:"kind,omitempty"`
}

// Validate refuses a campaign that cannot be a review.
func (c Campaign) Validate() error {
	if strings.TrimSpace(c.ID) == "" {
		return fmt.Errorf("a campaign needs an identifier")
	}
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("%s has no name", c.ID)
	}
	if len(c.Scope) == 0 {
		return fmt.Errorf(
			"%s covers no systems. A review of whatever happened to be "+
				"exported is one that is silently narrower than it claims, "+
				"and nothing afterwards can tell", c.ID)
	}
	for _, s := range c.Scope {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s covers an unnamed system", c.ID)
		}
	}
	if c.Opened.IsZero() {
		return fmt.Errorf("%s has no start", c.ID)
	}
	if c.Due.IsZero() {
		return fmt.Errorf("%s has no date for the decisions", c.ID)
	}
	if c.Remediate.IsZero() {
		return fmt.Errorf(
			"%s has no date for the changes. The control is review and "+
				"remediate, and a campaign with one date measures the half "+
				"that does not fail", c.ID)
	}
	if !c.Due.After(c.Opened) {
		return fmt.Errorf("%s is due before it opened", c.ID)
	}
	if c.Remediate.Before(c.Due) {
		return fmt.Errorf(
			"%s expects the changes before the decisions", c.ID)
	}
	if strings.TrimSpace(c.By) == "" {
		return fmt.Errorf("%s was opened by nobody", c.ID)
	}
	return nil
}

// Covers reports whether an identity is inside the campaign's scope.
func (c Campaign) Covers(id telemetry.ID) bool {
	for _, s := range c.Scope {
		if strings.EqualFold(s, id.Issuer) {
			return true
		}
	}
	return false
}

// Record turns a campaign into an audit entry.
func (c Campaign) Record() audit.Record {
	return audit.Record{
		Action: "review.opened", Resource: "/review/" + c.ID,
		Outcome: audit.Success, Principal: c.By, Kind: c.Kind,
		Verified: c.Kind != audit.KindUnknown,
		Detail: map[string]string{
			"campaign": c.ID, "scope": strings.Join(c.Scope, ","),
			"due":       c.Due.UTC().Format(time.RFC3339),
			"remediate": c.Remediate.UTC().Format(time.RFC3339),
		},
	}
}

// Item is one person's access, put in front of a reviewer.
type Item struct {
	Campaign string `json:"campaign"`
	// Account is the access itself, issuer-qualified.
	Account telemetry.ID `json:"account"`
	// Person is who it belongs to, where the join knows.
	Person string `json:"person,omitempty"`
	// Role is what they have, in the system's own words.
	Role string `json:"role,omitempty"`
	// Privileged marks access that can change other people's.
	Privileged bool `json:"privileged,omitempty"`
	// Seen is when the account was last used.
	//
	// The single most useful thing to put in front of a reviewer and the
	// one most often missing: an account nobody has touched in ninety days
	// is a decision that makes itself.
	Seen time.Time `json:"seen,omitempty"`
}

// Key identifies an item.
func (i Item) Key() string { return i.Campaign + "\x00" + i.Account.String() }

// Dormant reports whether nobody has used this account lately.
func (i Item) Dormant(now time.Time, after time.Duration) bool {
	if i.Seen.IsZero() {
		return true
	}
	return now.Sub(i.Seen) > after
}

// Decision is a reviewer's answer about one item.
type Decision struct {
	Campaign string       `json:"campaign"`
	Account  telemetry.ID `json:"account"`
	Verdict  Verdict      `json:"verdict"`

	At   time.Time  `json:"at"`
	By   string     `json:"by"`
	Kind audit.Kind `json:"kind,omitempty"`
	// Because is why. Required for Keep on privileged access, because that
	// is the decision nobody writes down and the one an auditor samples.
	Because string `json:"because,omitempty"`
	// Took is how long the reviewer had this in front of them.
	//
	// Recorded because the shape of a campaign is the only thing that
	// distinguishes a review from a formality, and it cannot be
	// reconstructed afterwards.
	Took time.Duration `json:"took,omitempty"`
}

// Key identifies what a decision is about.
func (d Decision) Key() string {
	return d.Campaign + "\x00" + d.Account.String()
}

// Validate refuses a decision that is not a review.
func (d Decision) Validate(privileged bool) error {
	if strings.TrimSpace(d.Campaign) == "" {
		return fmt.Errorf("a decision needs a campaign")
	}
	if d.Account.Zero() {
		return fmt.Errorf("%s: a decision needs an account", d.Campaign)
	}
	if !d.Verdict.known() {
		return fmt.Errorf("%q is not a verdict", d.Verdict)
	}
	if d.At.IsZero() {
		return fmt.Errorf("%s has no time", d.Key())
	}
	if strings.TrimSpace(d.By) == "" {
		return fmt.Errorf(
			"%s names no reviewer. A review nobody signed is a list that "+
				"was exported", d.Key())
	}
	if d.Kind == audit.KindAI {
		return fmt.Errorf(
			"%s was decided by a model. Whether this person still needs "+
				"this access is a question about what they do all day, "+
				"which is the one thing a model cannot see; it may sort the "+
				"list and a person decides", d.Key())
	}
	if sameParty(d.By, d.Account) {
		// The commonest way a review is worthless, and the easiest to
		// check: a self-certification with extra steps.
		return fmt.Errorf(
			"%s reviewed their own access. A review nobody independent "+
				"performed is a self-certification with extra steps",
			d.By)
	}
	if privileged && d.Verdict == Keep &&
		strings.TrimSpace(d.Because) == "" {
		return fmt.Errorf(
			"%s keeps privileged access with no reason given. That is the "+
				"decision nobody writes down and the one an auditor "+
				"samples", d.Key())
	}
	return nil
}

// sameParty reports whether a reviewer is reviewing themselves.
//
// Compared on the bare value as well as the qualified form, because a
// reviewer signs in as a person and the account under review is that person
// in some other system's namespace.
func sameParty(by string, account telemetry.ID) bool {
	by = strings.ToLower(strings.TrimSpace(by))
	if by == "" {
		return false
	}
	return by == strings.ToLower(account.String()) ||
		by == strings.ToLower(account.Value)
}

// Record turns a decision into an audit entry.
func (d Decision) Record() audit.Record {
	detail := map[string]string{
		"campaign": d.Campaign, "account": d.Account.String(),
		"verdict": string(d.Verdict),
	}
	if d.Because != "" {
		detail["because"] = d.Because
	}
	if d.Took > 0 {
		detail["took"] = d.Took.Round(time.Millisecond).String()
	}
	outcome := audit.Success
	if d.Verdict.Changes() {
		// A revocation is recorded as a denial: the interesting population
		// for an auditor is the access somebody decided to take away, and a
		// log where that reads the same as leaving it alone cannot be
		// searched for it.
		outcome = audit.Denied
	}
	return audit.Record{
		Action:   "review." + string(d.Verdict),
		Resource: "/review/" + d.Campaign, Outcome: outcome,
		Principal: d.By, Kind: d.Kind,
		Verified: d.Kind != audit.KindUnknown, Detail: detail,
	}
}

// Latest folds decisions down to the newest for each item.
func Latest(in []Decision) map[string]Decision {
	out := map[string]Decision{}
	for _, d := range in {
		if existing, ok := out[d.Key()]; ok && existing.At.After(d.At) {
			continue
		}
		out[d.Key()] = d
	}
	return out
}

// sortedItems orders items for a reviewer: the decisions that make
// themselves first.
func sortedItems(in []Item, now time.Time) []Item {
	out := append([]Item(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		di := out[i].Dormant(now, 90*24*time.Hour)
		dj := out[j].Dormant(now, 90*24*time.Hour)
		if di != dj {
			return di
		}
		if out[i].Privileged != out[j].Privileged {
			return out[i].Privileged
		}
		return out[i].Account.String() < out[j].Account.String()
	})
	return out
}
