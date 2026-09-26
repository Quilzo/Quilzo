// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package attest answers security questionnaires, and refuses to answer them
// wrongly.
//
// # The number every product advertises and nobody finishes
//
// Vanta says 95% accuracy. Conveyor says 95% and a hallucination rate below
// 0.01%. Tribble says 95% first-draft accuracy. The current CAIQ has over 260
// questions.
//
// Five per cent of 260 is thirteen. Thirteen wrong answers, per questionnaire,
// sent under the company's name into a customer's vendor file, where they are
// relied upon and where a wrong one is a misrepresentation rather than a typo.
// The figure is published as a feature and the arithmetic is never done.
//
// The problem is not that models are inaccurate. It is that accuracy is being
// measured against the text of previous answers, so a confident answer about
// a control that stopped working in March scores as correct — it matches what
// was said last time, which is precisely the thing that is now false.
//
// # Check the answer against the register, not against the last answer
//
// This organisation already holds a register of everything wrong with it:
// detections, vulnerabilities, failed controls, gaps in evidence. An answer
// is a claim, and a claim whose backing has an open finding against it is
// contradicted by this organisation's own records.
//
// So a filled questionnaire is checked before it is sent, and a contradiction
// stops it. Not a confidence score — a confidence score is the model's
// opinion about its own text. This is the difference between "we are fairly
// sure we said this before" and "our own register says otherwise".
//
// # A claim, not an answer
//
// Answers are stored against the claim they make rather than against the
// wording of the question, because the same thing is asked forty ways and an
// answer library keyed on wording accumulates forty entries that drift apart.
// A claim carries what it asserts, what backs it, who signed it and when it
// goes stale.
//
// # A model may draft and may not sign
//
// Drafting an answer from existing material is exactly what a model is good
// at and there is real value in it. Signing one is a representation made to a
// customer under contract, and a person makes it.
package attest

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

// MaxLife is how long a claim stands before somebody has to look again.
//
// A year. Long enough not to be busywork, short enough that an answer written
// before a re-platforming is not still being sent after it.
const MaxLife = 365 * 24 * time.Hour

// Answer is what a claim asserts.
type Answer string

const (
	// Yes is we do this.
	Yes Answer = "yes"
	// No is we do not, which is a legitimate answer and is the one an
	// automated library is worst at producing.
	No Answer = "no"
	// Partly is we do some of it, and the detail says which part.
	//
	// The answer most questionnaires have no box for, which is why so many
	// of them get a yes.
	Partly Answer = "partly"
	// NotApplicable is the question does not apply to what we do.
	NotApplicable Answer = "not-applicable"
)

// Answers lists them.
func Answers() []Answer { return []Answer{Yes, No, Partly, NotApplicable} }

func (a Answer) known() bool {
	for _, x := range Answers() {
		if x == a {
			return true
		}
	}
	return false
}

// Affirms reports whether this answer asserts that something is in place.
//
// Yes and Partly. Both can be contradicted by the register; No and
// NotApplicable cannot, because a finding saying a control is broken does not
// contradict somebody having said the control is not in place.
func (a Answer) Affirms() bool { return a == Yes || a == Partly }

// Claim is something this organisation says about itself.
type Claim struct {
	ID string `json:"id"`
	// Says is the assertion, in one line, in this organisation's words.
	Says   string `json:"says"`
	Answer Answer `json:"answer"`
	// Detail is what a reader needs beyond the answer. Required for Partly,
	// because "partly" with no detail is a yes wearing a hedge.
	Detail string `json:"detail,omitempty"`

	// Backing points at what supports this, in the register's own namespace:
	// "control:mfa", "requirement:ISO27001:A.8.5". It is what makes the
	// contradiction check possible, and an affirmative claim without it is
	// refused.
	Backing []string `json:"backing,omitempty"`

	At   time.Time  `json:"at"`
	By   string     `json:"by"`
	Kind audit.Kind `json:"kind,omitempty"`
	// Until is when this has to be looked at again.
	Until time.Time `json:"until,omitempty"`
}

// Validate refuses a claim that cannot be defended.
func (c Claim) Validate() error {
	if strings.TrimSpace(c.ID) == "" {
		return fmt.Errorf("a claim needs an identifier")
	}
	if strings.TrimSpace(c.Says) == "" {
		return fmt.Errorf(
			"%s asserts nothing. A library keyed on the wording of "+
				"questions accumulates forty entries for one fact; this is "+
				"keyed on the fact", c.ID)
	}
	if !c.Answer.known() {
		return fmt.Errorf("%s: %q is not an answer", c.ID, c.Answer)
	}
	if c.At.IsZero() {
		return fmt.Errorf("%s has no date", c.ID)
	}
	if strings.TrimSpace(c.By) == "" {
		return fmt.Errorf(
			"%s names nobody. An answer on a security questionnaire is a "+
				"representation made under contract, and the person who "+
				"made it is the one who has to stand behind it", c.ID)
	}
	if c.Kind == audit.KindAI {
		return fmt.Errorf(
			"%s was signed by a model. Drafting an answer from existing "+
				"material is exactly what one is good at; signing it is a "+
				"representation to a customer, and a person makes it", c.ID)
	}
	if c.Until.IsZero() {
		return fmt.Errorf(
			"%s never goes stale. An answer library with no expiry is a "+
				"library of last year's answers, still being sent", c.ID)
	}
	if !c.Until.After(c.At) {
		return fmt.Errorf("%s expired before it was written", c.ID)
	}
	if c.Until.Sub(c.At) > MaxLife {
		return fmt.Errorf(
			"%s stands for %s. The ceiling is a year: long enough not to be "+
				"busywork, short enough that an answer written before a "+
				"re-platforming is not still being sent after it", c.ID,
			c.Until.Sub(c.At).Round(24*time.Hour))
	}
	if c.Answer.Affirms() && len(c.Backing) == 0 {
		return fmt.Errorf(
			"%s says %q and points at nothing. A claim with nothing behind "+
				"it is the one that gets read out in a deposition, and it "+
				"is also the one nothing can check", c.ID, c.Answer)
	}
	if c.Answer == Partly && strings.TrimSpace(c.Detail) == "" {
		return fmt.Errorf(
			"%s says partly and does not say which part. Partly with no "+
				"detail is a yes wearing a hedge", c.ID)
	}
	for _, b := range c.Backing {
		if !strings.Contains(b, ":") {
			return fmt.Errorf(
				"%s is backed by %q, which names no kind of thing. Backing "+
					"is written as control:mfa or requirement:ISO27001:A.8.5 "+
					"so that the register can be asked about it", c.ID, b)
		}
	}
	return nil
}

// Stale reports whether a claim needs looking at again.
func (c Claim) Stale(now time.Time) bool {
	return !c.Until.IsZero() && !now.Before(c.Until)
}

// Record turns a claim into an audit entry.
func (c Claim) Record() audit.Record {
	detail := map[string]string{
		"claim": c.ID, "says": c.Says, "answer": string(c.Answer),
		"until": c.Until.UTC().Format(time.RFC3339),
	}
	if len(c.Backing) > 0 {
		detail["backing"] = strings.Join(c.Backing, ",")
	}
	if c.Detail != "" {
		detail["detail"] = c.Detail
	}
	return audit.Record{
		Action: "attest.claimed", Resource: "/claim/" + c.ID,
		Outcome: audit.Success, Principal: c.By, Kind: c.Kind,
		Verified: c.Kind != audit.KindUnknown, Detail: detail,
	}
}

// Question is one line of somebody else's questionnaire.
type Question struct {
	// ID is the questionnaire's own reference: "CAIQ v4.0.2 IAM-03".
	ID   string `json:"id"`
	Text string `json:"text"`
	// Claim is which of our claims answers it. Empty means nobody has
	// mapped it, which is reported rather than guessed at.
	Claim string `json:"claim,omitempty"`
}

// Questionnaire is a set of questions somebody sent.
type Questionnaire struct {
	Name string `json:"name"`
	// From is who asked, which decides who the representation is made to.
	From      string     `json:"from"`
	Questions []Question `json:"questions"`
}

// Validate refuses a questionnaire that cannot be filled.
func (q Questionnaire) Validate() error {
	if strings.TrimSpace(q.Name) == "" {
		return fmt.Errorf("a questionnaire needs a name")
	}
	if strings.TrimSpace(q.From) == "" {
		return fmt.Errorf(
			"%s does not say who asked. An answer is a representation made "+
				"to somebody, and the record of it has to say to whom",
			q.Name)
	}
	if len(q.Questions) == 0 {
		return fmt.Errorf("%s asks nothing", q.Name)
	}
	seen := map[string]bool{}
	for _, item := range q.Questions {
		if strings.TrimSpace(item.ID) == "" {
			return fmt.Errorf("%s has a question with no reference", q.Name)
		}
		if seen[item.ID] {
			return fmt.Errorf("%s asks %s twice", q.Name, item.ID)
		}
		seen[item.ID] = true
		if strings.TrimSpace(item.Text) == "" {
			return fmt.Errorf(
				"%s: %s has no text. A filled questionnaire that shows "+
					"references and no questions cannot be reviewed by the "+
					"person signing it", q.Name, item.ID)
		}
	}
	return nil
}

// Library is the claims this organisation stands behind.
type Library struct {
	byID map[string]Claim
}

// NewLibrary starts an empty one.
func NewLibrary() *Library { return &Library{byID: map[string]Claim{}} }

// Add puts a claim in the library, newest wins.
//
// Two claims with one identifier are somebody changing their mind, which is
// the same rule internal/vuln applies to assessments and internal/crosswalk
// to mappings.
func (l *Library) Add(c Claim) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if existing, ok := l.byID[c.ID]; ok && existing.At.After(c.At) {
		return nil
	}
	l.byID[c.ID] = c
	return nil
}

// Get returns one claim.
func (l *Library) Get(id string) (Claim, bool) {
	c, ok := l.byID[id]
	return c, ok
}

// All returns every claim, by identifier.
func (l *Library) All() []Claim {
	out := make([]Claim, 0, len(l.byID))
	for _, c := range l.byID {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Len is how many claims the library holds.
func (l *Library) Len() int { return len(l.byID) }
