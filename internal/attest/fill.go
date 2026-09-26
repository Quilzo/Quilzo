// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package attest

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Filling a questionnaire, and the four reasons not to send it.
//
// The check that matters is the first one. Every product in this category
// scores an answer against the text of previous answers, which is a measure
// of consistency rather than of truth: a confident answer about a control
// that stopped working in March matches what was said last time, and last
// time is exactly what is now false.
//
// This organisation holds a register of everything wrong with it. An answer
// is a claim, the claim points at what backs it, and an open finding against
// that backing is this organisation's own record saying otherwise.

// Trouble is a reason an answer should not go out.
type Trouble string

const (
	// Contradicted is the register has a serious open finding against what
	// this answer relies on.
	//
	// The one that stops a questionnaire: the organisation's own records
	// disagreeing with what it is about to tell a customer.
	Contradicted Trouble = "contradicted"
	// Doubtful is the same thing at a severity that does not warrant
	// stopping the file.
	//
	// Three missing days out of a hundred and eighty-two is a real finding
	// and is not a reason to tell a customer nothing. A check that fires on
	// everything is a check somebody turns off, and a check somebody turns
	// off is worse than no check — the argument internal/detect makes about
	// false positive rates, arriving where the cost of being wrong is a
	// blocked sale rather than an ignored alert.
	Doubtful Trouble = "doubtful"
	// Stale is the claim is past the date somebody said to look again.
	Stale Trouble = "stale"
	// Unmapped is no claim has been attached to this question.
	Unmapped Trouble = "unmapped"
	// Missing is a claim is named and the library does not hold it.
	Missing Trouble = "missing"
)

// Blocking reports whether this trouble stops a questionnaire going out.
func (t Trouble) Blocking() bool { return t == Contradicted }

// Serious is the severity at which a finding contradicts an answer rather
// than casting doubt on it.
//
// High. Below that the finding is reported alongside the answer and the file
// still goes: a gap of a few days in one control is not a reason to refuse to
// answer a customer, and treating it as one trains everybody to pass the
// flag.
const Serious = telemetry.SeverityHigh

// Concern is one trouble with one answer.
type Concern struct {
	Question string  `json:"question"`
	Trouble  Trouble `json:"trouble"`
	// What it is, in one line somebody can act on.
	What string `json:"what"`
	// Finding names the register entry that contradicts, where there is one,
	// and Severity how bad that entry is — which is what decides whether
	// this stops the file or sits beside it.
	Finding  string             `json:"finding,omitempty"`
	Severity telemetry.Severity `json:"severity,omitempty"`
}

// Response is one question, answered.
type Response struct {
	Question Question `json:"question"`
	Claim    string   `json:"claim,omitempty"`
	Answer   Answer   `json:"answer,omitempty"`
	Says     string   `json:"says,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Backing  []string `json:"backing,omitempty"`
}

// Filled is a questionnaire with our answers and what is wrong with them.
type Filled struct {
	Questionnaire Questionnaire `json:"questionnaire"`
	At            time.Time     `json:"at"`
	Responses     []Response    `json:"responses"`
	Concerns      []Concern     `json:"concerns,omitempty"`
}

// Answered is how many questions got an answer.
func (f Filled) Answered() int {
	var n int
	for _, r := range f.Responses {
		if r.Answer != "" {
			n++
		}
	}
	return n
}

// Blocking returns the concerns that stop this going out.
func (f Filled) Blocking() []Concern {
	var out []Concern
	for _, c := range f.Concerns {
		if c.Trouble.Blocking() {
			out = append(out, c)
		}
	}
	return out
}

// Sendable reports whether this may go to the customer.
func (f Filled) Sendable() bool { return len(f.Blocking()) == 0 }

// Why explains a filled questionnaire in one line, leading with what stops it.
func (f Filled) Why() string {
	if blocking := f.Blocking(); len(blocking) > 0 {
		return fmt.Sprintf(
			"%d answer(s) are contradicted by this organisation's own "+
				"register. Sending this is a representation that cannot be "+
				"supported by the records behind it", len(blocking))
	}
	var stale, unmapped, doubtful int
	for _, c := range f.Concerns {
		switch c.Trouble {
		case Stale:
			stale++
		case Unmapped, Missing:
			unmapped++
		case Doubtful:
			doubtful++
		}
	}
	switch {
	case doubtful > 0:
		return fmt.Sprintf(
			"nothing serious contradicts these answers; %d rest on a "+
				"control the register has a smaller open finding against, "+
				"which is worth reading before this goes out", doubtful)
	case unmapped > 0:
		return fmt.Sprintf(
			"%d of %d question(s) answered; %d have no claim behind them "+
				"and are left blank rather than guessed at", f.Answered(),
			len(f.Responses), unmapped)
	case stale > 0:
		return fmt.Sprintf(
			"every question answered; %d answer(s) are past the date "+
				"somebody said to look at them again", stale)
	default:
		return fmt.Sprintf("all %d question(s) answered and nothing in the "+
			"register contradicts any of them", len(f.Responses))
	}
}

// Fill answers a questionnaire and checks it against the register.
//
// The register is passed in rather than fetched, because what counts as an
// open finding is the caller's decision: a deployment mid-remediation may
// want accepted risks to contradict an affirmative answer and another may
// not, and burying that choice here would make it invisible.
func Fill(q Questionnaire, l *Library, register []finding.Finding,
	now time.Time) (Filled, error) {

	var f Filled
	if err := q.Validate(); err != nil {
		return f, err
	}
	f.Questionnaire = q
	f.At = now

	// The register, indexed by what each finding is about. A finding's
	// entity is written the same way a claim's backing is — issuer and
	// value — which is what makes this a lookup rather than a guess.
	against := map[string][]finding.Finding{}
	for _, item := range register {
		if item.State == finding.Fixed || item.State == finding.Stale {
			continue
		}
		against[key(item.Entity)] = append(against[key(item.Entity)], item)
	}

	for _, question := range q.Questions {
		r := Response{Question: question, Claim: question.Claim}
		if strings.TrimSpace(question.Claim) == "" {
			f.Responses = append(f.Responses, r)
			f.Concerns = append(f.Concerns, Concern{
				Question: question.ID, Trouble: Unmapped,
				What: "nothing in the library answers this, so it is left " +
					"blank. A generated answer here would be the model's " +
					"reading of the question rather than this " +
					"organisation's position",
			})
			continue
		}
		c, ok := l.Get(question.Claim)
		if !ok {
			f.Responses = append(f.Responses, r)
			f.Concerns = append(f.Concerns, Concern{
				Question: question.ID, Trouble: Missing,
				What: fmt.Sprintf(
					"this question is mapped to %q and the library does not "+
						"hold it", question.Claim),
			})
			continue
		}
		r.Answer, r.Says, r.Detail = c.Answer, c.Says, c.Detail
		r.Backing = c.Backing
		f.Responses = append(f.Responses, r)

		if c.Stale(now) {
			f.Concerns = append(f.Concerns, Concern{
				Question: question.ID, Trouble: Stale,
				What: fmt.Sprintf(
					"%s was due for review on %s and is still being sent",
					c.ID, c.Until.Format("2006-01-02")),
			})
		}
		if !c.Answer.Affirms() {
			// A finding saying a control is broken does not contradict
			// somebody having said the control is not in place.
			continue
		}
		for _, backing := range c.Backing {
			for _, item := range against[strings.ToLower(backing)] {
				trouble := Doubtful
				if item.Severity >= Serious {
					trouble = Contradicted
				}
				f.Concerns = append(f.Concerns, Concern{
					Question: question.ID, Trouble: trouble,
					Finding: item.ID, Severity: item.Severity,
					What: fmt.Sprintf(
						"this answers %q and relies on %s, and the register "+
							"has an open finding against it: %s", c.Says,
						backing, item.Title),
				})
			}
		}
	}
	sort.SliceStable(f.Concerns, func(i, j int) bool {
		if f.Concerns[i].Trouble.Blocking() !=
			f.Concerns[j].Trouble.Blocking() {
			return f.Concerns[i].Trouble.Blocking()
		}
		return f.Concerns[i].Question < f.Concerns[j].Question
	})
	return f, nil
}

// key is how a finding's entity is matched against a claim's backing.
func key(id telemetry.ID) string {
	return strings.ToLower(id.Issuer + ":" + id.Value)
}

// Findings turns the state of the library into the register.
//
// The answers nobody can support are findings about this organisation like
// any other, and they belong in the same queue: a stale claim is a control
// nobody has looked at, and a contradicted one is a customer about to be
// told something untrue.
func Findings(l *Library, filled []Filled, now time.Time) []finding.Finding {
	var out []finding.Finding
	add := func(id, title, what string, sev telemetry.Severity) {
		f := finding.Finding{
			Kind: finding.FromQuestionnaire, Title: title, Source: "attest",
			Entity:   telemetry.ID{Issuer: "claim", Value: id},
			Severity: sev, State: finding.Open, Seen: 1,
			First: now, Last: now,
			Evidence: []finding.Evidence{{
				At: now, Source: "attest", What: what,
			}},
		}
		f.ID = finding.Key(f.Kind, f.Source, f.Entity)
		out = append(out, f)
	}

	for _, c := range l.All() {
		if c.Stale(now) {
			add(c.ID,
				fmt.Sprintf("the claim %q was due for review on %s", c.Says,
					c.Until.Format("2006-01-02")),
				"an answer library with no expiry is a library of last "+
					"year's answers, and this one has one and is past it",
				telemetry.SeverityMedium)
		}
	}
	seen := map[string]bool{}
	for _, f := range filled {
		for _, c := range f.Blocking() {
			id := c.Finding + "\x00" + c.Question
			if seen[id] {
				continue
			}
			seen[id] = true
			add(c.Question,
				fmt.Sprintf("%s would tell %s something the register "+
					"contradicts", f.Questionnaire.Name,
					f.Questionnaire.From),
				c.What, telemetry.SeverityHigh)
		}
	}
	return finding.Rank(out, now)
}

// Coverage is how much of a questionnaire the library can answer.
//
// Reported before anybody starts, because the useful number is not how many
// answers were generated — it is how many questions this organisation has
// actually decided its position on. The rest is work, and a product that
// generates them anyway has converted that work into a risk.
func Coverage(q Questionnaire, l *Library) (answerable, total int) {
	for _, question := range q.Questions {
		total++
		if question.Claim == "" {
			continue
		}
		if _, ok := l.Get(question.Claim); ok {
			answerable++
		}
	}
	return answerable, total
}
