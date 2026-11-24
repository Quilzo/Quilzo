// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"fmt"
	"time"
)

// The kinds that hold what people decided: a risk and what was done about
// it, an exception and when it lapses, a decision and the authority it was
// made on, the appetite a board set, and the value a metric had on a day.

// RiskStatus is where a risk stands.
type RiskStatus string

// Values lists the statuses of a risk.
func (RiskStatus) Values() []string { return []string{"open", "treating", "accepted", "closed"} }

// Risk is something that could go wrong, with who answers for it and how
// likely and how bad it is on a scale of one to five. The two numbers are
// worked out by formula from typed facts and are never a model's.
//
// Accepting a risk is a decision: the record then carries the approval, and
// the person who raised the risk cannot be the one who accepts it.
type Risk struct {
	Ref         string     `json:"ref" reg:"required,label" about:"the organisation's own reference; its natural key"`
	Title       string     `json:"title" reg:"required,label" about:"what could go wrong, in a line"`
	Description Text       `json:"description,omitempty" about:"the risk in full, held as a digest"`
	Owner       ID         `json:"owner" reg:"required,ref=Subject" about:"who answers for it"`
	Raised      ID         `json:"raised_by" reg:"required,ref=Subject" about:"who raised it"`
	Likelihood  int64      `json:"likelihood" reg:"required,min=1,max=5" about:"how likely, from 1 to 5"`
	Impact      int64      `json:"impact" reg:"required,min=1,max=5" about:"how bad, from 1 to 5"`
	Status      RiskStatus `json:"status" reg:"required" about:"where it stands"`
	Controls    []ID       `json:"controls,omitempty" reg:"ref=Control" about:"the controls that treat it"`
	Approval    *Approval  `json:"approval,omitempty" about:"the approval that accepted it"`
}

const KindRisk Kind = "Risk"

func (Risk) Kind() Kind              { return KindRisk }
func (r Risk) Key() (string, string) { return Local, r.Ref }
func (r Risk) Check() error {
	if r.Status == "accepted" {
		if r.Approval == nil {
			return fmt.Errorf("an accepted risk carries the approval that accepted it")
		}
		if r.Approval.Raised != r.Raised {
			return fmt.Errorf("the approval was asked for by somebody other than the person who raised the risk")
		}
	}
	return nil
}
func (r Risk) index(w *Row) {
	w.About, w.N, w.M, w.State = r.Owner.bytes(), clamp32(r.Likelihood), clamp32(r.Impact), ordinal(r.Status)
}

var _ = define[Risk]("Something that could go wrong, with its owner, likelihood and impact.", ClassRestricted)

// MaxExceptionTerm is the longest an exception may run. An organisation's
// own maximum may be shorter; none may be longer, because an exception with
// no end is a control nobody runs.
const MaxExceptionTerm = 366 * 24 * time.Hour

// Exception lets a control or a risk stand unmet for a set time, on a
// person's approval. It has an end. When the end passes it lapses, and what
// it covered is a problem again without anybody doing anything.
type Exception struct {
	Ref      string    `json:"ref" reg:"required,label" about:"the organisation's own reference; its natural key"`
	About    ID        `json:"about" reg:"required" about:"the control or the risk it is an exception to"`
	Reason   Text      `json:"reason" reg:"required" about:"why it is asked for, held as a digest"`
	Owner    ID        `json:"owner" reg:"required,ref=Subject" about:"who answers for it"`
	Starts   Time      `json:"starts" reg:"required" about:"when it begins"`
	Expires  Time      `json:"expires" reg:"required" about:"when it lapses"`
	Approval *Approval `json:"approval" reg:"required" about:"the approval that granted it"`
}

const KindException Kind = "Exception"

func (Exception) Kind() Kind              { return KindException }
func (e Exception) Key() (string, string) { return Local, e.Ref }
func (e Exception) Check() error {
	term := time.Duration(e.Expires-e.Starts) * time.Second
	switch {
	case term <= 0:
		return fmt.Errorf("an exception lapses after it begins")
	case term > MaxExceptionTerm:
		return fmt.Errorf("an exception runs for at most %d days; this one runs for %d",
			int(MaxExceptionTerm.Hours()/24), int(term.Hours()/24))
	}
	return nil
}
func (e Exception) index(r *Row) {
	r.About, r.Via, r.At = e.About.bytes(), e.Owner.bytes(), int64(e.Expires)
}

var _ = define[Exception]("A control or a risk left unmet for a set time, on approval, until it lapses.",
	ClassRestricted, signed)

// Authority is what a decision rests on.
type Authority string

// Values lists the authorities: a board or committee's minute, a power
// somebody delegated, or management's own.
func (Authority) Values() []string { return []string{"minuted", "delegated", "management"} }

// Decision is something that was decided, by whom, and on what authority. A
// decision a board or a committee made needs its minute: the reference, and
// the digest of the signed extract. It is never changed afterwards; a
// decision that is reversed is a second decision.
type Decision struct {
	Ref       string    `json:"ref" reg:"required,label" about:"the organisation's own reference; its natural key"`
	Title     string    `json:"title" reg:"required,label" about:"what was decided, in a line"`
	About     []ID      `json:"about,omitempty" about:"the records the decision is about"`
	Authority Authority `json:"authority" reg:"required" about:"what the decision rests on"`
	Minute    string    `json:"minute,omitempty" reg:"label" about:"the reference of the minute that records it"`
	Extract   Digest    `json:"extract,omitempty" about:"the digest of the signed extract of that minute"`
	Decided   Time      `json:"decided" reg:"required" about:"when it was decided"`
	Decider   ID        `json:"decider" reg:"required,ref=Subject" about:"who decided, or who recorded the body's decision"`
	Words     Text      `json:"words,omitempty" about:"the decision in full, held as a digest"`
	Approval  *Approval `json:"approval,omitempty" about:"the approval with its authentication evidence, where one was given"`
}

const KindDecision Kind = "Decision"

func (Decision) Kind() Kind              { return KindDecision }
func (d Decision) Key() (string, string) { return Local, d.Ref }
func (d Decision) Check() error {
	if d.Authority == "minuted" && (d.Minute == "" || d.Extract == "") {
		return fmt.Errorf("a minuted decision needs the minute's reference and the digest of its signed extract")
	}
	return nil
}
func (d Decision) index(r *Row) {
	r.About, r.At, r.State = d.Decider.bytes(), int64(d.Decided), ordinal(d.Authority)
}

var _ = define[Decision]("Something that was decided, by whom and on what authority.", ClassRestricted, immutable)

// Direction is which side of a tolerance is acceptable.
type Direction string

// Values lists the directions: the metric must be at least the value, or at
// most it.
func (Direction) Values() []string { return []string{"at-least", "at-most"} }

// Tolerance is the appetite for one metric: the value it must not fall
// below, or must not rise above.
type Tolerance struct {
	Metric    ID        `json:"metric" reg:"required" about:"the metric the tolerance is for"`
	Direction Direction `json:"direction" reg:"required" about:"whether the metric must be at least the value or at most it"`
	Value     float64   `json:"value" about:"the value"`
}

// RiskAppetite is how much risk the organisation's leadership accepts, as a
// tolerance for each metric. It is a decision, with its approval. A metric
// outside its tolerance is listed as a decision needed, and is not coloured.
type RiskAppetite struct {
	Name       string      `json:"name" reg:"required,slug" about:"its machine name, such as the year it is set for; its natural key"`
	Decided    Time        `json:"decided" reg:"required" about:"when it was set"`
	Tolerances []Tolerance `json:"tolerances" reg:"required" about:"the tolerance for each metric"`
	Approval   *Approval   `json:"approval" reg:"required" about:"the approval that set it"`
}

const KindRiskAppetite Kind = "RiskAppetite"

func (RiskAppetite) Kind() Kind              { return KindRiskAppetite }
func (a RiskAppetite) Key() (string, string) { return Local, a.Name }
func (a RiskAppetite) Check() error {
	seen := map[ID]bool{}
	for _, t := range a.Tolerances {
		if seen[t.Metric] {
			return fmt.Errorf("a metric has one tolerance")
		}
		seen[t.Metric] = true
	}
	return nil
}
func (a RiskAppetite) index(r *Row) { r.At, r.N = int64(a.Decided), clamp32(int64(len(a.Tolerances))) }

var _ = define[RiskAppetite]("How much risk leadership accepts, as a tolerance for each metric.", ClassRestricted, signed)

// MetricValue is what a metric was at a moment: n of N, from which sources,
// at which grade. It is stored when it is computed and never changed, so a
// trend reads what was true then: changing a test changes tomorrow's value
// and not last quarter's.
type MetricValue struct {
	Metric      ID     `json:"metric" reg:"required" about:"the metric the value is of"`
	At          Time   `json:"at" reg:"required" about:"the moment it was computed for"`
	Numerator   int64  `json:"numerator" reg:"min=0" about:"n: how many met the metric"`
	Denominator int64  `json:"denominator" reg:"min=0" about:"N: how many were counted"`
	Grade       Grade  `json:"grade" reg:"required" about:"the weakest grade among the facts counted"`
	Sources     []ID   `json:"sources" reg:"required,ref=Source" about:"the sources the facts came from"`
	Snapshot    Digest `json:"snapshot" reg:"required" about:"the digest of what it was computed from"`
}

const KindMetricValue Kind = "MetricValue"

func (MetricValue) Kind() Kind { return KindMetricValue }
func (m MetricValue) Key() (string, string) {
	return Local, string(m.Metric) + "/" + fmt.Sprint(int64(m.At))
}
func (m MetricValue) Check() error {
	if m.Numerator > m.Denominator {
		return fmt.Errorf("a metric's value is n of N, and n cannot be more than N")
	}
	return nil
}
func (m MetricValue) index(r *Row) {
	r.About, r.At, r.N, r.M, r.Grade = m.Metric.bytes(), int64(m.At), clamp32(m.Numerator), clamp32(m.Denominator), ordinal(m.Grade)
}

var _ = define[MetricValue]("What a metric was at a moment: n of N, with its sources and grade.", ClassInternal, immutable)
