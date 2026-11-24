// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/sheet"
)

// The statement of applicability.
//
// Within a scope a person approved, each requirement of each framework the
// scope answers to is decided: it applies, or it does not, and why, each
// line an Applicability record carrying the approval of the person who
// decided it. A requirement nobody has decided about is undecided, and is
// shown so; it is never counted as applying, nor as not. Beside each line
// are the controls mapped to the requirement, each with its relation and
// how it stood at its newest run. That is evidence towards the requirement.
// It is never called compliance: a passing control mapped as a subset of a
// requirement leaves the rest of the requirement where it was, and the
// statement says which relation each mapping is.

// The three states of a line.
const (
	Applies   = "applies"
	Excluded  = "does not apply"
	Undecided = "undecided"
)

// DecideScope raises the decision of what the programme covers.
func (p *Programme) DecideScope(d Decider, s register.Scope) (Decided, error) {
	s.Approval = nil
	return p.Raise(d, "the scope "+s.Name, s)
}

// DecideLine raises the decision whether one requirement applies within a
// scope, and why. The words are kept beside the store and the line holds
// their digest.
func (p *Programme) DecideLine(d Decider, scope, framework, ref string, applies bool, why string) (Decided, error) {
	v, err := p.Reg.At("")
	if err != nil {
		return Decided{}, err
	}
	sid, err := named(v, register.KindScope, register.Local, scope)
	if err != nil {
		return Decided{}, err
	}
	rid, err := register.DeriveID(register.KindRequirement, framework, ref)
	if err != nil || !has(v, rid) {
		return Decided{}, fmt.Errorf("%w: the programme holds no requirement %s of %s; a framework's starter brings its requirements",
			register.ErrNotFound, clip(ref), clip(framework))
	}
	text, err := p.Keep.Keep(why)
	if err != nil {
		return Decided{}, fmt.Errorf("%w: %v", register.ErrInvalid, err)
	}
	word := "applies"
	if !applies {
		word = "does not apply"
	}
	return p.Raise(d, fmt.Sprintf("%s %s %s in the scope %s", framework, ref, word, scope),
		register.Applicability{Requirement: rid, Scope: sid, Applicable: applies, Justification: text})
}

// Line is one line of the statement.
type Line struct {
	Requirement   register.ID `json:"requirement"`
	Framework     string      `json:"framework"`
	Ref           string      `json:"ref"`
	Title         string      `json:"title"`
	State         string      `json:"state"`
	Decision      register.ID `json:"decision,omitempty"`
	Justification string      `json:"justification,omitempty"`
	// Kept says the justification's words are kept beside the store; a
	// line whose words were erased, or never kept, shows its digest.
	Kept     bool               `json:"kept,omitempty"`
	Digest   register.Text      `json:"digest,omitempty"`
	Approval *register.Approval `json:"approval,omitempty"`
	Controls []Mapped           `json:"controls"`
	// Related is how the requirement relates to other frameworks'.
	Related []Related `json:"related,omitempty"`
}

// Mapped is a control mapped to a requirement, with how it stands.
type Mapped struct {
	Control  register.ID       `json:"control"`
	Ref      string            `json:"ref"`
	Title    string            `json:"title"`
	Relation register.Relation `json:"relation"`
	Standing Standing          `json:"standing"`
}

// Related is a requirement of another framework a line's requirement is
// mapped to or from.
type Related struct {
	Framework string            `json:"framework"`
	Ref       string            `json:"ref"`
	Relation  register.Relation `json:"relation"`
	// From says the relation was written from the other requirement to
	// this one, so it reads the other way.
	From bool `json:"from,omitempty"`
}

// Statement is the statement of applicability for a scope, at a commit.
type Statement struct {
	Scope      register.Scope `json:"scope"`
	ScopeID    register.ID    `json:"scope_id"`
	Commit     string         `json:"commit"`
	Frameworks []string       `json:"frameworks"`
	Lines      []Line         `json:"lines"`
	// How many lines are in each state.
	Applying, NotApplying, Undecided int
}

// StatementAt is the statement of applicability for a scope at a view.
// The frameworks are those the scope answers to whose starters are
// installed, or every installed one for a scope that names none.
func StatementAt(v *register.View, keep Keeper, scope string) (Statement, error) {
	sid, err := named(v, register.KindScope, register.Local, scope)
	if err != nil {
		return Statement{}, err
	}
	se, err := v.Get(sid)
	if err != nil {
		return Statement{}, err
	}
	sc := se.Record.(register.Scope)
	installed, err := Installed(v)
	if err != nil {
		return Statement{}, err
	}
	want := map[string]bool{}
	for _, f := range sc.Frameworks {
		want[f] = true
	}
	st := Statement{Scope: sc, ScopeID: sid, Commit: v.Commit(), Lines: []Line{}}
	for f := range installed {
		if len(want) == 0 || want[f] {
			st.Frameworks = append(st.Frameworks, f)
		}
	}
	sort.Strings(st.Frameworks)
	in := map[string]bool{}
	for _, f := range st.Frameworks {
		in[f] = true
	}

	reqs := map[register.ID]register.Requirement{}
	if err := v.Each(register.KindRequirement, func(e register.Entry, _ map[string]any) error {
		reqs[e.ID] = e.Record.(register.Requirement)
		return nil
	}); err != nil {
		return Statement{}, err
	}
	decided := map[register.ID]register.Entry{}
	if err := v.Each(register.KindApplicability, func(e register.Entry, _ map[string]any) error {
		if a := e.Record.(register.Applicability); a.Scope == sid {
			decided[a.Requirement] = e
		}
		return nil
	}); err != nil {
		return Statement{}, err
	}
	controls := map[register.ID]register.Control{}
	if err := v.Each(register.KindControl, func(e register.Entry, _ map[string]any) error {
		controls[e.ID] = e.Record.(register.Control)
		return nil
	}); err != nil {
		return Statement{}, err
	}
	standing, err := Standings(v)
	if err != nil {
		return Statement{}, err
	}
	mapped := map[register.ID][]Mapped{}
	related := map[register.ID][]Related{}
	if err := v.Each(register.KindMapping, func(e register.Entry, _ map[string]any) error {
		m := e.Record.(register.Mapping)
		if c, ok := controls[m.From]; ok {
			mapped[m.To] = append(mapped[m.To], Mapped{Control: m.From, Ref: c.Ref, Title: c.Title,
				Relation: m.Relation, Standing: standing[m.From]})
			return nil
		}
		from, okFrom := reqs[m.From]
		to, okTo := reqs[m.To]
		if okFrom && okTo {
			related[m.From] = append(related[m.From], Related{Framework: to.Framework, Ref: to.Ref, Relation: m.Relation})
			related[m.To] = append(related[m.To], Related{Framework: from.Framework, Ref: from.Ref, Relation: m.Relation, From: true})
		}
		return nil
	}); err != nil {
		return Statement{}, err
	}

	order := map[string]map[string]int{}
	for _, f := range st.Frameworks {
		order[f] = map[string]int{}
		if s, ok := StarterNamed(f); ok {
			for i, c := range s.Clauses {
				order[f][c.Ref] = i
			}
		}
	}
	for id, q := range reqs {
		if !in[q.Framework] {
			continue
		}
		line := Line{Requirement: id, Framework: q.Framework, Ref: q.Ref, Title: q.Title, State: Undecided,
			Controls: mapped[id], Related: related[id]}
		if line.Controls == nil {
			line.Controls = []Mapped{}
		}
		sort.Slice(line.Controls, func(i, j int) bool { return line.Controls[i].Ref < line.Controls[j].Ref })
		if e, ok := decided[id]; ok {
			a := e.Record.(register.Applicability)
			line.Decision, line.Approval, line.Digest = e.ID, a.Approval, a.Justification
			line.State = Excluded
			if a.Applicable {
				line.State = Applies
			}
			if keep != nil {
				line.Justification, line.Kept = keep.Words(a.Justification)
			}
		}
		switch line.State {
		case Applies:
			st.Applying++
		case Excluded:
			st.NotApplying++
		default:
			st.Undecided++
		}
		st.Lines = append(st.Lines, line)
	}
	sort.Slice(st.Lines, func(i, j int) bool {
		a, b := st.Lines[i], st.Lines[j]
		if a.Framework != b.Framework {
			return a.Framework < b.Framework
		}
		oa, okA := order[a.Framework][a.Ref]
		ob, okB := order[b.Framework][b.Ref]
		if okA && okB && oa != ob {
			return oa < ob
		}
		return a.Ref < b.Ref
	})
	return st, nil
}

// CSVHeader is the statement's columns, in order.
var CSVHeader = []string{"framework", "requirement", "what it is about", "applicability", "justification",
	"approved by", "approved at", "approved alone", "evidence towards it", "related requirements",
	"requirement id", "decision id"}

// WriteCSV writes the statement as CSV, one requirement a row. Every cell
// is guarded against being read as a formula, and the evidence column says
// each mapped control's relation and how it stood at its newest run:
// evidence towards the requirement, never a verdict on it.
func (s Statement) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(CSVHeader); err != nil {
		return err
	}
	for _, l := range s.Lines {
		var by, at, alone string
		if a := l.Approval; a != nil && len(a.Signers) > 0 {
			by = string(a.Signers[0].Subject)
			at = a.Signers[0].At.At().Format("2006-01-02T15:04:05Z")
			alone = "no"
			if a.Alone {
				alone = "yes"
			}
		}
		why := l.Justification
		if l.Decision != "" && !l.Kept {
			why = "words not kept here; digest " + string(l.Digest)
		}
		var evidence []string
		for _, c := range l.Controls {
			evidence = append(evidence, c.Ref+" ("+string(c.Relation)+"): "+standingWords(c.Standing))
		}
		var rel []string
		for _, r := range l.Related {
			dir := "is " + string(r.Relation) + " " + r.Framework + " " + r.Ref
			if r.From {
				dir = r.Framework + " " + r.Ref + " is " + string(r.Relation) + " this"
			}
			rel = append(rel, dir)
		}
		row := []string{l.Framework, l.Ref, l.Title, l.State, why, by, at, alone,
			strings.Join(evidence, "; "), strings.Join(rel, "; "), string(l.Requirement), string(l.Decision)}
		for i := range row {
			row[i] = sheet.GuardCell(row[i])
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// standingWords is how a control stood, as the statement says it.
func standingWords(s Standing) string {
	switch s.Outcome {
	case register.Pass:
		return "passing at its newest run, " + s.At.At().Format("2 Jan 2006")
	case register.Fail:
		return "failing at its newest run, " + s.At.At().Format("2 Jan 2006")
	}
	return "no evidence from a run"
}
