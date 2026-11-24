// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

import (
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/register"
)

// Populations: the N of every "n of N".
//
// A population says which source its members are read from and the typed
// query that selects them. Where a second source knows of the same things,
// it is compared with that source, and the members either side has no
// counterpart for on the other, by being the same record or by an exact
// link, are counted as a number of their own: "entra 641 accounts, hr 598
// staff: 43 unexplained". The disagreement is not netted off, averaged or
// hidden in the denominator; it is what somebody has to explain.
//
// A population with one source is labelled unchecked: whatever that source
// does not know of is invisible, and nothing here would notice. One whose
// source is the tool it is used to measure is labelled circular: the
// accounts the identity provider lists are the ones it can say have a
// second factor, and an account it never heard of is in neither number.

// Label is what a population is labelled with, wherever it is shown.
type Label string

const (
	// Unchecked is a population with one source.
	Unchecked Label = "single source: unmanaged members are invisible"
	// Circular is a population not declared independent of the tool it
	// measures.
	Circular Label = "circular: not shown to be independent of the tool it measures"
	// Stale is a count older than the population says it may be.
	Stale Label = "stale: counted longer ago than it may be"
	// Uncounted is a population nobody has counted.
	Uncounted Label = "not yet counted"
)

// Labels is what a population is labelled with, as of now.
func Labels(p register.Population, now time.Time) []Label {
	var out []Label
	if p.CrossCheck == "" {
		out = append(out, Unchecked)
	}
	if !p.Independent {
		out = append(out, Circular)
	}
	switch {
	case p.Counted == 0:
		out = append(out, Uncounted)
	case now.Sub(p.Counted.At()) > time.Duration(p.Fresh)*time.Second:
		out = append(out, Stale)
	}
	return out
}

// Count is a population as code counted it at a view.
type Count struct {
	ID         register.ID         `json:"id"`
	Population register.Population `json:"population"`
	// Members is the population's members by identifier, from its source;
	// Cross what the cross-check source knows of.
	Members []register.ID `json:"members"`
	Cross   []register.ID `json:"cross,omitempty"`
	// OnlyHere are members with no counterpart in the cross-check, and
	// OnlyThere what the cross-check knows of with no counterpart here.
	OnlyHere  []register.ID `json:"only_here,omitempty"`
	OnlyThere []register.ID `json:"only_there,omitempty"`
	Labels    []Label       `json:"labels,omitempty"`
	// Source and CrossName are what the two sources are called.
	Source    string `json:"source"`
	CrossName string `json:"cross_check,omitempty"`
}

// Disagreement is a count as one line: each source with its number, and
// how many are unexplained, or that there is one source and nothing
// checked it. Code writes it from the count; it is the line a screen shows
// beside the figure.
func Disagreement(c Count) string {
	if c.Population.CrossCheck == "" {
		return fmt.Sprintf("%s %d: single source, unchecked", c.Source, len(c.Members))
	}
	return fmt.Sprintf("%s %d, %s %d: %d unexplained", c.Source, len(c.Members), c.CrossName, len(c.Cross), c.Unexplained())
}

// sourceName is what a source is called: its title, or its machine name.
func sourceName(v *register.View, id register.ID) string {
	e, err := v.Get(id)
	if err != nil {
		return string(id)
	}
	s, ok := e.Record.(register.Source)
	if !ok {
		return string(id)
	}
	if s.Title != "" {
		return s.Title
	}
	return s.Name
}

// Unexplained is the disagreement between the two sources: what either has
// that the other has no counterpart for.
func (c Count) Unexplained() int { return len(c.OnlyHere) + len(c.OnlyThere) }

// CountAt counts a population at a view, as of now, and writes nothing.
func CountAt(v *register.View, id register.ID, now time.Time) (Count, error) {
	e, err := v.Get(id)
	if err != nil {
		return Count{}, err
	}
	pop, ok := e.Record.(register.Population)
	if !ok {
		return Count{}, fmt.Errorf("%w: %s is not a population", register.ErrNotFound, id)
	}
	q, err := queryAt(v, pop.Query)
	if err != nil {
		return Count{}, fmt.Errorf("%w: the query that selects the population is not in the register", register.ErrNotFound)
	}
	sel, err := Select(v, q, pop.Source)
	if err != nil {
		return Count{}, err
	}
	c := Count{ID: id, Population: pop, Members: sel.Members, Source: sourceName(v, pop.Source)}
	if pop.CrossCheck != "" {
		cq, err := queryAt(v, pop.CrossQuery)
		if err != nil {
			return Count{}, fmt.Errorf("%w: the query that selects the cross-check is not in the register", register.ErrNotFound)
		}
		cross, err := Select(v, cq, pop.CrossCheck)
		if err != nil {
			return Count{}, err
		}
		c.Cross, c.CrossName = cross.Members, sourceName(v, pop.CrossCheck)
		links, err := linked(v)
		if err != nil {
			return Count{}, err
		}
		c.OnlyHere = unmatched(c.Members, c.Cross, links)
		c.OnlyThere = unmatched(c.Cross, c.Members, links)
	}
	pop.Size, pop.Members = int64(len(c.Members)), membersDigest(c.Members)
	pop.CrossSize, pop.Unexplained = int64(len(c.Cross)), int64(c.Unexplained())
	pop.Counted, pop.Commit = register.TimeOf(now), v.Commit()
	c.Population = pop
	c.Labels = Labels(pop, now)
	return c, nil
}

// linked is every link at a view, each way.
func linked(v *register.View) (map[register.ID][]register.ID, error) {
	out := map[register.ID][]register.ID{}
	err := v.Each(register.KindLink, func(e register.Entry, _ map[string]any) error {
		l := e.Record.(register.Link)
		out[l.A] = append(out[l.A], l.B)
		out[l.B] = append(out[l.B], l.A)
		return nil
	})
	return out, err
}

// unmatched is the members of one side with no counterpart on the other:
// not the same record, and not linked to one.
func unmatched(side, other []register.ID, links map[register.ID][]register.ID) []register.ID {
	there := map[register.ID]bool{}
	for _, id := range other {
		there[id] = true
	}
	var out []register.ID
	for _, id := range side {
		found := there[id]
		for _, l := range links[id] {
			found = found || there[l]
		}
		if !found {
			out = append(out, id)
		}
	}
	return out
}

// Recount counts a population at the register's head and writes the count
// into it: both numbers, the disagreement, when and at which commit.
func (p *Programme) Recount(by register.Actor, id register.ID) (Count, register.Receipt, error) {
	v, err := p.Reg.At("")
	if err != nil {
		return Count{}, register.Receipt{}, err
	}
	c, err := CountAt(v, id, p.now())
	if err != nil {
		return Count{}, register.Receipt{}, err
	}
	rc, err := p.Reg.Put(by, "a count of the population "+c.Population.Name, c.Population)
	return c, rc, err
}

// Definition is a population as a person defines it.
type Definition struct {
	Name, Title string
	Source      string
	Query       register.Query
	Fresh       time.Duration
	Independent bool
	CrossCheck  string
	CrossQuery  *register.Query
}

// Define writes a population and its queries, as one commit. The sources
// are named by their machine names and must be in the register.
func (p *Programme) Define(by register.Actor, d Definition) (register.ID, register.Receipt, error) {
	v, err := p.Reg.At("")
	if err != nil {
		return "", register.Receipt{}, err
	}
	src, err := named(v, register.KindSource, register.Local, d.Source)
	if err != nil {
		return "", register.Receipt{}, err
	}
	q, err := CheckQuery(d.Query)
	if err != nil {
		return "", register.Receipt{}, err
	}
	pop := register.Population{Name: d.Name, Title: d.Title, Source: src, Query: q.Digest,
		Fresh: int64(d.Fresh / time.Second), Independent: d.Independent}
	recs := []register.Record{q}
	if d.CrossCheck != "" {
		if d.CrossQuery == nil {
			return "", register.Receipt{}, fmt.Errorf("%w: a cross-check names the query that selects what it knows of",
				register.ErrInvalid)
		}
		cross, err := named(v, register.KindSource, register.Local, d.CrossCheck)
		if err != nil {
			return "", register.Receipt{}, err
		}
		cq, err := CheckQuery(*d.CrossQuery)
		if err != nil {
			return "", register.Receipt{}, err
		}
		pop.CrossCheck, pop.CrossQuery = cross, cq.Digest
		recs = append(recs, cq)
	}
	// A population redefined has no count until it is counted again: the
	// count it had was of what it was.
	id, err := register.IDOf(pop)
	if err != nil {
		return "", register.Receipt{}, err
	}
	recs = append(recs, pop)
	rc, err := p.Reg.Put(by, "the population "+d.Name, recs...)
	return id, rc, err
}
