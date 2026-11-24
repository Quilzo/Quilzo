// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

import (
	"fmt"
	"sort"

	"github.com/quilzo/quilzo/internal/register"
)

// Links: two records from two sources that are the same thing.
//
// Code makes a link, and only on an identifier both sources report and
// that is the same byte for byte: a serial number, a host name, a cloud
// resource's identifier, a user principal name, the hash of an address. A
// near match is not a match. "LAPTOP-07" and "laptop-07", or an address
// with a trailing space, are two things until the source that spells it
// otherwise is fixed, because a join made on a guess is a population
// counted on a guess, and nobody can tell afterwards which members were
// guessed. An identifier two records of one source share is ambiguous,
// and links neither of them.

// Side is where one source reports the identifier: the Ref of its assets
// when Fact is empty, or the value of one of its observations.
type Side struct {
	Source register.ID `json:"source"`
	Fact   string      `json:"fact,omitempty"`
}

// Correlation is what a correlation found.
type Correlation struct {
	Links []register.Link `json:"links"`
	// Ambiguous counts identifiers that two records of one source share,
	// which linked nothing.
	Ambiguous int `json:"ambiguous"`
}

// Correlate finds the links between two sides on one identifier, at a
// view. It writes nothing; Link writes what it found.
func Correlate(v *register.View, on register.LinkOn, a, b Side) (Correlation, error) {
	if !validLinkOn(on) {
		return Correlation{}, fmt.Errorf("%w: a link is made on one of %v", register.ErrInvalid, register.LinkOn("").Values())
	}
	if a.Source == b.Source {
		return Correlation{}, fmt.Errorf("%w: a link joins two sources, and both sides are one", register.ErrInvalid)
	}
	left, ambigA, err := identifiers(v, a)
	if err != nil {
		return Correlation{}, err
	}
	right, ambigB, err := identifiers(v, b)
	if err != nil {
		return Correlation{}, err
	}
	out := Correlation{Ambiguous: ambigA + ambigB, Links: []register.Link{}}
	for value, x := range left {
		y, ok := right[value]
		if !ok || x == y {
			continue
		}
		lo, hi := x, y
		if hi < lo {
			lo, hi = hi, lo
		}
		out.Links = append(out.Links, register.Link{A: lo, B: hi, On: on,
			Match: digestOf("quilzo link identifier v1\n"+string(on)+"\n", []string{value})})
	}
	sort.Slice(out.Links, func(i, j int) bool {
		if out.Links[i].A != out.Links[j].A {
			return out.Links[i].A < out.Links[j].A
		}
		return out.Links[i].B < out.Links[j].B
	})
	return out, nil
}

func validLinkOn(on register.LinkOn) bool {
	for _, v := range on.Values() {
		if v == string(on) {
			return true
		}
	}
	return false
}

// identifiers is each value one side reports, with the record it is about.
// A value reported about two records is ambiguous and dropped.
func identifiers(v *register.View, s Side) (map[string]register.ID, int, error) {
	got := map[string]register.ID{}
	dup := map[string]bool{}
	add := func(value string, id register.ID) {
		if value == "" {
			return
		}
		if had, ok := got[value]; ok && had != id {
			dup[value] = true
			return
		}
		got[value] = id
	}
	var err error
	if s.Fact == "" {
		err = v.Each(register.KindAsset, func(e register.Entry, _ map[string]any) error {
			if a := e.Record.(register.Asset); a.Source == s.Source {
				add(a.Ref, e.ID)
			}
			return nil
		})
	} else {
		err = v.Each(register.KindObservation, func(e register.Entry, _ map[string]any) error {
			o := e.Record.(register.Observation)
			if text, ok := o.Value.Value().(string); ok && o.Source == s.Source && o.Fact == s.Fact {
				add(text, o.About)
			}
			return nil
		})
	}
	for value := range dup {
		delete(got, value)
	}
	return got, len(dup), err
}

// Link finds the links between two sides and writes them, as one commit.
func (p *Programme) Link(by register.Actor, on register.LinkOn, a, b Side) (Correlation, register.Receipt, error) {
	v, err := p.Reg.At("")
	if err != nil {
		return Correlation{}, register.Receipt{}, err
	}
	for _, s := range []Side{a, b} {
		if e, err := v.Get(s.Source); err != nil || e.Kind != register.KindSource {
			return Correlation{}, register.Receipt{}, fmt.Errorf("%w: the source %s is not in the register",
				register.ErrNotFound, s.Source)
		}
	}
	c, err := Correlate(v, on, a, b)
	if err != nil || len(c.Links) == 0 {
		return c, register.Receipt{}, err
	}
	recs := make([]register.Record, len(c.Links))
	for i, l := range c.Links {
		recs[i] = l
	}
	rc, err := p.Reg.Put(by, fmt.Sprintf("links on %s between two sources", on), recs...)
	return c, rc, err
}
