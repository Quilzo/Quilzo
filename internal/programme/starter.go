// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"sync"

	"github.com/quilzo/quilzo/internal/frameworks"
	"github.com/quilzo/quilzo/internal/register"
)

// Starters: a framework's requirements, ready to be taken into the
// programme.
//
// Each requirement is the framework's own identifier and a line in
// Quilzo's own words saying what it is about. None of a standard's text is
// here: ISO's, the AICPA's and NIST's documents are their publishers', and a
// copy shipped with a program is an infringement and goes stale. The
// identifier is what a reader looks the clause up by in the copy they are
// licensed to read, and the line is enough to recognise it.
//
// A starter is taken in, or out, as one decision: a register.Starter record
// with its approval, written in the same commit as the requirements and
// mappings it brings. That is internal/feature's rule for a feature, kept
// here through the register's own write path because the register's
// collections refuse every other.

// Starter is one framework's requirements, and how some of them relate to
// another framework's.
type Starter struct {
	// Framework is its name as the programme files it, internal/frameworks'
	// identifier where that package carries the framework.
	Framework string
	// Name and Version are what the framework is called and the edition the
	// starter is written against; About says what it is, in a sentence.
	Name, Version, About string
	// Level says what the identifiers are: the clauses of an annex, the
	// articles of a regulation, the categories of a framework's functions.
	Level string
	// Clauses are its requirements, in the framework's own order.
	Clauses []Clause
	// Crosswalk is how some of its requirements relate to another
	// framework's, in NIST IR 8477's relationships, each with why.
	Crosswalk []Relation
}

// Clause is one requirement: the framework's identifier for it and a line
// in Quilzo's own words.
type Clause struct {
	Ref, Line string
}

// Relation is how one of a starter's requirements relates to another
// framework's: From is the starter's requirement, To the other's, and
// Relation what From is to To.
type Relation struct {
	From      string
	Framework string
	To        string
	Relation  register.Relation
	Why       string
}

var (
	startersMu sync.Mutex
	starters   = map[string]*Starter{}
	// rationales is the words of every relation's Why, by its digest, so a
	// screen shows the words a mapping's Rationale names.
	rationales = map[register.Text]string{}
)

// starter adds a starter, from the file that holds it. A starter declared
// wrongly stops the program starting: it is a mistake in the program.
func starter(s Starter) *Starter {
	if err := s.check(); err != nil {
		panic("programme: the " + s.Framework + " starter: " + err.Error())
	}
	startersMu.Lock()
	defer startersMu.Unlock()
	if _, dup := starters[s.Framework]; dup {
		panic("programme: the " + s.Framework + " starter is declared twice")
	}
	starters[s.Framework] = &s
	for _, r := range s.Crosswalk {
		rationales[TextOf(r.Why)] = r.Why
	}
	return &s
}

func (s Starter) check() error {
	if len(s.Clauses) == 0 || s.Name == "" || s.Version == "" || s.About == "" || s.Level == "" {
		return fmt.Errorf("a starter has a name, an edition, a sentence about it, what its identifiers are and requirements")
	}
	seen := map[string]bool{}
	for _, c := range s.Clauses {
		if c.Ref == "" || c.Line == "" || len(c.Line) > 160 {
			return fmt.Errorf("the requirement %q needs a line of at most 160 bytes", c.Ref)
		}
		if seen[c.Ref] {
			return fmt.Errorf("the requirement %s is listed twice", c.Ref)
		}
		seen[c.Ref] = true
	}
	for _, r := range s.Crosswalk {
		if !seen[r.From] {
			return fmt.Errorf("a relation starts from %s, which the starter does not hold", r.From)
		}
		if !slices.Contains(register.Relation("").Values(), string(r.Relation)) {
			return fmt.Errorf("the relation from %s to %s is %q, which is not one of NIST IR 8477's", r.From, r.To, r.Relation)
		}
		if r.Why == "" || r.Framework == "" || r.To == "" {
			return fmt.Errorf("the relation from %s names the other framework's requirement and says why", r.From)
		}
	}
	return nil
}

// Starters is every starter this program carries, in the order of their
// frameworks' names.
func Starters() []*Starter {
	startersMu.Lock()
	defer startersMu.Unlock()
	out := make([]*Starter, 0, len(starters))
	for _, s := range starters {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Framework < out[j].Framework })
	return out
}

// StarterNamed is the starter for a framework.
func StarterNamed(framework string) (*Starter, bool) {
	startersMu.Lock()
	defer startersMu.Unlock()
	s, ok := starters[framework]
	return s, ok
}

// starterWords is the words of a starter relation's rationale.
func starterWords(t register.Text) (string, bool) {
	startersMu.Lock()
	defer startersMu.Unlock()
	w, ok := rationales[t]
	return w, ok
}

// Catalogued is the framework as internal/frameworks describes it, where
// that package carries it.
func (s *Starter) Catalogued() (frameworks.Framework, bool) { return frameworks.Get(s.Framework) }

// Requirement is one clause as the register files it.
func (s *Starter) Requirement(c Clause) register.Requirement {
	return register.Requirement{Framework: s.Framework, Ref: c.Ref, Title: c.Line}
}

// RequirementID is the identifier of a framework's requirement, which is
// the same whether or not its starter is installed.
func RequirementID(framework, ref string) (register.ID, error) {
	return register.DeriveID(register.KindRequirement, framework, ref)
}

// Records is what installing the starter writes beside its decision: each
// requirement, and each relation to another framework as a Mapping.
func (s *Starter) Records() ([]register.Record, error) {
	var out []register.Record
	for _, c := range s.Clauses {
		out = append(out, s.Requirement(c))
	}
	for _, r := range s.Crosswalk {
		from, err := RequirementID(s.Framework, r.From)
		if err != nil {
			return nil, err
		}
		to, err := RequirementID(r.Framework, r.To)
		if err != nil {
			return nil, err
		}
		out = append(out, register.Mapping{From: from, To: to, Relation: r.Relation, Rationale: TextOf(r.Why)})
	}
	return out, nil
}

// Content is the digest of what the starter brings: SHA-256 over its
// framework, edition, requirements and relations as JSON. A decision names
// it, so approving a starter is approving exactly these lines.
func (s *Starter) Content() register.Digest {
	b, _ := json.Marshal(struct {
		Framework, Version string
		Clauses            []Clause
		Crosswalk          []Relation
	}{s.Framework, s.Version, s.Clauses, s.Crosswalk})
	h := sha256.New()
	h.Write([]byte("quilzo/programme starter v1\n"))
	h.Write(b)
	return register.Digest("sha256:" + hex.EncodeToString(h.Sum(nil)))
}

// Decision is the record of taking the starter in (install) or out.
func (s *Starter) Decision(install bool) register.Starter {
	return register.Starter{Framework: s.Framework, Version: s.Version, Content: s.Content(),
		Requirements: int64(len(s.Clauses)), Mappings: int64(len(s.Crosswalk)), Installed: install}
}

// Install raises the decision to take a starter in.
func (p *Programme) Install(d Decider, framework string) (Decided, error) {
	return p.starterDecision(d, framework, true)
}

// Uninstall raises the decision to take a starter out. Its requirements stay
// in the register, as everything written does, and are read as out of the
// programme.
func (p *Programme) Uninstall(d Decider, framework string) (Decided, error) {
	return p.starterDecision(d, framework, false)
}

func (p *Programme) starterDecision(d Decider, framework string, install bool) (Decided, error) {
	s, ok := StarterNamed(framework)
	if !ok {
		return Decided{}, fmt.Errorf("%w: there is no starter for %q", register.ErrNotFound, framework)
	}
	verb := "take the %s starter out of the programme"
	if install {
		verb = "take the %s starter into the programme"
	}
	return p.Raise(d, fmt.Sprintf(verb, framework), s.Decision(install))
}

// Installed is the frameworks whose starters are in the programme at a
// view, by name, with the decision that put each in.
func Installed(v *register.View) (map[string]register.Starter, error) {
	out := map[string]register.Starter{}
	err := v.Each(register.KindStarter, func(e register.Entry, _ map[string]any) error {
		if s := e.Record.(register.Starter); s.Installed {
			out[s.Framework] = s
		}
		return nil
	})
	return out, err
}
