// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package entity is a group of companies, and the one rule that makes
// shared controls honest.
//
// # The shared-control illusion
//
// A group defines one control — multi-factor authentication enforced — and
// marks it as shared across five subsidiaries. Evidence arrives from the
// parent's identity provider. Every dashboard turns green for all five.
//
// The German subsidiary runs its own tenant and nobody ever connected it.
// The control is evidenced for one entity and reported for five, and the
// reason this goes unnoticed for a year is that nothing in the system is
// wrong: the control exists, the evidence is real, the connector works. It
// simply speaks for one company and is being read as speaking for the group.
//
// This is the failure the enterprise literature names when it says control
// failures go undetected without true multi-entity support, and the fix is
// not a feature. It is an arithmetic decision: a shared control is exactly as
// covered as its worst entity, and a report that shows the union of its
// evidence is lying by construction.
//
// # Evidence flows down and never up
//
// A control the group operates — a group-wide identity provider, a policy
// that binds every subsidiary — genuinely covers the companies beneath it.
// The reverse is never true. A subsidiary's export does not evidence the
// group's control, because the group includes companies that export did not
// look at.
//
// Reaches() is that rule and it is four lines. Nearly every implementation of
// this gets it wrong in the same direction, because the wrong direction is
// the one that makes a number go up.
//
// # Inheritance is a claim, not a default
//
// A subsidiary relying on the group's control has to be able to show it at
// audit, and "the parent does that" is only an answer if the parent's
// evidence is in scope for the subsidiary's examination. So relying on an
// ancestor is recorded, with who decided it — and a reliance on an entity
// that has no evidence of its own is reported rather than inherited.
package entity

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

// MaxDepth bounds how deep a group may nest.
//
// Eight. Deeper than any real corporate structure and shallow enough that a
// malformed file cannot make a traversal expensive.
const MaxDepth = 8

// Entity is one company in a group.
type Entity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Parent is the entity above this one. Empty for the root.
	Parent string `json:"parent,omitempty"`
	// Owner is who is accountable here. A group has one person for the
	// whole thing and one per company, and the second is the one an auditor
	// asks for.
	Owner string `json:"owner,omitempty"`
	// Region is where this company operates, which decides which
	// frameworks apply to it and where its data may sit.
	Region string `json:"region,omitempty"`
	// Note is for whoever reads the structure next.
	Note string `json:"note,omitempty"`
}

// Validate refuses an entity that cannot sit in a tree.
func (e Entity) Validate() error {
	if strings.TrimSpace(e.ID) == "" {
		return fmt.Errorf("an entity needs an identifier")
	}
	if e.ID != strings.ToLower(e.ID) || strings.ContainsAny(e.ID, " /\\:") {
		return fmt.Errorf(
			"%q is not usable as an entity identifier. Lowercase, no "+
				"spaces and no slashes: it becomes a path segment and half "+
				"of every scoped grant", e.ID)
	}
	if strings.TrimSpace(e.Name) == "" {
		return fmt.Errorf(
			"%s has no name. A report that lists companies by identifier is "+
				"one nobody outside the team can read", e.ID)
	}
	if e.Parent == e.ID {
		return fmt.Errorf("%s is its own parent", e.ID)
	}
	return nil
}

// Tree is a group.
type Tree struct {
	byID     map[string]Entity
	order    []string
	children map[string][]string
	root     string
}

// New starts an empty tree.
func New() *Tree {
	return &Tree{byID: map[string]Entity{}, children: map[string][]string{}}
}

// Add puts an entity in the tree.
//
// Parents are resolved when the tree is closed rather than here, so a file
// may list companies in any order — which is what a file maintained by hand
// ends up doing.
func (t *Tree) Add(e Entity) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if _, seen := t.byID[e.ID]; seen {
		return fmt.Errorf("there are two entities called %s", e.ID)
	}
	t.byID[e.ID] = e
	t.order = append(t.order, e.ID)
	return nil
}

// Close resolves the structure and refuses one that is not a tree.
func (t *Tree) Close() error {
	t.children = map[string][]string{}
	t.root = ""
	var roots []string
	for _, id := range t.order {
		e := t.byID[id]
		if e.Parent == "" {
			roots = append(roots, id)
			continue
		}
		if _, ok := t.byID[e.Parent]; !ok {
			return fmt.Errorf(
				"%s names %s as its parent and there is no such entity. A "+
					"company hanging off nothing is one that appears in no "+
					"scope and is reported on by nothing", e.ID, e.Parent)
		}
		t.children[e.Parent] = append(t.children[e.Parent], id)
	}
	switch len(roots) {
	case 0:
		if len(t.order) > 0 {
			return fmt.Errorf(
				"every entity has a parent, so this is a cycle rather than " +
					"a group")
		}
		return nil
	case 1:
		t.root = roots[0]
	default:
		sort.Strings(roots)
		return fmt.Errorf(
			"there are %d entities with no parent: %s. A group has one top, "+
				"and two separate trees in one file are two groups that "+
				"will share a scope by accident", len(roots),
			strings.Join(roots, ", "))
	}
	for _, id := range t.order {
		if _, err := t.Ancestors(id); err != nil {
			return err
		}
	}
	for k := range t.children {
		sort.Strings(t.children[k])
	}
	return nil
}

// Root is the top of the group.
func (t *Tree) Root() string { return t.root }

// Len is how many companies are in the group.
func (t *Tree) Len() int { return len(t.byID) }

// Get returns one entity.
func (t *Tree) Get(id string) (Entity, bool) {
	e, ok := t.byID[id]
	return e, ok
}

// All returns every entity, in the order they were added.
func (t *Tree) All() []Entity {
	out := make([]Entity, 0, len(t.order))
	for _, id := range t.order {
		out = append(out, t.byID[id])
	}
	return out
}

// Ancestors returns the entities above one, nearest first.
func (t *Tree) Ancestors(id string) ([]string, error) {
	var out []string
	seen := map[string]bool{id: true}
	at := id
	for depth := 0; ; depth++ {
		e, ok := t.byID[at]
		if !ok || e.Parent == "" {
			return out, nil
		}
		if seen[e.Parent] {
			return nil, fmt.Errorf(
				"%s is inside a cycle through %s. A group that contains "+
					"itself makes every scope infinite", id, e.Parent)
		}
		if depth >= MaxDepth {
			return nil, fmt.Errorf(
				"%s is more than %d levels deep, which is deeper than any "+
					"real corporate structure and is usually a mistake in "+
					"the file", id, MaxDepth)
		}
		seen[e.Parent] = true
		out = append(out, e.Parent)
		at = e.Parent
	}
}

// Children returns the entities directly beneath one.
func (t *Tree) Children(id string) []string {
	return append([]string(nil), t.children[id]...)
}

// Scope returns an entity and everything beneath it, nearest first.
//
// What an audit covers. A SOC 2 for the American company covers that company
// and whatever it consolidates, and not the group's other half.
func (t *Tree) Scope(id string) []string {
	if _, ok := t.byID[id]; !ok {
		return nil
	}
	out := []string{id}
	for i := 0; i < len(out); i++ {
		out = append(out, t.children[out[i]]...)
	}
	return out
}

// Path is the entity's position, as a slash-separated string.
//
// The shape internal/auth already scopes grants on, so authority over a
// company and authority over everything beneath it are the same mechanism
// that scopes authority over a section of a site.
func (t *Tree) Path(id string) string {
	up, err := t.Ancestors(id)
	if err != nil {
		return ""
	}
	parts := make([]string, 0, len(up)+1)
	for i := len(up) - 1; i >= 0; i-- {
		parts = append(parts, up[i])
	}
	parts = append(parts, id)
	return "/" + strings.Join(parts, "/")
}

// Reaches reports whether evidence gathered for one entity speaks for
// another.
//
// Down the tree and never up. The group's identity provider covers the
// companies beneath it; a subsidiary's export does not cover the group,
// because the group includes companies that export never looked at.
//
// Four lines, and nearly every implementation of this gets it wrong in the
// same direction — because the wrong direction is the one that makes a
// number go up.
func (t *Tree) Reaches(from, to string) bool {
	if from == to {
		return true
	}
	up, err := t.Ancestors(to)
	if err != nil {
		return false
	}
	for _, a := range up {
		if a == from {
			return true
		}
	}
	return false
}

// Reliance is a subsidiary recording that it depends on an ancestor's control.
//
// Recorded rather than assumed. At audit the subsidiary has to show the
// control, and "the parent does that" is only an answer if the parent's
// evidence is in scope for this examination — which is a judgement somebody
// makes, with their name on it.
type Reliance struct {
	// Entity is the company relying, and On the one it relies upon.
	Entity string `json:"entity"`
	On     string `json:"on"`
	// Control is what is being relied upon.
	Control string `json:"control"`
	// Because is why that is acceptable for this company's audit.
	Because string `json:"because"`

	At   time.Time  `json:"at"`
	By   string     `json:"by"`
	Kind audit.Kind `json:"kind,omitempty"`
}

// Key identifies what a reliance is about.
func (r Reliance) Key() string { return r.Entity + "\x00" + r.Control }

// Validate refuses a reliance that would inherit the wrong way.
func (r Reliance) Validate(t *Tree) error {
	if strings.TrimSpace(r.Entity) == "" || strings.TrimSpace(r.On) == "" {
		return fmt.Errorf("a reliance needs two entities")
	}
	if strings.TrimSpace(r.Control) == "" {
		return fmt.Errorf("%s relies on %s for nothing in particular",
			r.Entity, r.On)
	}
	if r.Entity == r.On {
		return fmt.Errorf("%s relies on itself, which is not a reliance",
			r.Entity)
	}
	if t != nil {
		if _, ok := t.Get(r.Entity); !ok {
			return fmt.Errorf("there is no entity %s", r.Entity)
		}
		if _, ok := t.Get(r.On); !ok {
			return fmt.Errorf("there is no entity %s", r.On)
		}
		if !t.Reaches(r.On, r.Entity) {
			return fmt.Errorf(
				"%s cannot rely on %s: evidence flows down a group and "+
					"never up or sideways. %s is not above %s, so its "+
					"evidence says nothing about this company", r.Entity,
				r.On, r.On, r.Entity)
		}
	}
	if r.At.IsZero() {
		return fmt.Errorf("%s has no date", r.Key())
	}
	if strings.TrimSpace(r.By) == "" {
		return fmt.Errorf(
			"%s names nobody. Relying on a parent's control is a judgement "+
				"the subsidiary's auditor will question, and the person who "+
				"made it is the one they ask", r.Key())
	}
	if r.Kind == audit.KindAI {
		return fmt.Errorf(
			"%s was decided by a model. Whether a parent's evidence is in "+
				"scope for a subsidiary's examination is a question about "+
				"two audits and a contract; a person answers it", r.Key())
	}
	if strings.TrimSpace(r.Because) == "" {
		return fmt.Errorf(
			"%s records no reason. The question at audit is not whether the "+
				"parent operates the control, it is why that counts here",
			r.Key())
	}
	return nil
}

// Record turns a reliance into an audit entry.
func (r Reliance) Record() audit.Record {
	return audit.Record{
		Action: "entity.relies", Resource: "/entity/" + r.Entity,
		Outcome: audit.Success, Principal: r.By, Kind: r.Kind,
		Verified: r.Kind != audit.KindUnknown,
		Detail: map[string]string{
			"entity": r.Entity, "on": r.On, "control": r.Control,
			"because": r.Because,
		},
	}
}
