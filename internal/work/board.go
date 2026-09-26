// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package work

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Item is one piece of work.
type Item struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Kind  string `json:"kind"`
	Owner string `json:"owner,omitempty"`

	State   State    `json:"state"`
	Waiting *Waiting `json:"waiting,omitempty"`
	Origin  Origin   `json:"origin"`

	// Met is which of the kind's requirements are satisfied, and Excused
	// is which were waived and by whom. Two maps rather than one, because
	// "we did it" and "we decided not to" are the only distinction anybody
	// cares about a quarter later and a single field would lose it.
	Met     []string          `json:"met,omitempty"`
	Excused map[string]string `json:"excused,omitempty"`

	Made  time.Time `json:"made"`
	Moved time.Time `json:"moved"`
	Log   []Move    `json:"log,omitempty"`
}

// NewID makes an identifier.
func NewID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Board is a set of work and the kinds it can be.
type Board struct {
	Name  string          `json:"name"`
	Kinds map[string]Kind `json:"kinds"`
	Items []*Item         `json:"items"`
}

// NewBoard starts a board with a set of kinds.
func NewBoard(name string, kinds ...Kind) (*Board, error) {
	b := &Board{Name: name, Kinds: map[string]Kind{}}
	for _, k := range kinds {
		if err := k.Validate(); err != nil {
			return nil, err
		}
		if _, dup := b.Kinds[k.Name]; dup {
			return nil, fmt.Errorf("there are two kinds called %q", k.Name)
		}
		b.Kinds[k.Name] = k
	}
	return b, nil
}

// Add puts new work on the board.
func (b *Board) Add(title, kind, owner string, o Origin,
	at time.Time) (*Item, error) {
	if strings.TrimSpace(title) == "" {
		return nil, fmt.Errorf("work needs a title somebody would recognise")
	}
	if _, ok := b.Kinds[kind]; !ok {
		return nil, fmt.Errorf("%q is not a kind of work on this board; "+
			"there are %s", kind, b.kindList())
	}
	if err := o.Validate(); err != nil {
		return nil, err
	}
	id, err := NewID()
	if err != nil {
		return nil, err
	}
	it := &Item{
		ID: id, Title: strings.TrimSpace(title), Kind: kind,
		Owner: strings.TrimSpace(owner), State: Todo, Origin: o,
		Made: at.UTC(), Moved: at.UTC(),
	}
	b.Items = append(b.Items, it)
	return it, nil
}

func (b *Board) kindList() string {
	out := make([]string, 0, len(b.Kinds))
	for k := range b.Kinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// Item looks work up by identifier.
func (b *Board) Item(id string) (*Item, bool) {
	for _, it := range b.Items {
		if it.ID == id {
			return it, true
		}
	}
	return nil, false
}

// Move changes an item's state.
//
// Backward moves and drops need a reason. Everything else does not, because
// a tracker that asks for a justification on every click is a tracker
// people work around.
func (b *Board) Move(id string, to State, by, why string,
	at time.Time) error {
	it, ok := b.Item(id)
	if !ok {
		return fmt.Errorf("no item %s", id)
	}
	if !to.Known() {
		return fmt.Errorf("%q is not a state. There are four — %s — and "+
			"there is no way to add a fifth, because the things teams "+
			"usually add are not states, they are what the work is waiting "+
			"on. Set that instead", to, stateList())
	}
	if to == it.State {
		return nil
	}
	if strings.TrimSpace(by) == "" {
		return fmt.Errorf("a move is somebody's")
	}
	why = strings.TrimSpace(why)
	if it.State.Backward(to) && why == "" {
		return fmt.Errorf(
			"moving from %s back to %s is the most informative thing that "+
				"happens on a board, and it needs a reason. Without one it "+
				"is indistinguishable from any other move, which is why "+
				"teams end up inventing a Reopened state and then having "+
				"two that mean %s", it.State, to, Todo)
	}
	if to == Dropped && why == "" {
		return fmt.Errorf("dropping work needs a reason. Silently " +
			"abandoned work is what turns a backlog into a graveyard, and " +
			"a year later nobody can tell it from work that was forgotten")
	}
	if to == Done {
		if missing := b.Unmet(it); len(missing) > 0 {
			return fmt.Errorf(
				"%q is not done. Still outstanding: %s. Meet what is "+
					"missing, or excuse it and say who decided",
				it.Title, strings.Join(missing, ", "))
		}
	}
	from := it.State
	it.State, it.Moved = to, at.UTC()
	if !to.Open() {
		it.Waiting = nil
	}
	it.Log = append(it.Log, Move{
		From: from, To: to, By: strings.TrimSpace(by), At: at.UTC(),
		Why: why,
	})
	return nil
}

func stateList() string {
	out := make([]string, 0, len(States))
	for _, s := range States {
		out = append(out, string(s))
	}
	return strings.Join(out, ", ")
}

// Wait records what an item is held up by.
func (b *Board) Wait(id string, w Waiting, at time.Time) error {
	it, ok := b.Item(id)
	if !ok {
		return fmt.Errorf("no item %s", id)
	}
	if !it.State.Open() {
		return fmt.Errorf("%q is %s, so nothing is holding it up",
			it.Title, it.State)
	}
	if err := w.Validate(); err != nil {
		return err
	}
	if w.Since.IsZero() {
		w.Since = at.UTC()
	}
	it.Waiting = &w
	return nil
}

// Unblock records that whatever was holding an item up has arrived.
func (b *Board) Unblock(id string) error {
	it, ok := b.Item(id)
	if !ok {
		return fmt.Errorf("no item %s", id)
	}
	it.Waiting = nil
	return nil
}

// Meet records that a requirement is satisfied.
func (b *Board) Meet(id, requirement string) error {
	it, ok := b.Item(id)
	if !ok {
		return fmt.Errorf("no item %s", id)
	}
	k := b.Kinds[it.Kind]
	if !has(k.Requires, requirement) {
		return fmt.Errorf("%q is not in the definition of done for a %s; "+
			"it is %s", requirement, it.Kind,
			strings.Join(k.Requires, ", "))
	}
	if !has(it.Met, requirement) {
		it.Met = append(it.Met, requirement)
	}
	delete(it.Excused, requirement)
	return nil
}

// Excuse waives a requirement, on the record.
func (b *Board) Excuse(id, requirement, by, why string) error {
	it, ok := b.Item(id)
	if !ok {
		return fmt.Errorf("no item %s", id)
	}
	k := b.Kinds[it.Kind]
	if !has(k.Requires, requirement) {
		return fmt.Errorf("%q is not in the definition of done for a %s",
			requirement, it.Kind)
	}
	if strings.TrimSpace(by) == "" || strings.TrimSpace(why) == "" {
		return fmt.Errorf("excusing a requirement takes a name and a " +
			"reason. An anonymous exception is the same as not having the " +
			"requirement, and it will be found in an audit rather than in " +
			"a decision")
	}
	if it.Excused == nil {
		it.Excused = map[string]string{}
	}
	it.Excused[requirement] = strings.TrimSpace(by) + ": " +
		strings.TrimSpace(why)
	return nil
}

// Unmet is what still stands between an item and Done.
func (b *Board) Unmet(it *Item) []string {
	k := b.Kinds[it.Kind]
	var out []string
	for _, r := range k.Requires {
		if has(it.Met, r) {
			continue
		}
		if _, waived := it.Excused[r]; waived {
			continue
		}
		out = append(out, r)
	}
	return out
}

func has(in []string, want string) bool {
	for _, s := range in {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}
