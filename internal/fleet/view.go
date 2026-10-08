// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package fleet

import (
	"sort"
	"time"
)

// Kinds of thing in the fleet.
const (
	KindAgent    = "agent"
	KindApp      = "app"
	KindTool     = "tool server"
	KindRoute    = "model route"
	KindExternal = "external agent"
	KindPerson   = "person"
	KindQuilzo   = "Quilzo"
)

// Node is one thing in the fleet.
type Node struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"`
	Name     string    `json:"name"`
	Detail   string    `json:"detail,omitempty"`
	Owner    string    `json:"owner,omitempty"`
	Standing string    `json:"standing,omitempty"`
	Autonomy string    `json:"autonomy,omitempty"`
	Spent    string    `json:"spent,omitempty"`
	Last     time.Time `json:"last,omitzero"`
	Flags    []string  `json:"flags,omitempty"`
}

// Edge is who called what, as the log recorded it: not what was declared,
// what happened.
type Edge struct {
	From  string    `json:"from"`
	To    string    `json:"to"`
	Calls int       `json:"calls"`
	Last  time.Time `json:"last"`
}

// View is the fleet: everything, who called what, and the AI use nobody
// registered.
type View struct {
	Nodes  []Node     `json:"nodes"`
	Edges  []Edge     `json:"edges"`
	Shadow []Sighting `json:"shadow"`
	Days   int        `json:"days"`
}

// Edges collects calls into edges.
type Edges struct{ m map[[2]string]*Edge }

// Add counts one call from one thing to another.
func (e *Edges) Add(from, to string, at time.Time) {
	if from == "" || to == "" || from == to {
		return
	}
	if e.m == nil {
		e.m = map[[2]string]*Edge{}
	}
	k := [2]string{from, to}
	x := e.m[k]
	if x == nil {
		x = &Edge{From: from, To: to}
		e.m[k] = x
	}
	x.Calls++
	if at.After(x.Last) {
		x.Last = at
	}
}

// List is the edges, busiest first.
func (e *Edges) List() []Edge {
	out := make([]Edge, 0, len(e.m))
	for _, x := range e.m {
		out = append(out, *x)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Calls != out[j].Calls {
			return out[i].Calls > out[j].Calls
		}
		return out[i].From+out[i].To < out[j].From+out[j].To
	})
	return out
}

// Touch marks a node as last seen at a time, adding it as a kind of thing
// the view had not listed when it is not there yet (a person, say).
func (v *View) Touch(id, kind, name string, at time.Time) {
	for i := range v.Nodes {
		if v.Nodes[i].ID == id {
			if at.After(v.Nodes[i].Last) {
				v.Nodes[i].Last = at
			}
			return
		}
	}
	v.Nodes = append(v.Nodes, Node{ID: id, Kind: kind, Name: name, Last: at})
}
