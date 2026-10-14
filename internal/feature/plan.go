// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// What installing a package would change, worked out against what the
// installation holds now.
//
// A feature owns what it created and nothing else. A name already in use by
// a person or by another feature is a conflict and the install is refused:
// otherwise removing the feature later would remove somebody else's work,
// and an upgrade could quietly rewrite a block it never made.

// Actions in a plan.
const (
	Add    = "add"
	Change = "change"
	Keep   = "keep"
	Remove = "remove"
)

// State is what the installation holds, as the command line reads it.
type State struct {
	// Current is each existing block's definition, as JSON.
	Current map[Ref]json.RawMessage
	// Owner is the feature that installed a block. Absent means a person
	// made it, or it predates features.
	Owner map[Ref]string
}

// Step is one change.
type Step struct {
	Ref    Ref    `json:"ref"`
	Action string `json:"action"`
}

// Plan is what an install would do.
type Plan struct {
	Steps     []Step   `json:"steps"`
	Conflicts []string `json:"conflicts,omitempty"`
}

// Block is a block's definition as declared in the package, or nil.
func (p *Package) Block(r Ref) any {
	switch r.Kind {
	case "type":
		for _, t := range p.Types {
			if t.Name == r.Name {
				return t
			}
		}
	case "collection":
		for _, c := range p.Collections {
			if c.Name == r.Name {
				return c
			}
		}
	case "listing":
		for _, l := range p.Listings {
			if l.Name == r.Name {
				return l
			}
		}
	case "form":
		for _, f := range p.Forms {
			if f.Name == r.Name {
				return f
			}
		}
	case "page":
		for _, pg := range p.Pages {
			if pg.Name == r.Name {
				return pg.Body
			}
		}
	case "menu":
		for _, m := range p.Menus {
			if m.Name == r.Name {
				return m
			}
		}
	case "chatbot":
		for _, a := range p.Chatbots {
			if a.Name == r.Name {
				return a
			}
		}
	case "agent":
		for _, m := range p.Agents {
			if m.Name == r.Name {
				return m
			}
		}
	case "webhook":
		for _, h := range p.Webhooks {
			if h.URL == r.Name {
				return h
			}
		}
	}
	return nil
}

// Same reports whether two definitions are the same once both are JSON.
func Same(a any, b json.RawMessage) bool {
	x, err := json.Marshal(a)
	if err != nil {
		return false
	}
	var ya, yb any
	if json.Unmarshal(x, &ya) != nil || json.Unmarshal(b, &yb) != nil {
		return false
	}
	na, _ := json.Marshal(ya)
	nb, _ := json.Marshal(yb)
	return bytes.Equal(na, nb)
}

// MakePlan works out the steps. owned is what the installed version of this
// feature owns, empty for a first install.
func (p *Package) MakePlan(st State, owned []Ref) Plan {
	var pl Plan
	declared := map[Ref]bool{}
	for _, r := range p.Refs() {
		declared[r] = true
		cur, exists := st.Current[r]
		owner := st.Owner[r]
		switch {
		case !exists:
			pl.Steps = append(pl.Steps, Step{r, Add})
		case owner != p.Name:
			who := "a person"
			if owner != "" {
				who = "the feature " + owner
			}
			pl.Conflicts = append(pl.Conflicts, fmt.Sprintf("%s already exists and was made by %s", r, who))
		case Same(p.Block(r), cur):
			pl.Steps = append(pl.Steps, Step{r, Keep})
		default:
			pl.Steps = append(pl.Steps, Step{r, Change})
		}
	}
	for _, r := range owned {
		if !declared[r] {
			pl.Steps = append(pl.Steps, Step{r, Remove})
		}
	}
	sort.Strings(pl.Conflicts)
	return pl
}

// Installed is the record of a feature on this installation.
type Installed struct {
	Name    string    `json:"name"`
	Version string    `json:"version"`
	Digest  string    `json:"digest"`
	Title   string    `json:"title"`
	At      time.Time `json:"at"`
	// By is who approved it: one name, or two.
	By []string `json:"by"`
	// Owns is every block this feature made.
	Owns []Ref `json:"owns"`
	// Disabled is set when somebody turned the feature off everywhere.
	Disabled bool `json:"disabled,omitempty"`
	// History is the earlier versions, newest first, kept so a rollback
	// reinstalls exactly what was there.
	History []Version `json:"history,omitempty"`
}

// Version is one earlier install.
type Version struct {
	Version string    `json:"version"`
	Digest  string    `json:"digest"`
	At      time.Time `json:"at"`
	By      []string  `json:"by"`
}

// Pending is an install waiting for a second person.
type Pending struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Digest      string    `json:"digest"`
	RequestedBy string    `json:"requested_by"`
	At          time.Time `json:"at"`
	Card        Card      `json:"card"`
	Plan        Plan      `json:"plan"`
	// Rollback marks a request to go back to an earlier version.
	Rollback bool `json:"rollback,omitempty"`
	// Rows is how many records are imported into RowsCollection once it
	// is approved, from a file kept beside the request.
	Rows           int    `json:"rows,omitempty"`
	RowsCollection string `json:"rows_collection,omitempty"`
}

// PendingTTL is how long a request waits before it lapses.
const PendingTTL = 7 * 24 * time.Hour
