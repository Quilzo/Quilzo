// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import (
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
)

// Roles for the people who work in a feature (see internal/auth/approle.go).
//
// A role is declared over the package's own blocks and nothing else: its
// collections, its pages and its agents. It cannot name the site, an area,
// another feature's blocks, or administering anything, so the most a role
// can ever be is what the feature it came with already is. Declaring it
// grants nothing; a person who may grant access assigns it to somebody.

// Role is one role in the feature.
type Role struct {
	Name  string `json:"name"`
	Title string `json:"title"`
	// Summary is what somebody in the role does, in a sentence.
	Summary string  `json:"summary,omitempty"`
	Grants  []Grant `json:"grants"`
}

// Grant is one thing a role may do, on one of the package's blocks: a
// collection's records, a page, or an agent. May is what: read or write
// for a collection; read, write or publish for a page; run or approve for
// an agent.
type Grant struct {
	Collection string `json:"collection,omitempty"`
	Page       string `json:"page,omitempty"`
	Agent      string `json:"agent,omitempty"`
	May        string `json:"may"`
}

// MaxGrants bounds a role, so it stays something a person reads.
const MaxGrants = 40

// may is what each kind of block can be granted, and as what.
var may = map[string]map[string]auth.Binding{
	"collection": {
		"read":  {Role: auth.RoleReader},
		"write": {Role: auth.RoleAuthor},
	},
	"page": {
		"read":    {Role: auth.RoleReader},
		"write":   {Role: auth.RoleAuthor},
		"publish": {Role: auth.RolePublisher},
	},
	"agent": {
		"run":     {Permission: auth.ActRunAgents},
		"approve": {Permission: auth.ActApprove},
	},
}

// on is the kind and name of the block a grant is on, or empty kind when
// it names none or more than one.
func (g Grant) on() (string, string) {
	kind, name, n := "", "", 0
	for _, c := range []struct{ kind, name string }{{"collection", g.Collection}, {"page", g.Page}, {"agent", g.Agent}} {
		if c.name != "" {
			kind, name = c.kind, c.name
			n++
		}
	}
	if n != 1 {
		return "", ""
	}
	return kind, name
}

// Text is a grant in words.
func (g Grant) Text() string {
	kind, name := g.on()
	switch kind + " " + g.May {
	case "collection read":
		return fmt.Sprintf("reads the records in %q", name)
	case "collection write":
		return fmt.Sprintf("reads and writes the records in %q", name)
	case "page read":
		return fmt.Sprintf("reads the page %q and those under it", name)
	case "page write":
		return fmt.Sprintf("edits the page %q and those under it, in the draft", name)
	case "page publish":
		return fmt.Sprintf("edits and publishes the page %q and those under it", name)
	case "agent run":
		return fmt.Sprintf("runs the agent %q", name)
	case "agent approve":
		return fmt.Sprintf("decides what the agent %q waits for a person to decide", name)
	}
	return fmt.Sprintf("%s on %s %q", g.May, kind, name)
}

// FullName is the role's name with its feature's: lab-samples/technician.
func (p *Package) FullName(r Role) string { return p.Name + "/" + r.Name }

// AppRole is a role as the bindings it stands for.
func (p *Package) AppRole(r Role) auth.AppRole {
	out := auth.AppRole{Name: p.FullName(r), Title: r.Title, Summary: r.Summary}
	for _, g := range r.Grants {
		kind, name := g.on()
		b := may[kind][g.May]
		switch kind {
		case "collection":
			b.Resource = auth.DataResource(name)
		case "page":
			b.Resource = "/" + name
		case "agent":
			b.Resource = auth.AgentResource(name)
		}
		out.Bindings = append(out.Bindings, b)
		out.Grants = append(out.Grants, g.Text())
	}
	return out
}

// AppRoles is every role the package declares, as bindings.
func (p *Package) AppRoles() []auth.AppRole {
	out := make([]auth.AppRole, 0, len(p.Roles))
	for _, r := range p.Roles {
		out = append(out, p.AppRole(r))
	}
	return out
}

// validateRoles checks the roles against the blocks the package declares.
func (p *Package) validateRoles(bad func(string, ...any), unique func(string, string)) {
	declared := map[string]map[string]bool{"collection": {}, "page": {}, "agent": {}}
	for _, c := range p.Collections {
		declared["collection"][c.Name] = true
	}
	for _, pg := range p.Pages {
		declared["page"][pg.Name] = true
	}
	for _, m := range p.Agents {
		declared["agent"][m.Name] = true
	}
	for _, r := range p.Roles {
		unique("role", r.Name)
		if !reName.MatchString(r.Name) {
			bad("role name %q is not usable: lower-case letters, digits and hyphens, starting with a letter", r.Name)
		}
		if strings.TrimSpace(r.Title) == "" || len(r.Title) > 120 {
			bad("role %q needs a title, at most 120 characters", r.Name)
		}
		if len(r.Summary) > 300 {
			bad("role %q: the summary is at most 300 characters", r.Name)
		}
		switch {
		case len(r.Grants) == 0:
			bad("role %q grants nothing", r.Name)
		case len(r.Grants) > MaxGrants:
			bad("role %q has %d grants; at most %d", r.Name, len(r.Grants), MaxGrants)
		}
		seen := map[Grant]bool{}
		for _, g := range r.Grants {
			kind, name := g.on()
			if kind == "" {
				bad("role %q: each grant names one collection, page or agent", r.Name)
				continue
			}
			if !declared[kind][name] {
				bad("role %q: %s %q is not declared in this package; a role reaches only the feature's own blocks", r.Name, kind, name)
			}
			if _, ok := may[kind][g.May]; !ok {
				bad("role %q: a %s is granted as %s, not %q", r.Name, kind, mayList(kind), g.May)
			}
			if seen[g] {
				bad("role %q grants %s twice", r.Name, g.Text())
			}
			seen[g] = true
		}
	}
}

func mayList(kind string) string {
	switch kind {
	case "collection":
		return "read or write"
	case "page":
		return "read, write or publish"
	}
	return "run or approve"
}
