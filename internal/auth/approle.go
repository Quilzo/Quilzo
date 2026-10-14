// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"
	"sort"
	"strings"
)

// Roles an app declares for the people who work in it.
//
// The four rungs and the jobs are the store's: who may change content, who
// runs security, who answers visitors. An app built on Quilzo has people of
// its own: a lab has technicians who record samples and a manager who
// approves what the lab's agent does; a help desk has agents and team
// leads. What each may do is a fact about the app, so the app says it, in
// the package that makes it, and only over what that package made: its
// collections, its pages and its agents. A business-app platform does the
// same thing: a Dataverse security role, a ServiceNow application role, an
// Odoo group, a Frappe role, an Entra app role.
//
// An app role is still bindings. Assigning one grants exactly the bindings
// it stands for, each marked with the role it came with, so explain says
// which role gave somebody what, and nothing new has to be evaluated: the
// policy holds bindings and only bindings. Declaring a role grants nothing;
// somebody who may grant access assigns it to a person. When the app is
// upgraded the role's holders hold what it grants now, and when the app is
// removed nobody holds it.

// AppRole is a role an app declares, as the bindings it stands for.
type AppRole struct {
	// Name is the app and the role: lab-samples/technician.
	Name    string
	Title   string
	Summary string
	// Grants says what each binding lets somebody do, in words, in the
	// order of Bindings.
	Grants   []string
	Bindings []Binding
}

const viaApp = "app:"

// ViaApp is what a binding granted as an app role is marked with.
func ViaApp(role string) string { return viaApp + role }

// AppRoleOf is the app role a binding was granted as, if it was.
func (b Binding) AppRoleOf() (string, bool) { return strings.CutPrefix(b.Via, viaApp) }

// asText is a reason's mention of what a binding was granted as.
func asText(b *Binding) string {
	if r, ok := b.AppRoleOf(); ok {
		return " as " + r
	}
	return ""
}

// IsAppRoleName reports whether a name is shaped like an app role's:
// APP/ROLE, which no role, permission or job is.
func IsAppRoleName(name string) bool {
	app, role, ok := strings.Cut(name, "/")
	return ok && app != "" && role != "" && !strings.Contains(role, "/")
}

// Assign gives a principal an app role: every binding it stands for, or
// none of them. base carries who granted it, why and until when.
func (p *Policy) Assign(principal string, r AppRole, base Binding) error {
	if strings.TrimSpace(principal) == "" {
		return fmt.Errorf("a binding needs a principal")
	}
	if len(r.Bindings) == 0 {
		return fmt.Errorf("%s grants nothing", r.Name)
	}
	if base.Deny {
		return fmt.Errorf("%s is a role an app declares; it is granted, never denied", r.Name)
	}
	if p.Holds(principal, r.Name) {
		return fmt.Errorf("%s already holds %s", principal, r.Name)
	}
	for _, b := range expandFor(principal, r, base) {
		if err := p.Grant(b); err != nil {
			p.RevokeAppRole(principal, r.Name)
			return err
		}
	}
	return nil
}

func expandFor(principal string, r AppRole, base Binding) []Binding {
	out := make([]Binding, 0, len(r.Bindings))
	for _, rb := range r.Bindings {
		b := base
		b.Principal, b.Role, b.Permission, b.Resource = principal, rb.Role, rb.Permission, rb.Resource
		b.Deny, b.OwnOnly, b.Via = false, false, ViaApp(r.Name)
		out = append(out, b)
	}
	return out
}

// Holds reports whether a principal holds an app role.
func (p *Policy) Holds(principal, role string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, b := range p.Bindings {
		if b.Principal == principal && b.Via == ViaApp(role) {
			return true
		}
	}
	return false
}

// RevokeAppRole takes an app role from a principal, and reports how many
// bindings went.
func (p *Policy) RevokeAppRole(principal, role string) int {
	return p.dropWhere(func(b Binding) bool { return b.Principal == principal && b.Via == ViaApp(role) })
}

func (p *Policy) dropWhere(match func(Binding) bool) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	kept := p.Bindings[:0]
	removed := 0
	for _, b := range p.Bindings {
		if match(b) {
			removed++
			continue
		}
		kept = append(kept, b)
	}
	p.Bindings = kept
	return removed
}

// Reassign makes everybody who holds an app role hold what it grants now,
// keeping who granted it to them, when and why, and when it ends. With r
// nil the role is gone and nobody holds it. It reports who held it.
func (p *Policy) Reassign(name string, r *AppRole) []string {
	p.mu.RLock()
	held := map[string]Binding{}
	for _, b := range p.Bindings {
		if b.Via == ViaApp(name) {
			if _, ok := held[b.Principal]; !ok {
				held[b.Principal] = b
			}
		}
	}
	p.mu.RUnlock()
	p.dropWhere(func(b Binding) bool { return b.Via == ViaApp(name) })
	who := make([]string, 0, len(held))
	for principal, base := range held {
		who = append(who, principal)
		if r == nil {
			continue
		}
		for _, b := range expandFor(principal, *r, base) {
			_ = p.Grant(b)
		}
	}
	sort.Strings(who)
	return who
}
