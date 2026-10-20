// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import "github.com/quilzo/quilzo/internal/auth"

// Actor is who a hook acts for: the person, and the limits of the
// credential their session was made from.
//
// The hooks that decide something on the command line's side (approving
// what an agent waits for, installing a feature, running an agent) used to
// be handed the person's name and nothing else, and the host rebuilt a
// caller with an administrator's role and no limits from it. So a session
// exchanged from a read-only token, or one capped at reader or confined to
// /blog, could approve a held payment or a publish whenever the person held
// that right somewhere: the limits that make a narrow credential narrow
// stopped at the edge of this package. Handing the limits across with the
// name is what lets the other side check the session, not the person.
type Actor struct {
	Name   string
	Role   auth.Role
	Scope  string
	Limits auth.Scope
}

// actor is the session as a hook should see it.
func (p principal) actor() Actor {
	return Actor{Name: p.Name, Role: p.Role, Scope: p.Scope, Limits: p.Limits}
}
