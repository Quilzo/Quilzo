// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Who answers for an agent, and until when it may run.
//
// An agent is a principal of its own, agent/NAME: what it writes is
// authored by that name, the audit log records it as the actor, and the
// access policy can grant it a role like anybody else, which then bounds
// every run of it whoever starts it. But an agent cannot be accountable,
// so each has a sponsor: the person who answers for it, who is asked when
// it misbehaves, and without whom it does not run. When the sponsor leaves
// (their access ends, or the identity provider suspends them) the agent
// stops with them, rather than carrying on as an orphan nobody watches.
//
// And it ends. An identity lasts ninety days unless somebody says
// otherwise, a year at most, and an agent past its end does not run until
// somebody renews it. Most agents nobody looks after are agents nobody
// needs; the renewal is when somebody decides which.

// Identity is an agent's standing as a principal.
type Identity struct {
	// Sponsor is the person who answers for the agent.
	Sponsor string    `json:"sponsor"`
	Expires time.Time `json:"expires"`
	// Created and Renewed say when, and by whom.
	Created   time.Time `json:"created"`
	CreatedBy string    `json:"created_by"`
	Renewed   time.Time `json:"renewed,omitzero"`
	RenewedBy string    `json:"renewed_by,omitempty"`
}

// The lifetimes.
const (
	DefaultLifetime = 90 * 24 * time.Hour
	MaxLifetime     = 365 * 24 * time.Hour
)

// PrincipalPrefix begins every agent's principal name.
const PrincipalPrefix = "agent/"

// Principal is an agent's principal name in the access policy and the log.
func Principal(name string) string { return PrincipalPrefix + name }

// NewIdentity is an identity starting now, for a lifetime: zero means the
// default.
func NewIdentity(sponsor, by string, lifetime time.Duration, now time.Time) (Identity, error) {
	if lifetime == 0 {
		lifetime = DefaultLifetime
	}
	id := Identity{Sponsor: strings.TrimSpace(sponsor), Expires: now.Add(lifetime), Created: now, CreatedBy: by}
	return id, id.Validate(now)
}

// Validate checks an identity can stand.
func (id Identity) Validate(now time.Time) error {
	if id.Sponsor == "" {
		return errors.New("an agent needs a sponsor: the person who answers for it")
	}
	if strings.HasPrefix(id.Sponsor, PrincipalPrefix) {
		return errors.New("an agent is sponsored by a person, not by another agent")
	}
	if strings.ContainsAny(id.Sponsor, " \t\r\n") || len(id.Sponsor) > 254 {
		return fmt.Errorf("%q is not a principal", id.Sponsor)
	}
	if !id.Expires.After(now) {
		return errors.New("an agent's identity ends in the future")
	}
	start := id.Created
	if !id.Renewed.IsZero() {
		start = id.Renewed
	}
	if id.Expires.Sub(start) > MaxLifetime+time.Minute {
		return fmt.Errorf("an agent's identity lasts at most %d days before somebody renews it", int(MaxLifetime.Hours()/24))
	}
	return nil
}

// Renew extends an identity from now.
func (id Identity) Renew(by string, lifetime time.Duration, now time.Time) (Identity, error) {
	if lifetime == 0 {
		lifetime = DefaultLifetime
	}
	id.Renewed, id.RenewedBy, id.Expires = now, by, now.Add(lifetime)
	return id, id.Validate(now)
}

// Expired reports whether it has run out.
func (id Identity) Expired(now time.Time) bool { return !now.Before(id.Expires) }

// ErrNoSponsor is an agent nobody answers for.
var ErrNoSponsor = errors.New("nobody answers for this agent")

// MayRun says whether an agent with this identity may run now, given
// whether its sponsor can still act here. A missing identity is an agent
// declared before identities existed: it runs, and the posture check says
// it needs a sponsor.
func (id *Identity) MayRun(sponsorActive bool, now time.Time) error {
	if id == nil {
		return nil
	}
	if id.Sponsor == "" {
		return ErrNoSponsor
	}
	if id.Expired(now) {
		return fmt.Errorf("its identity ended on %s; its sponsor, %s, or an administrator renews it (quilzo agent renew)",
			id.Expires.UTC().Format("2 January 2006"), id.Sponsor)
	}
	if !sponsorActive {
		return fmt.Errorf("its sponsor, %s, can no longer act here, so it does not run until somebody else answers for it (quilzo agent sponsor)", id.Sponsor)
	}
	return nil
}
