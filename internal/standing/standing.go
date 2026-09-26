// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package standing relates the authority somebody is given to the
// authority a situation hands them.
//
// # Two kinds of authority, and only one of them was written down
//
// internal/auth is the standing kind: a binding says this principal has
// this role on this resource, an administrator granted it, it is revocable,
// deny wins wherever it sits, and Explain answers why. That model is good
// and this package does not replace any of it.
//
// The other kind arrived later and by accident. A call has a host who can
// eject people. An incident has a commander whose instructions others
// follow. An errand has an owner who is the only person who can confirm it.
// A detection has somebody who promotes it out of shadow. None of those are
// bindings. Nobody granted them, they expire when the situation does, and
// they were each invented inside the package that needed one.
//
// That is not a mistake in itself — a call host is genuinely not a rung on
// a site-wide ladder, and forcing it to be one would produce the
// over-granting internal/auth is built to avoid. The mistake is leaving the
// relationship between the two unstated, because then two things are
// possible and neither is visible:
//
//   - Situational authority exceeding standing authority. Somebody who is
//     a reader everywhere opens a call, becomes its host, and removes
//     people from it. Nothing checked, because the call never asked.
//   - The reverse assumption. An administrator expects to be able to close
//     somebody else's incident and cannot, or can, and nobody decided
//     which.
//
// # The rule that is not obvious
//
// The tempting rule is that every situational role needs a standing role
// above some line. That is wrong, and applying it would break the thing
// that works: the point of a call host is that an ordinary person can run
// a meeting, and requiring an administrator to be present would mean
// meetings are run by whoever has the most access, which is how a
// permission model starts shaping the organisation.
//
// The rule that holds is about reach. A situational power that acts inside
// its own situation needs nothing standing — ejecting somebody from a call
// ends when the call does, and the worst case is a bad meeting. A power
// that reaches outside it is a standing act wearing a situational costume,
// and needs the standing authority for what it actually does. Retiring a
// detection every team's estate depends on is not a property of one
// person's afternoon.
//
// So every situational role declares its powers and, for each, whether it
// reaches outside. A guard checks that the register covers every package
// that has one, because the failure this exists to prevent is a sixth
// model appearing quietly in the seventh package.
package standing

import (
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
)

// Power is one thing a situational role lets somebody do.
type Power struct {
	Name string `json:"name"`
	// Outside says the effect survives the situation.
	//
	// The whole distinction. Inside means the worst case ends when the
	// call, the incident or the shift does. Outside means it does not, and
	// then this is a standing act and needs standing authority for it.
	Outside bool `json:"outside,omitempty"`
	// Needs is the standing action required, and is only meaningful when
	// Outside is set.
	Needs auth.Action `json:"needs,omitempty"`
	// Why explains the classification, because "inside" is a judgement and
	// an unexplained one is a judgement nobody can disagree with.
	Why string `json:"why"`
}

// Validate refuses a power whose classification says nothing.
func (p Power) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("a power needs a name")
	}
	if strings.TrimSpace(p.Why) == "" {
		return fmt.Errorf(
			"%q does not say why it is classified as it is. Whether an "+
				"effect survives its situation is a judgement, and an "+
				"unexplained judgement is one nobody can disagree with",
			p.Name)
	}
	if p.Outside && strings.TrimSpace(string(p.Needs)) == "" {
		return fmt.Errorf(
			"%q reaches outside its situation and names no standing "+
				"action. That is a standing act wearing a situational "+
				"costume, which is the thing this package exists to find",
			p.Name)
	}
	if !p.Outside && strings.TrimSpace(string(p.Needs)) != "" {
		return fmt.Errorf(
			"%q acts inside its situation and also requires standing "+
				"authority. One of those is wrong, and requiring authority "+
				"for something that ends with the meeting is how a call "+
				"comes to be run by whoever has the most access", p.Name)
	}
	return nil
}

// Situational is a role a situation confers rather than an administrator.
type Situational struct {
	// Package is where it lives, and Name what that package calls it.
	Package string `json:"package"`
	Name    string `json:"name"`
	// What it is, in the words somebody unfamiliar would need.
	What string `json:"what"`
	// Held says how somebody comes to have it, which is the part that
	// makes it situational: nobody granted it.
	Held string `json:"held"`
	// Ends says when it stops, because a situational role that never ends
	// is a standing one nobody wrote down.
	Ends   string  `json:"ends"`
	Powers []Power `json:"powers"`
}

// Validate refuses a declaration that is really a standing role.
func (s Situational) Validate() error {
	for _, f := range []struct{ name, v string }{
		{"package", s.Package}, {"name", s.Name}, {"what", s.What},
		{"held", s.Held}, {"ends", s.Ends},
	} {
		if strings.TrimSpace(f.v) == "" {
			return fmt.Errorf("a situational role needs a %s", f.name)
		}
	}
	if len(s.Powers) == 0 {
		return fmt.Errorf(
			"%s/%s confers nothing, so it is a label rather than a role",
			s.Package, s.Name)
	}
	seen := map[string]bool{}
	for _, p := range s.Powers {
		if err := p.Validate(); err != nil {
			return fmt.Errorf("%s/%s: %w", s.Package, s.Name, err)
		}
		if seen[p.Name] {
			return fmt.Errorf("%s/%s lists %q twice", s.Package, s.Name,
				p.Name)
		}
		seen[p.Name] = true
	}
	return nil
}

// Reaches is the powers that survive the situation.
func (s Situational) Reaches() []Power {
	var out []Power
	for _, p := range s.Powers {
		if p.Outside {
			out = append(out, p)
		}
	}
	return out
}

// Contained reports whether everything this confers ends with the
// situation.
//
// The property worth having. A contained role can be handed to anybody the
// situation admits, and the worst case is a bad afternoon.
func (s Situational) Contained() bool { return len(s.Reaches()) == 0 }

// Power finds one by name.
func (s Situational) Power(name string) (Power, bool) {
	for _, p := range s.Powers {
		if strings.EqualFold(p.Name, name) {
			return p, true
		}
	}
	return Power{}, false
}

// Allows reports whether somebody holding a standing role may exercise a
// situational power, and why not.
//
// policy is how the caller's standing authority is checked: a power that
// reaches outside asks it for the named action on the named resource.
// Passing nothing means the caller has no standing authority, which is the
// right default for an anonymous participant.
func Allows(s Situational, power string, principal string,
	policy *auth.Policy, resource string) error {
	p, ok := s.Power(power)
	if !ok {
		return fmt.Errorf("%s/%s confers no power called %q. It confers %s",
			s.Package, s.Name, power, strings.Join(names(s.Powers), ", "))
	}
	if !p.Outside {
		return nil
	}
	if policy == nil {
		return fmt.Errorf(
			"%q reaches outside the %s it came from, and nothing here "+
				"knows what %s may do anywhere else. %s", p.Name, s.Package,
			principal, p.Why)
	}
	d := policy.Evaluate(principal, p.Needs, resource)
	if !d.Allowed {
		return fmt.Errorf(
			"%s is %s of this %s, which does not carry %q outside it. That "+
				"needs %s on %s, and %s. %s",
			principal, s.Name, s.Package, p.Name, p.Needs, resource,
			strings.ToLower(d.Reason), p.Why)
	}
	return nil
}

func names(in []Power) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return out
}
