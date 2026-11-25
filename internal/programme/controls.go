// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

import (
	"fmt"

	"github.com/quilzo/quilzo/internal/register"
)

// Controls, and what they are mapped to.
//
// A control is what the organisation does; a mapping says how it relates
// to a requirement, in one of NIST IR 8477's five relationships, with why.
// A mapping without a relation would be a line drawn between two boxes, and
// the register refuses one: the relation is what says whether passing the
// control is all of the requirement or part of it.

// AddControl writes a control.
func (p *Programme) AddControl(by register.Actor, c register.Control) (register.ID, register.Receipt, error) {
	id, err := register.IDOf(c)
	if err != nil {
		return "", register.Receipt{}, err
	}
	rc, err := p.Reg.Put(by, "the control "+c.Ref, c)
	return id, rc, err
}

// MapControl writes how a control relates to a requirement, and why. The
// words of why are kept beside the store and the mapping holds their
// digest.
func (p *Programme) MapControl(by register.Actor, control, framework, ref string, rel register.Relation, why string) (register.ID, register.Receipt, error) {
	v, err := p.Reg.At("")
	if err != nil {
		return "", register.Receipt{}, err
	}
	cid, err := named(v, register.KindControl, register.Local, control)
	if err != nil {
		return "", register.Receipt{}, err
	}
	rid, err := register.DeriveID(register.KindRequirement, framework, ref)
	if err != nil || !has(v, rid) {
		return "", register.Receipt{}, fmt.Errorf("%w: the programme holds no requirement %s of %s", register.ErrNotFound,
			clip(ref), clip(framework))
	}
	text, err := p.Keep.Keep(why)
	if err != nil {
		return "", register.Receipt{}, fmt.Errorf("%w: %v", register.ErrInvalid, err)
	}
	m := register.Mapping{From: cid, To: rid, Relation: rel, Rationale: text}
	id, err := register.IDOf(m)
	if err != nil {
		return "", register.Receipt{}, err
	}
	rc, err := p.Reg.Put(by, fmt.Sprintf("the control %s mapped to %s %s", control, framework, ref), m)
	return id, rc, err
}
