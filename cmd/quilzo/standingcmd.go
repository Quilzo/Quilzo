// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"

	"github.com/quilzo/quilzo/internal/standing"
)

// The authority a situation hands somebody, against the authority they
// were given.
//
// internal/auth is the standing kind: a binding, an administrator granted
// it, it is revocable, deny wins wherever it sits. The other kind arrived
// later and by accident — a call has a host who can eject people, an
// incident has a commander, an errand has an owner who is the only person
// who can confirm it. Nobody granted those and they expire when the
// situation does.
//
// That is not wrong. A call host is genuinely not a rung on a site-wide
// ladder, and making it one would produce exactly the over-granting
// internal/auth exists to avoid. What was missing is the relationship, and
// the rule is about reach: a power that acts inside its situation needs
// nothing standing, and one that survives it is a standing act wearing a
// situational costume.

func cmdStanding(args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return standingList()
	default:
		return fmt.Errorf("unknown standing command %q; try list", args[0])
	}
}

func standingList() error {
	if err := standing.Check(); err != nil {
		return err
	}
	all := standing.Register()
	shape := standing.Look()
	if w.JSON(map[string]any{
		"roles": all, "shape": shape,
		"escalations": standing.Escalations(),
	}) {
		return nil
	}

	w.Human("%swhat a situation can hand somebody%s\n\n", bold, reset)
	for _, s := range all {
		mark, colour := "contained", green
		if !s.Contained() {
			mark, colour = "reaches outside", yellow
		}
		w.Human("  %s%s/%s%s %s(%s)%s\n", bold, s.Package, s.Name, reset,
			colour, mark, reset)
		w.Human("    %s%s · held: %s · ends: %s%s\n", dim, s.What, s.Held,
			s.Ends, reset)
		for _, p := range s.Powers {
			if p.Outside {
				w.Human("    %s%-18s%s %sneeds %s — %s%s\n", yellow,
					p.Name, reset, dim, p.Needs,
					wrapAt(p.Why, 52, "                       "), reset)
				continue
			}
			w.Human("    %s%-18s%s %s%s%s\n", dim, p.Name, reset, dim,
				wrapAt(p.Why, 52, "                       "), reset)
		}
		w.Human("\n")
	}

	w.Human("  %s%s%s\n\n", bold, wrapAt(shape.Why(), 66, "  "), reset)
	w.Human("  %sthe tempting rule is that every situational role needs a\n"+
		"  standing one above some line. That is wrong, and applying it\n"+
		"  would break the thing that works: the point of a call host is\n"+
		"  that an ordinary person can run a meeting, and requiring an\n"+
		"  administrator would mean meetings are run by whoever has the\n"+
		"  most access — a permission model shaping the organisation%s\n",
		dim, reset)
	return nil
}
