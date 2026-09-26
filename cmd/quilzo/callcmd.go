// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/groupkey"
	"github.com/quilzo/quilzo/internal/sframe"
)

// Where the media encryption key comes from.
//
// internal/sframe encrypts frames so a forwarding unit cannot read them and
// says plainly that it has nothing to say about where the key came from.
// That is the honest position for a codec and a bad one for a product:
// without key agreement, "end-to-end encrypted" is a claim about an
// algorithm rather than about a call. internal/groupkey is the missing
// half, and this command runs it.
//
// `call demo` builds a real call — separate identities, real commits, each
// member's view computed from the protocol rather than copied — then adds
// somebody, removes somebody, and shows what each member can and cannot
// derive at each step.

func cmdCall(args []string) error {
	if len(args) == 0 {
		args = []string{"demo"}
	}
	switch args[0] {
	case "demo":
		return callDemo(args[1:])
	case "cost":
		return callCost(args[1:])
	default:
		return fmt.Errorf("unknown call command %q; try demo or cost",
			args[0])
	}
}

// party is one participant, kept as the pair the protocol actually needs:
// private keys, and that member's own view of the group.
type party struct {
	id   *groupkey.Identity
	view *groupkey.Group
}

func start(names []string) ([]*party, error) {
	first, err := groupkey.NewIdentity(names[0])
	if err != nil {
		return nil, err
	}
	g, err := groupkey.Create("standup", first)
	if err != nil {
		return nil, err
	}
	people := []*party{{id: first, view: g}}
	for _, n := range names[1:] {
		if err := invite(&people, n); err != nil {
			return nil, err
		}
	}
	return people, nil
}

// invite runs a real join: a commit to everybody already there, and a
// welcome to the new arrival, who builds their view from it.
func invite(people *[]*party, name string) error {
	joiner, err := groupkey.NewIdentity(name)
	if err != nil {
		return err
	}
	host := (*people)[0]
	interim := host.view.Interim()
	c, ws, err := host.view.Commit(host.id,
		[]groupkey.Change{{Kind: groupkey.Add, Member: joiner.Member(0)}})
	if err != nil {
		return err
	}
	for _, p := range *people {
		if err := p.view.Apply(c, p.id); err != nil {
			return fmt.Errorf("%s could not apply the commit: %w",
				p.id.Name, err)
		}
	}
	g, err := groupkey.Join(ws[0], interim, joiner)
	if err != nil {
		return err
	}
	*people = append(*people, &party{id: joiner, view: g})
	return nil
}

func callDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	suiteID := fs.Int("suite", int(sframe.AES128GCMSHA256128),
		"which SFrame cipher suite the media goes out under")
	if err := fs.Parse(args); err != nil {
		return err
	}
	suite := sframe.Suite(*suiteID)
	if !suite.Known() {
		return fmt.Errorf("%d is not a registered cipher suite", *suiteID)
	}

	people, err := start([]string{"ada", "grace", "alan"})
	if err != nil {
		return err
	}

	w.Human("%s%s%s\n", bold, groupkey.SuiteName, reset)
	w.Human("  %severy commit is encapsulated under ML-KEM-768 and X25519 "+
		"together,\n  so it holds if either one holds%s\n\n", dim, reset)

	if err := showEpoch(people, suite, "three people in a call"); err != nil {
		return err
	}

	if err := invite(&people, "katherine"); err != nil {
		return err
	}
	if err := showEpoch(people, suite, "katherine joins"); err != nil {
		return err
	}

	// Somebody leaves. Their view is kept so it can be asked what it can
	// still derive, which is the whole point of forward secrecy.
	left := people[1]
	host := people[0]
	c, _, err := host.view.Commit(host.id,
		[]groupkey.Change{{Kind: groupkey.Remove, Index: left.view.Me()}})
	if err != nil {
		return err
	}
	staying := []*party{}
	for _, p := range people {
		if p == left {
			continue
		}
		if err := p.view.Apply(c, p.id); err != nil {
			return err
		}
		staying = append(staying, p)
	}
	w.Human("  %s%s tries to follow the call they were removed from%s\n",
		dim, left.id.Name, reset)
	if err := left.view.Apply(c, left.id); err != nil {
		w.Human("    %srefused%s %s\n", green, reset, firstLine(err))
		w.Human("    %stheir view stays at epoch %d while the call is at "+
			"%d, and the\n    secret for %d was never encapsulated to "+
			"them%s\n\n", dim, left.view.Epoch, host.view.Epoch,
			host.view.Epoch, reset)
	} else {
		return fmt.Errorf("a removed member applied the commit that " +
			"removed them, which would be a bug worth stopping for")
	}
	if err := showEpoch(staying, suite, "grace is removed"); err != nil {
		return err
	}

	w.Human("  %sthe authenticator is the part a machine cannot finish. Two "+
		"people\n  who compare it somewhere the call is not have established "+
		"that they\n  are in the same call with the same roster — which "+
		"holds even if the\n  signing keys they checked each other with were "+
		"stolen%s\n", dim, reset)
	return nil
}

// showEpoch prints what every member derived, and checks they match.
func showEpoch(people []*party, suite sframe.Suite, what string) error {
	head := people[0].view
	w.Human("%s%s%s\n", bold, what, reset)
	w.Human("  %sepoch %d · %d in the call · %s%s\n", dim, head.Epoch,
		head.Size(), head.Authenticator(), reset)

	base, err := head.BaseKey(suite)
	if err != nil {
		return err
	}
	for _, p := range people {
		if a := p.view.Authenticator(); a != head.Authenticator() {
			return fmt.Errorf("%s computed %s and %s computed %s; they are "+
				"not in the same call", p.id.Name, a, people[0].id.Name,
				head.Authenticator())
		}
		got, err := p.view.BaseKey(suite)
		if err != nil {
			return err
		}
		if string(got) != string(base) {
			return fmt.Errorf("%s derived a different base key", p.id.Name)
		}
		k, err := p.view.SenderKey(suite, 0)
		if err != nil {
			return err
		}
		w.Human("    %-10s %sindex %d · KID %#x · salt %x…%s\n", p.id.Name,
			dim, p.view.Me(), k.KID, k.Salt[:4], reset)
	}
	w.Human("\n")
	return nil
}

func firstLine(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func callCost(args []string) error {
	fs := flag.NewFlagSet("cost", flag.ContinueOnError)
	upto := fs.Int("members", 100, "the largest call to measure")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *upto < 2 || *upto > 256 {
		return fmt.Errorf("measure between 2 and 256; past that this is a " +
			"broadcast and wants a different design")
	}

	sizes := []int{2, 5, 10, 20, 50, 100, 250}
	var rows []map[string]any
	w.Human("%swhat a membership change costs%s\n", bold, reset)
	w.Human("  %sa fresh secret, encapsulated to every member, once, when "+
		"somebody\n  joins or leaves — not per frame%s\n\n", dim, reset)
	w.Human("  %s%-8s %10s %10s %10s%s\n", dim, "in call", "flat", "a tree",
		"per member", reset)

	people, err := start([]string{"ada"})
	if err != nil {
		return err
	}
	at := 1
	for _, n := range sizes {
		if n > *upto {
			break
		}
		for at < n {
			if err := invite(&people, fmt.Sprintf("m%d", at)); err != nil {
				return err
			}
			at++
		}
		host := people[0]
		c, _, err := host.view.Commit(host.id, nil)
		if err != nil {
			return err
		}
		if err := applyAll(people, c); err != nil {
			return err
		}
		cost := c.Cost()
		rows = append(rows, map[string]any{
			"members": cost.Members, "bytes": cost.Bytes,
			"tree_bytes": cost.Tree(), "per_member": cost.PerMember,
		})
		w.Human("  %-8d %9s %10s %10s\n", cost.Members, kb(cost.Bytes),
			kb(cost.Tree()), kb(cost.PerMember))
	}
	if w.JSON(map[string]any{
		"suite": groupkey.SuiteName, "rows": rows,
	}) {
		return nil
	}
	w.Human("\n  %sthe tree column is what MLS's ratchet tree would make "+
		"this, and it\n  is a real saving on a cost that is already about "+
		"one key frame of the\n  screen codec. What it buys it with is tree "+
		"hashes, parent hashes,\n  blank nodes and the resolution algorithm "+
		"— the part of MLS where\n  implementation bugs actually live. A "+
		"call is not a group of fifty\n  thousand, so this does not have "+
		"one; the numbers are printed so that\n  stays a decision rather "+
		"than an assumption%s\n", dim, reset)
	return nil
}

func applyAll(people []*party, c *groupkey.Commit) error {
	for _, p := range people {
		if err := p.view.Apply(c, p.id); err != nil {
			return fmt.Errorf("%s: %w", p.id.Name, err)
		}
	}
	return nil
}

func kb(n int) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f KB", float64(n)/1024)
}
