// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"fmt"
	"sort"
	"strings"
)

// Delta is what an amendment to a declaration changed, in reach: the
// things the agent may now do that it may not before.
//
// The idea is OpenShell's — its policy changes are diffed and a risky one
// is held for a person to look at — done with what this program already
// holds: two manifests, subtracted. What it catches is the amendment that
// reads as a review of the same agent and is a widening: a capability
// nobody granted, a host nobody approved, a program nobody named, one
// more step of autonomy. The exact list is computed, not summarised,
// because "added: 3 things" is a number a tired reader waves through and
// "may now send to payments.example.com" is not.
type Delta struct {
	// Added is each widening, one line each, in words a person reads.
	Added []string
	// Widens is true when any of them widens what the agent may do.
	Widens bool
}

// DeltaOf is what amending old into new changes. Narrowing is listed too —
// a reader of the log deserves to see a declaration shrink as plainly as
// grow — but only the growth is a gate.
func DeltaOf(old, new Manifest) Delta {
	var d Delta
	add := func(line string) {
		d.Added = append(d.Added, line)
		d.Widens = true
	}

	// Capabilities, by name, sorted so the diff is stable.
	names := func(caps []string) map[string]bool {
		m := map[string]bool{}
		for _, c := range caps {
			m[c] = true
		}
		return m
	}
	oc, nc := names(old.Capabilities), names(new.Capabilities)
	var gained []string
	for c := range nc {
		if !oc[c] {
			gained = append(gained, c)
		}
	}
	sort.Strings(gained)
	for _, c := range gained {
		add("may now " + c)
	}

	// Autonomy: up is a widening, whatever else moved. Up means the new
	// level is not within the old one.
	if !new.Autonomy.AtMost(old.Autonomy) {
		add("autonomy raised from " + string(old.Autonomy) + " to " + string(new.Autonomy))
	}

	// The browser's reach: hosts, by name.
	if old.Browser != nil || new.Browser != nil {
		ob, nb := old.Browser, new.Browser
		if ob == nil {
			ob = &Browser{}
		}
		if nb == nil {
			nb = &Browser{}
		}
		for _, h := range hostsGained(ob.Read, nb.Read) {
			add("may now read " + h)
		}
		for _, h := range hostsGained(ob.Write, nb.Write) {
			add("may now act on " + h)
		}
		if nb.Pictures && !ob.Pictures {
			add("may now be shown pictures of the page")
		}
	}

	// The workspace's reach: programs, hosts, and what stopped asking.
	if old.Shell != nil || new.Shell != nil {
		os_, ns := old.Shell, new.Shell
		if os_ == nil {
			os_ = &Shell{}
		}
		if ns == nil {
			ns = &Shell{}
		}
		for _, p := range hostsGained(os_.Programs, ns.Programs) {
			add("may now run " + p)
		}
		for _, h := range hostsGained(os_.Hosts, ns.Hosts) {
			add("commands may now reach " + h)
		}
		for _, k := range []string{"network", "write"} {
			if asks(os_, k) && !asks(ns, k) {
				add("stopped asking a person before a command that " + k + "s")
			}
		}
	}

	// Delegates: another agent's hands, newly available.
	od := map[string]bool{}
	for _, n := range old.Delegates {
		od[n] = true
	}
	var dgained []string
	for _, n := range new.Delegates {
		if !od[n] {
			dgained = append(dgained, n)
		}
	}
	sort.Strings(dgained)
	for _, n := range dgained {
		add("may now hand work to " + n)
	}

	// The budget: more of anything is a widening, because a budget is the
	// thing a loop spends.
	if new.Budget.Steps > old.Budget.Steps {
		add(fmt.Sprintf("step budget raised from %d to %d", old.Budget.Steps, new.Budget.Steps))
	}
	if new.Budget.Tools > old.Budget.Tools {
		add(fmt.Sprintf("tool budget raised from %d to %d", old.Budget.Tools, new.Budget.Tools))
	}
	if new.Budget.Duration > old.Budget.Duration {
		add(fmt.Sprintf("time budget raised from %s to %s", old.Budget.Duration, new.Budget.Duration))
	}
	return d
}

func hostsGained(oldList, newList []string) []string {
	had := map[string]bool{}
	for _, h := range oldList {
		had[h] = true
	}
	var gained []string
	for _, h := range newList {
		if !had[h] {
			gained = append(gained, h)
		}
	}
	sort.Strings(gained)
	return gained
}

func asks(s *Shell, kind string) bool {
	for _, k := range s.Ask {
		if k == kind {
			return true
		}
	}
	return false
}

// Lines is the delta as one block of prose, for a record or a refusal.
func (d Delta) Lines() string {
	return strings.Join(d.Added, "; ")
}
