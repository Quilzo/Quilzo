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
		oldShell, newShell := old.Shell, new.Shell
		if oldShell == nil {
			oldShell = &Shell{}
		}
		if newShell == nil {
			newShell = &Shell{}
		}
		for _, p := range hostsGained(oldShell.Programs, newShell.Programs) {
			add("may now run " + p)
		}
		for _, h := range hostsGained(oldShell.Hosts, newShell.Hosts) {
			add("commands may now reach " + h)
		}
		for _, k := range []string{"network", "write"} {
			if asks(oldShell, k) && !asks(newShell, k) {
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
	// Zero tokens and no money leave only the gateway's shared budgets, so
	// dropping a cap is the largest raise of all.
	if raised(int64(old.Budget.Tokens), int64(new.Budget.Tokens)) {
		add(fmt.Sprintf("token budget raised from %s to %s", capWord(int64(old.Budget.Tokens), old.Budget.Tokens), capWord(int64(new.Budget.Tokens), new.Budget.Tokens)))
	}
	om, oerr := old.Budget.MoneyMicros()
	nm, nerr := new.Budget.MoneyMicros()
	if oerr == nil && nerr == nil && raised(om, nm) {
		add(fmt.Sprintf("money budget raised from %s to %s", capWord(om, old.Budget.Money), capWord(nm, new.Budget.Money)))
	}

	// What stopped waiting for a person.
	held := map[string]bool{}
	for _, c := range new.Capabilities {
		held[c] = true
	}
	for _, t := range new.Tools {
		held[t.Name] = true
	}
	stillAsks := map[string]bool{}
	for _, c := range new.AskFirst {
		stillAsks[c] = true
	}
	var unasked []string
	for _, c := range old.AskFirst {
		if held[c] && !stillAsks[c] {
			unasked = append(unasked, c)
		}
	}
	sort.Strings(unasked)
	for _, c := range unasked {
		add("stopped asking a person before " + c)
	}
	if old.HumanApproval && !new.HumanApproval {
		add("what it does no longer waits for a person's approval to become public")
	}

	// Tools: a new one, a new host for one, or one that now writes.
	oldTools := map[string]Tool{}
	for _, t := range old.Tools {
		oldTools[t.Name] = t
	}
	for _, t := range sortedTools(new.Tools) {
		was, had := oldTools[t.Name]
		switch {
		case !had:
			add("may now call " + t.Name + " at " + t.Host)
		case was.Host != t.Host:
			add(t.Name + " now reaches " + t.Host + " instead of " + was.Host)
		}
		if t.Writes && (!had || !was.Writes) {
			add(t.Name + " may now change things at " + t.Host)
		}
		if t.Secret != "" && (!had || was.Secret != t.Secret) {
			add(t.Name + " may now use the secret " + t.Secret)
		}
	}

	// Signing in with a sealed secret, and pictures of a desktop.
	var oc2, nc2 []string
	if old.Browser != nil {
		for _, c := range old.Browser.Credentials {
			oc2 = append(oc2, c.Secret+" on "+c.Host)
		}
	}
	if new.Browser != nil {
		for _, c := range new.Browser.Credentials {
			nc2 = append(nc2, c.Secret+" on "+c.Host)
		}
	}
	for _, c := range hostsGained(oc2, nc2) {
		add("may now sign in with " + c)
	}
	if new.Cell != nil && new.Cell.Pictures && (old.Cell == nil || !old.Cell.Pictures) {
		add("may now be shown pictures of the desktop")
	}

	// What it reads: each list narrows, and an empty one does not.
	or, nr := old.Retrieval, new.Retrieval
	if nr.Ref != or.Ref {
		add(fmt.Sprintf("now reads %s rather than %s", refWord(nr.Ref), refWord(or.Ref)))
	}
	for _, w := range listWidens("content types", or.Types, nr.Types) {
		add(w)
	}
	for _, w := range listWidens("languages", or.Locales, nr.Locales) {
		add(w)
	}
	if or.Path != nr.Path && !within(or.Path, nr.Path) {
		add(fmt.Sprintf("may now read %s rather than only %s", pathWord(nr.Path), pathWord(or.Path)))
	}
	if nr.KeepInstructions && !or.KeepInstructions {
		add("is now shown sentences addressed to an AI in what it reads")
	}

	// What it remembers.
	for _, tier := range []struct {
		name     string
		was, now bool
	}{{"what happened (episodic)", old.Memory.Episodic, new.Memory.Episodic},
		{"what it concluded (semantic)", old.Memory.Semantic, new.Memory.Semantic},
		{"procedures (procedural)", old.Memory.Procedural, new.Memory.Procedural}} {
		if tier.now && !tier.was {
			add("now remembers " + tier.name)
		}
	}
	if new.Memory.Any() && new.Memory.Retain > old.Memory.Retain {
		add(fmt.Sprintf("keeps what it remembers for %s rather than %s", new.Memory.Retain, old.Memory.Retain))
	}

	// Its own program: another command, another image, more to read or
	// to carry in its environment.
	if old.Program != nil || new.Program != nil {
		op, np := old.Program, new.Program
		if op == nil {
			op = &Program{}
		}
		if np == nil {
			np = &Program{}
		}
		if strings.Join(np.Command, "\x00") != strings.Join(op.Command, "\x00") && len(np.Command) > 0 {
			add("now runs " + strings.Join(np.Command, " "))
		}
		if np.Image != op.Image && np.Image != "" {
			add("its program now runs in " + np.Image)
		}
		for _, r := range hostsGained(op.Read, np.Read) {
			add("its program may now read " + r)
		}
		var oenv, nenv []string
		for k, v := range op.Env {
			oenv = append(oenv, k+"="+v)
		}
		for k, v := range np.Env {
			nenv = append(nenv, k+"="+v)
		}
		for _, e := range hostsGained(oenv, nenv) {
			k, _, _ := strings.Cut(e, "=")
			add("its program's environment now sets " + k)
		}
		if np.MemoryMB > op.MemoryMB || np.CPUSeconds > op.CPUSeconds {
			add("its program may use more memory or CPU time")
		}
	}

	// The workspace: another folder, or more room in it.
	if old.Shell != nil && new.Shell != nil {
		if new.Shell.Workspace != old.Shell.Workspace {
			add(fmt.Sprintf("its workspace is now %q rather than %q", new.Shell.Workspace, old.Shell.Workspace))
		}
		if new.Shell.Timeout > old.Shell.Timeout || new.Shell.MemoryMB > old.Shell.MemoryMB || new.Shell.QuotaMB > old.Shell.QuotaMB {
			add("its commands may run longer, or use more memory or disc")
		}
	}

	// A kind is a label except the supervisor's, and a label that changes
	// changes what a reader thinks they approved.
	if new.Kind != old.Kind {
		add(fmt.Sprintf("is now of kind %s rather than %s", new.Kind, old.Kind))
	}
	return d
}

// raised says whether a cap went up, zero being no cap at all.
func raised(old, new int64) bool {
	if old == 0 {
		return false
	}
	return new == 0 || new > old
}

func capWord(n int64, s any) string {
	if n == 0 {
		return "no cap"
	}
	return fmt.Sprint(s)
}

func sortedTools(ts []Tool) []Tool {
	out := append([]Tool(nil), ts...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func refWord(ref string) string {
	if ref == "" {
		return "the live site"
	}
	return "ref " + ref
}

func pathWord(p string) string {
	if p == "" {
		return "everything"
	}
	return p
}

// listWidens names what a restricting list now admits that it did not.
func listWidens(what string, old, new []string) []string {
	if len(old) == 0 {
		return nil
	}
	if len(new) == 0 {
		return []string{"may now read all " + what + ", not only " + strings.Join(old, ", ")}
	}
	var out []string
	for _, x := range hostsGained(old, new) {
		out = append(out, "may now read "+what+" "+x)
	}
	return out
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
