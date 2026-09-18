// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Bounding an agent by whoever started it.
//
// # The hole this closes
//
// A manifest is a declaration of what an agent may do, stored under its own
// hash and validated before it runs. What it was not, until now, is a
// declaration relative to anybody: `agent run` built its session from the
// stored manifest alone, so the agent's authority was whatever the manifest
// said regardless of who invoked it.
//
// Declaring a manifest needs the `grant` action, which is the strongest
// action this program has, so the hole is not that a stranger writes one. It
// is that a token deliberately narrowed afterwards — read-only, or scoped to
// two content types — stopped mattering the moment its holder ran an agent.
// `quilzo agent run` needs `edit-draft`, and a read-only publisher's token
// holds `edit-draft` as a role while being refused every write; run an agent
// with it and the agent wrote what the token could not.
//
// That is the shape of a confused deputy, and the narrowing that prevents it
// was already written. Manifest.Narrow implements parent-bounds-child for
// delegation, is tested, and was called from nowhere but its own tests. This
// file gives it its first caller: the parent is the person.
//
// # Why the caller becomes a manifest
//
// Rather than teaching the session about roles and scopes, which would be a
// second authorisation model beside internal/auth and would drift from it.
// A Caller is expressed as the manifest it would be if it were an agent, and
// then the two are combined by the one function that knows how to do that. A
// change to the narrowing algebra therefore applies to both uses at once,
// which is the property that made the delegation version worth having.
func narrowedBy(m agent.Manifest, c *Caller) agent.Manifest {
	return boundOf(m, c).Narrow(m)
}

// boundOf expresses a caller's authority as a manifest bounding one agent.
//
// It takes the manifest because Narrow intersects capability lists literally:
// an empty list on the bounding side intersects to nothing, so there is no
// "restricts no capability" value to pass. An earlier version of this
// function passed nil for exactly that reason, believing empty meant all, and
// gave every caller an agent that could do nothing — which every test would
// have passed, because an agent that refuses everything refuses correctly.
// TestAnUnscopedTokenLeavesTheManifestAlone is what caught it.
//
// So the capability bound is the manifest's own list, minus the writes when
// this caller cannot write. A role is not a set of operation names, and the
// honest statement of what a role bounds is "how far", not "which".
func boundOf(m agent.Manifest, c *Caller) agent.Manifest {
	if c == nil {
		// No caller resolved. Refusing everything rather than permitting
		// everything: an unresolved caller is the case where the safe default
		// matters most, and a nil here would otherwise mean "unrestricted".
		return agent.Manifest{Autonomy: agent.AutonomyPropose,
			Retrieval: agent.Retrieval{Ref: site.RefLive}}
	}
	autonomy := autonomyFor(c)
	if c.Limits.ReadOnly {
		autonomy = agent.AutonomyPropose
	}

	b := agent.Manifest{
		Capabilities: mayCall(m.Capabilities, autonomy),
		Autonomy:     autonomy,
		Retrieval: agent.Retrieval{
			// A caller narrowed to content types or locales narrows what the
			// agent may retrieve, in the same terms: auth.Scope and
			// agent.Retrieval already use content type names and language
			// tags, so this is the same vocabulary and not a translation.
			Types:   c.Limits.Types,
			Locales: c.Limits.Locales,
		},
		// Unbounded here. A budget belongs to the agent and a token does not
		// carry one; capping it by the caller would mean inventing a number.
		Budget: agent.Budget{
			Steps: maxBudget, Tools: maxBudget,
			Duration: agent.Duration(1 << 62),
		},
		// Memory is the agent's, and a token says nothing about it.
		Memory: agent.Memory{
			Episodic: true, Semantic: true, Procedural: true,
			Retain: agent.Duration(1 << 62),
		},
	}
	// A read-only token reads what is published, whatever the manifest says.
	// The autonomy half of this is above, because the capability bound is
	// derived from it. This is the case the Caller comment describes as having
	// been dropped on the floor once already.
	if c.Limits.ReadOnly {
		b.Retrieval.Ref = site.RefLive
	}
	return b
}

// mayCall keeps the capabilities an agent at this autonomy could use.
//
// Stripping the writes rather than relying on Session.check to refuse them
// later. Both would be correct and this one is clearer: an agent that holds
// write_page and is refused every time it tries looks broken in a trace,
// while one that never held it reads as what it is.
//
// agent.IsWrite is the classifier, not a prefix test, so an operation added
// to the write set there is covered here without anybody remembering.
func mayCall(declared []string, a agent.Autonomy) []string {
	if !a.AtMost(agent.AutonomyPropose) {
		return declared
	}
	out := make([]string, 0, len(declared))
	for _, c := range declared {
		if !agent.IsWrite(c) {
			out = append(out, c)
		}
	}
	return out
}

// autonomyFor is the most an agent may do on this caller's behalf.
//
// Mapped from the role rather than from the action the command needed,
// because the command needed one action and a run takes many. A reader's
// token cannot produce a draft however the manifest is written.
func autonomyFor(c *Caller) agent.Autonomy {
	switch {
	case permits(c.Role, auth.ActPublish):
		return agent.AutonomyPublish
	case permits(c.Role, auth.ActEditDraft):
		return agent.AutonomyDraft
	default:
		return agent.AutonomyPropose
	}
}

// permits asks the one table that knows which role an action needs.
//
// Through auth.Needs rather than comparing ranks here, so a change to what
// publishing requires reaches this decision too. An action no table row
// covers is not permitted, which is the same direction every other refusal
// in this program takes.
func permits(r auth.Role, a auth.Action) bool {
	need, ok := auth.Needs(a)
	return ok && r.AtLeast(need)
}

// maxBudget is larger than any budget a manifest may declare.
const maxBudget = 1 << 30

// pageTypeOf and pageLocaleOf resolve what a page is, for the scope check.
//
// agentexec.Reader takes these as functions and treats a nil one as "nothing
// is typed", which Session.Retrieve then reads as unrestricted. `agent run`
// built the Reader with both left nil, so Retrieval.Types and
// Retrieval.Locales in a manifest were decoration: a support bot declared to
// read only the help articles read everything, and the manifest said
// otherwise.
//
// The same two rules the content API already uses, deliberately. The type
// comes from the schema store's bindings, which is authoritative; the locale
// comes from the page's own field, because a locale is a property of the
// content and not of its type — the same type exists in every language, which
// is the whole point of having locales. Two answers to one question is how the
// API and the agent surface come to disagree about who may read what.
func pageTypeOf(root string) func(string) string {
	st, err := schema.Load(root)
	if err != nil || st == nil {
		// Nothing typed, which is the honest answer for a store with no
		// schema — not "everything is forbidden", because a manifest naming
		// no types restricts nothing anyway.
		return nil
	}
	return func(page string) string { return st.Bound[page] }
}

// pageLocaleOf reads a page's language from its own fields.
func pageLocaleOf(s *store.Store, ref string) func(string) string {
	return func(page string) string {
		pages, err := site.PagesAt(s, ref)
		if err != nil {
			return ""
		}
		fields, ok := pages[page].(map[string]any)
		if !ok {
			return ""
		}
		for _, key := range []string{"locale", "lang", "language"} {
			if v, ok := fields[key].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
}

// refOf is the ref an agent reads, with the same default the executor uses.
//
// Spelled once here rather than at each call site, because a second copy of
// "empty means live" is a second place for it to become "empty means draft".
func refOf(m agent.Manifest) string {
	if m.Retrieval.Ref == "" {
		return site.RefLive
	}
	return m.Retrieval.Ref
}
