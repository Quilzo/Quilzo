// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package sca

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
	"github.com/quilzo/quilzo/internal/vuln"
)

// Work is what somebody would actually have to do about an exposure.
type Work string

const (
	// Bump: a direct dependency with a fixed version. An afternoon.
	Bump Work = "bump"
	// Wait: a transitive dependency with a fix that a package above it
	// has not taken. The work is a conversation, and the name of the
	// package to have it with is in Blocker.
	Wait Work = "wait"
	// Nothing: there is no fixed version anywhere. Not a discount — the
	// options are a fork, a replacement or an accepted risk, and all three
	// are decisions rather than tickets.
	Nothing Work = "nothing"
	// Unknown: the bill carried no dependency graph, so whether this is a
	// bump or a conversation cannot be told from what was given.
	Unknown Work = "unknown"
)

// Why says what the work is, in the words somebody triaging needs.
func (w Work) Why() string {
	switch w {
	case Bump:
		return "a direct dependency with a released fix"
	case Wait:
		return "a fix exists and something above it has not taken it, so " +
			"the work is asking rather than upgrading"
	case Nothing:
		return "no fixed version exists anywhere, so the options are a " +
			"fork, a replacement or an accepted risk — all decisions " +
			"rather than tickets"
	case Unknown:
		return "the bill carried no dependency graph, so whether this is " +
			"an afternoon or a conversation cannot be told from it"
	}
	return string(w)
}

// Actionable reports whether somebody reading this could start today.
func (w Work) Actionable() bool { return w == Bump }

// Hit is one component matched against one advisory.
type Hit struct {
	Exposure vuln.Exposure `json:"exposure"`
	Work     Work          `json:"work"`
	// Depth is how far from something somebody chose. One is direct.
	Depth int `json:"depth"`
	// Path is the route from the root, by component name.
	Path []string `json:"path,omitempty"`
	// Blocker is the direct dependency that has to move first.
	Blocker string `json:"blocker,omitempty"`
	// Fixed is the version to move to, when there is one.
	Fixed string `json:"fixed,omitempty"`
}

// Report is everything a scan found, and what it could not tell.
type Report struct {
	Hits []Hit `json:"hits"`
	// Components is how many the bill listed, Matched how many advisories
	// applied. Both, because "four findings" from a bill of six packages
	// and from a bill of four thousand are different situations.
	Components int `json:"components"`
	Advisories int `json:"advisories"`
	// Graphless is true when the bill had no dependencies block, so no
	// depth or blocker could be worked out for anything.
	Graphless bool `json:"graphless"`
	// Unversioned counts components with no version, which cannot be
	// matched against a range at all.
	Unversioned int `json:"unversioned"`
	// Unmatchable counts advisories naming an ecosystem or a package
	// nothing in the bill uses, which is normal and worth seeing when it
	// is everything.
	Unmatchable int `json:"unmatchable"`
}

// Scan matches a bill against a set of advisories.
//
// known is when this organisation found out, passed through to every
// advisory so ages are computed from the right clock.
func Scan(b BOM, records []Record, where string, known time.Time) Report {
	tree := b.Graph()
	parts := b.Flat()
	rep := Report{Components: len(parts), Graphless: !tree.Known()}

	// Index the bill by package identity, keeping the bom-ref so the graph
	// can be asked about it afterwards.
	type held struct {
		part Part
		ref  string
		key  string
	}
	byKey := map[string][]held{}
	for _, p := range parts {
		eco, name, ok := ParsePURL(p.PURL)
		if !ok {
			// No purl: fall back to the name, which is all some
			// generators emit. Matching on it is weaker and is what the
			// ecosystem field exists to disambiguate, so this only
			// matches an advisory whose package name is identical.
			name = strings.TrimSpace(p.Name)
			if p.Group != "" {
				name = p.Group + "/" + name
			}
			if name == "" {
				continue
			}
			eco = ""
		}
		if strings.TrimSpace(p.Version) == "" {
			rep.Unversioned++
			continue
		}
		ref := p.BOMRef
		if ref == "" {
			ref = p.PURL
		}
		k := vuln.Key(eco, name)
		byKey[k] = append(byKey[k], held{part: p, ref: ref, key: k})
		if eco != "" {
			// Also indexed without the ecosystem, so a bill with a purl
			// and an advisory without one still meet.
			bare := vuln.Key("", name)
			byKey[bare] = append(byKey[bare], held{part: p, ref: ref, key: k})
		}
	}

	for _, r := range records {
		if !r.Live() {
			continue
		}
		rep.Advisories++
		adv := r.Advisory(known)
		matched := false
		seen := map[string]bool{}
		for _, rg := range adv.Affects {
			k := vuln.Key(rg.Ecosystem, rg.Package)
			cands := byKey[k]
			if len(cands) == 0 {
				cands = byKey[vuln.Key("", rg.Package)]
			}
			for _, c := range cands {
				if seen[c.ref] {
					continue
				}
				if !affected(adv, rg.Ecosystem, rg.Package, c.part.Version) {
					continue
				}
				seen[c.ref] = true
				matched = true
				rep.Hits = append(rep.Hits,
					hit(adv, tree, c.part, c.ref, c.key, where))
			}
		}
		if !matched {
			rep.Unmatchable++
		}
	}
	sort.SliceStable(rep.Hits, func(i, j int) bool {
		if rep.Hits[i].Work.Actionable() != rep.Hits[j].Work.Actionable() {
			return rep.Hits[i].Work.Actionable()
		}
		return rep.Hits[i].Exposure.Advisory.ID <
			rep.Hits[j].Exposure.Advisory.ID
	})
	return rep
}

func hit(adv vuln.Advisory, tree Tree, p Part, ref, key,
	where string) Hit {
	eco, name, ok := ParsePURL(p.PURL)
	if !ok {
		name = p.Name
	}
	depth := -1
	var path []string
	blocker := ""
	if tree.Known() {
		depth = tree.Depth(ref)
		for _, step := range tree.Path(ref) {
			if sp, ok := tree.Part(step); ok {
				path = append(path, nameOf(sp))
			} else {
				path = append(path, step)
			}
		}
		if b, ok := tree.Blocker(ref); ok {
			blocker = nameOf(b)
		}
	}

	comp := vuln.Component{
		Ecosystem: eco, Name: name, Version: p.Version,
		Direct: depth == 1,
	}
	if where != "" {
		// The bill says what was scanned; the caller says where it runs.
		// Issuer-qualified like every other identity here, so two
		// deployments of the same package are two components.
		comp.Where = telemetry.ID{Issuer: "sbom", Value: where}
	}
	e := vuln.Exposure{Advisory: adv, Component: comp}
	fixed, fixable := e.Fixable()

	h := Hit{Exposure: e, Depth: depth, Path: path, Blocker: blocker,
		Fixed: fixed}
	switch {
	case !fixable:
		h.Work = Nothing
	case depth < 0:
		h.Work = Unknown
	case depth <= 1:
		h.Work = Bump
	default:
		h.Work = Wait
	}
	return h
}

func nameOf(p Part) string {
	if _, n, ok := ParsePURL(p.PURL); ok {
		return n + at(p.Version)
	}
	if p.Group != "" {
		return p.Group + "/" + p.Name + at(p.Version)
	}
	return p.Name + at(p.Version)
}

func at(v string) string {
	if strings.TrimSpace(v) == "" {
		return ""
	}
	return "@" + v
}

// affected evaluates whether a version falls inside an advisory's ranges.
//
// A version is affected when it is at or after an introduced boundary and
// before the matching fixed one. Comparison is internal/vuln's, which
// refuses to compare two versions it cannot order rather than guessing —
// and a version it cannot order is treated as affected, because the
// alternative is silently dropping a real finding on a version string
// nobody anticipated.
func affected(adv vuln.Advisory, eco, pkg, version string) bool {
	want := vuln.Key(eco, pkg)
	for _, r := range adv.Affects {
		if vuln.Key(r.Ecosystem, r.Package) != want {
			continue
		}
		if r.Introduced != "" && r.Introduced != "0" {
			c, ok := vuln.Compare(version, r.Introduced)
			if ok && c < 0 {
				continue // before this range opened
			}
		}
		if r.Fixed != "" {
			c, ok := vuln.Compare(version, r.Fixed)
			if ok && c >= 0 {
				continue // at or after the fix
			}
		}
		return true
	}
	return false
}

// Actionable is the hits somebody could start on today.
func (r Report) Actionable() []Hit {
	var out []Hit
	for _, h := range r.Hits {
		if h.Work.Actionable() {
			out = append(out, h)
		}
	}
	return out
}

// Blocked groups the hits waiting on somebody else, by who.
//
// The list to take to a meeting. One package that has not moved can be
// holding up a dozen advisories, and seeing them as one conversation
// rather than a dozen tickets is the difference between chasing an
// upstream and chasing a queue.
func (r Report) Blocked() map[string][]Hit {
	out := map[string][]Hit{}
	for _, h := range r.Hits {
		if h.Work == Wait && h.Blocker != "" {
			out[h.Blocker] = append(out[h.Blocker], h)
		}
	}
	return out
}

// Worst is the package blocking the most work.
func (r Report) Worst() (string, int) {
	best, at := "", 0
	blocked := r.Blocked()
	names := make([]string, 0, len(blocked))
	for n := range blocked {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if len(blocked[n]) > at {
			best, at = n, len(blocked[n])
		}
	}
	return best, at
}

// Why summarises a scan.
func (r Report) Why() string {
	var says []string
	says = append(says, fmt.Sprintf("%d component(s), %d advisory match(es)",
		r.Components, len(r.Hits)))
	if n := len(r.Actionable()); n > 0 {
		says = append(says, fmt.Sprintf("%d can be upgraded today", n))
	}
	if b, n := r.Worst(); n > 0 {
		says = append(says, fmt.Sprintf(
			"%d are waiting on %s", n, b))
	}
	if r.Graphless {
		says = append(says, "the bill carried no dependency graph, so "+
			"nothing here knows whether it is a bump or a conversation")
	}
	if r.Unversioned > 0 {
		says = append(says, fmt.Sprintf(
			"%d component(s) have no version and cannot be matched",
			r.Unversioned))
	}
	return strings.Join(says, "; ")
}

// Exposures is the hits in the shape internal/vuln ranks and files.
func (r Report) Exposures() []vuln.Exposure {
	out := make([]vuln.Exposure, 0, len(r.Hits))
	for _, h := range r.Hits {
		out = append(out, h.Exposure)
	}
	return out
}
