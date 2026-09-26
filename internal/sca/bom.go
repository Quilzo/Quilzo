// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package sca

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// BOM is a CycloneDX bill of materials.
type BOM struct {
	Format       string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber,omitempty"`
	Version      int          `json:"version,omitempty"`
	Metadata     *Metadata    `json:"metadata,omitempty"`
	Components   []Part       `json:"components,omitempty"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}

// Metadata says what was scanned and by what.
type Metadata struct {
	Timestamp time.Time `json:"timestamp,omitzero"`
	Component *Part     `json:"component,omitempty"`
	Tools     any       `json:"tools,omitempty"`
}

// Part is one component in the bill.
type Part struct {
	Type    string `json:"type,omitempty"`
	BOMRef  string `json:"bom-ref,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	Group   string `json:"group,omitempty"`
	Scope   string `json:"scope,omitempty"`
	// Components nested inside another, which some generators use instead
	// of the flat list.
	Components []Part `json:"components,omitempty"`
}

// Dependency is one node of the graph.
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// ReadBOM parses a CycloneDX document.
func ReadBOM(in []byte) (BOM, error) {
	var b BOM
	if err := json.Unmarshal(in, &b); err != nil {
		return BOM{}, fmt.Errorf("this is not JSON: %w", err)
	}
	if !strings.EqualFold(b.Format, "CycloneDX") {
		return BOM{}, fmt.Errorf(
			"this says bomFormat %q. Only CycloneDX is read here; SPDX is "+
				"a different document with a different graph and "+
				"pretending otherwise would produce a dependency tree "+
				"nobody drew", b.Format)
	}
	if strings.TrimSpace(b.SpecVersion) == "" {
		return BOM{}, fmt.Errorf("this has no specVersion")
	}
	if len(b.Components) == 0 && (b.Metadata == nil ||
		b.Metadata.Component == nil) {
		return BOM{}, fmt.Errorf("this bill lists nothing")
	}
	return b, nil
}

// Flat is every component, including ones nested inside another.
func (b BOM) Flat() []Part {
	var out []Part
	var walk func([]Part)
	walk = func(in []Part) {
		for _, p := range in {
			out = append(out, p)
			walk(p.Components)
		}
	}
	walk(b.Components)
	return out
}

// Root is the thing the bill is about.
func (b BOM) Root() (Part, bool) {
	if b.Metadata != nil && b.Metadata.Component != nil {
		return *b.Metadata.Component, true
	}
	return Part{}, false
}

// ParsePURL reads a package URL into an ecosystem and a name.
//
// pkg:golang/github.com/x/y@v1.2.3 and pkg:npm/%40scope/pkg@1.0.0 are both
// ordinary. The type is the ecosystem, the namespace and name join with a
// slash, and both are percent-decoded — a scoped npm package whose @ was
// left encoded will not match an advisory that spelled it out.
func ParsePURL(p string) (ecosystem, name string, ok bool) {
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(p, "pkg:") {
		return "", "", false
	}
	rest := p[len("pkg:"):]
	// Qualifiers and subpath are not part of the identity.
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i > 0 {
		rest = rest[:i]
	}
	typ, path, found := strings.Cut(rest, "/")
	if !found || typ == "" || path == "" {
		return "", "", false
	}
	var parts []string
	for _, seg := range strings.Split(path, "/") {
		d, err := url.PathUnescape(seg)
		if err != nil {
			d = seg
		}
		if d != "" {
			parts = append(parts, d)
		}
	}
	if len(parts) == 0 {
		return "", "", false
	}
	return Ecosystem(strings.ToLower(typ)), strings.Join(parts, "/"), true
}

// purlTypes maps a package URL type onto the ecosystem name OSV uses.
//
// The two vocabularies disagree, which is the ordinary reason a bill and an
// advisory database fail to match a package that is plainly in both.
var purlTypes = map[string]string{
	"golang": "Go", "npm": "npm", "pypi": "PyPI", "cargo": "crates.io",
	"maven": "Maven", "nuget": "NuGet", "gem": "RubyGems",
	"composer": "Packagist", "hex": "Hex", "pub": "Pub",
	"cran": "CRAN", "swift": "SwiftURL", "conan": "ConanCenter",
	"deb": "Debian", "rpm": "Red Hat", "apk": "Alpine",
	"github": "GitHub Actions",
}

// Ecosystem maps a purl type to OSV's ecosystem name.
func Ecosystem(purlType string) string {
	if e, ok := purlTypes[strings.ToLower(purlType)]; ok {
		return e
	}
	return purlType
}

// Tree is the dependency graph, indexed for asking questions of it.
type Tree struct {
	root  string
	byRef map[string]Part
	kids  map[string][]string
}

// Graph builds the tree from a bill.
func (b BOM) Graph() Tree {
	t := Tree{byRef: map[string]Part{}, kids: map[string][]string{}}
	for _, p := range b.Flat() {
		ref := p.BOMRef
		if ref == "" {
			ref = p.PURL
		}
		if ref == "" {
			continue
		}
		t.byRef[ref] = p
	}
	if r, ok := b.Root(); ok {
		t.root = r.BOMRef
		if t.root == "" {
			t.root = r.PURL
		}
		if _, seen := t.byRef[t.root]; !seen && t.root != "" {
			t.byRef[t.root] = r
		}
	}
	for _, d := range b.Dependencies {
		t.kids[d.Ref] = append(t.kids[d.Ref], d.DependsOn...)
	}
	// A bill with no declared root but a dependency entry that nothing
	// depends on: take that as the root rather than giving up, because a
	// graph with no entry point answers none of the questions below.
	if t.root == "" {
		depended := map[string]bool{}
		for _, kids := range t.kids {
			for _, k := range kids {
				depended[k] = true
			}
		}
		refs := make([]string, 0, len(t.kids))
		for r := range t.kids {
			refs = append(refs, r)
		}
		sort.Strings(refs)
		for _, r := range refs {
			if !depended[r] {
				t.root = r
				break
			}
		}
	}
	return t
}

// Part looks a component up.
func (t Tree) Part(ref string) (Part, bool) {
	p, ok := t.byRef[ref]
	return p, ok
}

// Known reports whether the graph has anything in it.
func (t Tree) Known() bool { return len(t.kids) > 0 && t.root != "" }

// Path is the shortest route from the root to a component.
//
// Shortest because that is the cheapest fix: a package pulled in by two
// different direct dependencies is fixable through whichever of them moves
// first, and reporting the longer route would send somebody to the harder
// conversation.
func (t Tree) Path(ref string) []string {
	if t.root == "" {
		return nil
	}
	if ref == t.root {
		return []string{ref}
	}
	prev := map[string]string{}
	seen := map[string]bool{t.root: true}
	queue := []string{t.root}
	for len(queue) > 0 {
		at := queue[0]
		queue = queue[1:]
		kids := append([]string(nil), t.kids[at]...)
		sort.Strings(kids)
		for _, k := range kids {
			if seen[k] {
				continue
			}
			seen[k] = true
			prev[k] = at
			if k == ref {
				var path []string
				for n := k; n != ""; n = prev[n] {
					path = append([]string{n}, path...)
					if n == t.root {
						break
					}
				}
				return path
			}
			queue = append(queue, k)
		}
	}
	return nil
}

// Depth is how far a component is from something somebody chose.
//
// One is a direct dependency. Zero means it is the thing being scanned.
// Minus one means the graph does not reach it, which happens when a
// generator emitted components without a dependencies block and is worth
// distinguishing from "it is direct" — a scanner that assumed direct would
// tell a team to bump a version they do not control.
func (t Tree) Depth(ref string) int {
	p := t.Path(ref)
	if len(p) == 0 {
		return -1
	}
	return len(p) - 1
}

// Blocker is the nearest dependency the team controls on the way to a
// component: the direct dependency that has to move first.
//
// The work item. "Upgrade transitive package X" is not an action anybody
// can take. "Ask for, or wait for, a release of Y that takes X 2.4.1" is,
// and Y is what this returns.
func (t Tree) Blocker(ref string) (Part, bool) {
	p := t.Path(ref)
	if len(p) < 2 {
		return Part{}, false
	}
	if len(p) == 2 {
		// Direct: the component is its own blocker, and the team can move
		// it themselves.
		c, ok := t.Part(ref)
		return c, ok
	}
	c, ok := t.Part(p[1])
	return c, ok
}
