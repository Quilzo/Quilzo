// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package feature makes a feature a package: one file that declares a set of
// Quilzo's own building blocks, checked, described in words a person can
// approve, installed as one decision, and taken back as one.
//
// # Why a package rather than a screen at a time
//
// A feature people ask for, "track samples for my lab and let the team see
// who has which", is a type, a collection, a listing, a form, two pages, a
// menu entry and perhaps a chatbot and an agent. Built one screen at a time
// it has no name: nobody can say what it is allowed to do, review it as a
// whole, hand it to another installation, or remove it without hunting for
// its parts. As a package it has a name, a purpose, a version, a digest and
// an owner, and every part of it is known.
//
// # Level one: composition, no code
//
// Everything a package declares is data that Quilzo's own code already runs,
// validated by the same checks the command line uses for each block. There is
// no code in a package at this level and nothing to sandbox: a type is a flat
// list of fields, a listing is a declared query, a page is content staged in
// the draft. Whoever wrote the file, a person or a model, it can only
// describe things Quilzo already knows how to do safely.
//
// # What it cannot do
//
// A package never publishes: its pages go to the draft, and going live is
// the review it always was. It never grants access: the roles it declares
// for the people who work in it reach only its own blocks, and hold nobody
// until a person who may grant access assigns them. It never carries a secret
// (a webhook's signing secret is made at install), and never overwrites a
// block it did not create: a name another feature or a person already uses
// is a conflict, refused, so removing a feature can never remove somebody
// else's work.
package feature

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/menu"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/seo"
)

// Format is the package format this program reads and writes.
const Format = 1

// Bounds. A package is something a person reads before approving, and one
// too large to read is one nobody did.
const (
	MaxBytes  = 2 << 20
	MaxBlocks = 200
)

// Package is one feature.
type Package struct {
	Format  int    `json:"format"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Title   string `json:"title"`
	// Purpose is what the feature is for, in a sentence a person approving
	// it reads first.
	Purpose string `json:"purpose"`
	// Made says how the package came to be, so a reader knows whether a
	// person or a model wrote it.
	Made *Made `json:"made,omitempty"`

	// Site is the site itself, for a package that is a whole site (see
	// site.go).
	Site *Site `json:"site,omitempty"`

	Types       []schema.Type         `json:"types,omitempty"`
	Collections []Collection          `json:"collections,omitempty"`
	Listings    []listing.Listing     `json:"listings,omitempty"`
	Forms       []form.Form           `json:"forms,omitempty"`
	Pages       []Page                `json:"pages,omitempty"`
	Menus       []menu.Menu           `json:"menus,omitempty"`
	Chatbots    []assistant.Assistant `json:"chatbots,omitempty"`
	Agents      []agent.Manifest      `json:"agents,omitempty"`
	Webhooks    []Webhook             `json:"webhooks,omitempty"`
	// Roles are for the people who work in the feature (see roles.go).
	Roles []Role `json:"roles,omitempty"`

	// Signature, when present, is over the package's digest by the
	// installation that exported it.
	Signature *Signature `json:"signature,omitempty"`
}

// Made is a package's provenance.
type Made struct {
	// By is who made it: a person's name, or "agent:NAME" for the builder.
	By string `json:"by"`
	// From is what it was made from: the sentence asked for, or the file a
	// person dropped in.
	From string    `json:"from,omitempty"`
	At   time.Time `json:"at,omitzero"`
	// Model is the model that drafted it, when one did.
	Model string `json:"model,omitempty"`
}

// Collection binds a collection of records to a type.
type Collection struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Page is content staged into the draft under a name.
type Page struct {
	Name string         `json:"name"`
	Body map[string]any `json:"body"`
}

// Webhook is an endpoint told about events. Its secret is made at install
// and never travels in a package.
type Webhook struct {
	URL   string   `json:"url"`
	Types []string `json:"types,omitempty"`
	Note  string   `json:"note,omitempty"`
}

// Signature is a package digest signed with an installation's log keys.
type Signature struct {
	KeyID      string   `json:"key_id"`
	Ed25519    string   `json:"ed25519"`
	MLDSA      string   `json:"mldsa,omitempty"`
	Algorithms []string `json:"algorithms"`
}

var (
	reName    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	reVersion = regexp.MustCompile(`^[0-9]{1,6}(\.[0-9]{1,6}){0,2}$`)
	// rePage is a page's name as the store has it: lower-case words joined
	// by hyphens, in folders.
	rePage = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*(?:/[a-z0-9]+(?:-[a-z0-9]+)*)*$`)
)

// Decode reads a package strictly: unknown fields are refused, because a
// key this program does not know is a permission somebody believes they
// asked for and did not get.
func Decode(r io.Reader) (*Package, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxBytes {
		return nil, fmt.Errorf("a package is at most %d MiB; this one is larger", MaxBytes>>20)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p Package
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("this is not a feature package: %w", err)
	}
	if dec.More() {
		return nil, errors.New("this is not a feature package: there is more than one JSON value in it")
	}
	return &p, nil
}

// Checks are the validations that need the installation: what capabilities
// exist, and which agent kinds are declared. The command line supplies them.
type Checks struct {
	Agent func(agent.Manifest) error
	// URL checks a webhook endpoint the way `quilzo webhook add` does.
	URL func(string) error
	// EventType reports whether a webhook event type exists.
	EventType func(string) bool
}

// Validate checks a package on its own: its shape, its bounds, and every
// block by the same rules that block is held to anywhere else. It does not
// look at what is installed; Plan does that.
func (p *Package) Validate(c Checks) error {
	var errs []string
	bad := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }

	if p.Format != Format {
		bad("format is %d; this program reads format %d", p.Format, Format)
	}
	if !reName.MatchString(p.Name) {
		bad("name %q is not usable: lower-case letters, digits and hyphens, starting with a letter, 2 to 63 long", p.Name)
	}
	if !reVersion.MatchString(p.Version) {
		bad("version %q is not usable: one to three numbers separated by dots, such as 1.0.2", p.Version)
	}
	if strings.TrimSpace(p.Title) == "" || len(p.Title) > 120 {
		bad("a title is required, at most 120 characters")
	}
	if strings.TrimSpace(p.Purpose) == "" || len(p.Purpose) > 600 {
		bad("a purpose is required, one or two sentences of at most 600 characters")
	}
	if n := p.Blocks(); n == 0 {
		bad("the package declares nothing")
	} else if n > MaxBlocks {
		bad("the package declares %d blocks; at most %d, so a person can read it", n, MaxBlocks)
	}

	seen := map[string]bool{}
	unique := func(kind, name string) {
		k := kind + "/" + name
		if seen[k] {
			bad("%s %q is declared twice", kind, name)
		}
		seen[k] = true
	}

	types := map[string]bool{}
	for _, t := range p.Types {
		unique("type", t.Name)
		if err := schema.NewRegistry().Add(t); err != nil {
			bad("type %q: %v", t.Name, err)
		}
		types[t.Name] = true
	}
	collections := map[string]bool{}
	for _, col := range p.Collections {
		unique("collection", col.Name)
		if err := collection.ValidName(col.Name); err != nil {
			bad("collection %q: %v", col.Name, err)
		}
		if !types[col.Type] {
			bad("collection %q is bound to type %q, which the package does not declare", col.Name, col.Type)
		}
		collections[col.Name] = true
	}
	for i := range p.Listings {
		l := p.Listings[i]
		unique("listing", l.Name)
		if err := l.Validate(); err != nil {
			bad("listing %q: %v", l.Name, err)
		}
		if !collections[l.Collection] {
			bad("listing %q reads collection %q, which the package does not declare", l.Name, l.Collection)
		}
	}
	for i := range p.Forms {
		f := p.Forms[i]
		unique("form", f.Name)
		if err := f.Validate(); err != nil {
			bad("form %q: %v", f.Name, err)
		}
	}
	pages := map[string]any{}
	for _, pg := range p.Pages {
		unique("page", pg.Name)
		if !rePage.MatchString(pg.Name) || len(pg.Name) > 128 {
			bad("page name %q is not usable", pg.Name)
		}
		if pg.Body == nil {
			bad("page %q has no body", pg.Name)
		}
		pages[pg.Name] = pg.Body
	}
	for i := range p.Menus {
		m := p.Menus[i]
		unique("menu", m.Name)
		if err := menu.ValidName(m.Name); err != nil {
			bad("menu %q: %v", m.Name, err)
		}
	}
	launchers := 0
	for _, a := range p.Chatbots {
		unique("chatbot", a.Name)
		if err := a.Validate(); err != nil {
			bad("chatbot %q: %v", a.Name, err)
		}
		if a.Launcher != nil {
			launchers++
		}
	}
	if launchers > 1 {
		bad("%d chatbots ask for the site's launcher; a site shows one", launchers)
	}
	for _, m := range p.Agents {
		unique("agent", m.Name)
		if c.Agent != nil {
			if err := c.Agent(m); err != nil {
				bad("agent %q: %v", m.Name, err)
			}
		}
	}
	for _, h := range p.Webhooks {
		unique("webhook", h.URL)
		if c.URL != nil {
			if err := c.URL(h.URL); err != nil {
				bad("webhook %s: %v", h.URL, err)
			}
		}
		for _, t := range h.Types {
			if c.EventType != nil && !c.EventType(t) {
				bad("webhook %s: %q is not an event this sends", h.URL, t)
			}
		}
	}
	p.validateRoles(bad, unique)
	if p.Site != nil {
		p.Site.validate(bad)
		// Redirects are served before pages, so one from the package's own
		// page would hide it.
		if m, err := seo.NewMap(p.Site.Redirects); err == nil && m.Len() > 0 {
			for _, pg := range p.Pages {
				if _, ok := m.Lookup(PagePath(pg.Name)); ok {
					bad("site: a redirect from %s would hide the package's own page %s", PagePath(pg.Name), pg.Name)
				}
			}
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return fmt.Errorf("the package is not usable:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

// PagePath is where a page is served: the index at the root, the rest by
// name.
func PagePath(name string) string {
	if name == "index" {
		return "/"
	}
	return "/" + name
}

// Blocks counts what the package declares.
func (p *Package) Blocks() int {
	n := len(p.Types) + len(p.Collections) + len(p.Listings) + len(p.Forms) + len(p.Pages) +
		len(p.Menus) + len(p.Chatbots) + len(p.Agents) + len(p.Webhooks) + len(p.Roles)
	if p.Site != nil {
		n++
	}
	return n
}

// Digest is the SHA-256 of the package without its signature, as JSON in
// field order with maps sorted, which encoding/json does, so the same
// package always has the same digest.
func (p *Package) Digest() (string, error) {
	q := *p
	q.Signature = nil
	b, err := json.Marshal(&q)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Ref names a block: its kind and its name.
type Ref struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

func (r Ref) String() string { return r.Kind + " " + r.Name }

// Refs is every block the package declares, in a fixed order.
func (p *Package) Refs() []Ref {
	var out []Ref
	add := func(kind string, names ...string) {
		for _, n := range names {
			out = append(out, Ref{kind, n})
		}
	}
	for _, t := range p.Types {
		add("type", t.Name)
	}
	for _, c := range p.Collections {
		add("collection", c.Name)
	}
	for _, l := range p.Listings {
		add("listing", l.Name)
	}
	for _, f := range p.Forms {
		add("form", f.Name)
	}
	for _, pg := range p.Pages {
		add("page", pg.Name)
	}
	for _, m := range p.Menus {
		add("menu", m.Name)
	}
	for _, a := range p.Chatbots {
		add("chatbot", a.Name)
	}
	for _, m := range p.Agents {
		add("agent", m.Name)
	}
	for _, h := range p.Webhooks {
		add("webhook", h.URL)
	}
	// A role's name is its feature's and its own, because who holds it is
	// recorded by that name and another feature may have a role of the same.
	for _, r := range p.Roles {
		add("role", p.FullName(r))
	}
	if p.Site != nil {
		out = append(out, SiteRef)
	}
	return out
}

// example is a package someone can read, edit and install.
//
//go:embed example.json
var example []byte

// Example is a small, complete package: a lab sample tracker.
func Example() []byte { return append([]byte(nil), example...) }
