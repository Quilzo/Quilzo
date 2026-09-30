// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package action declares the few things this program may do to another
// tool, as opposed to read from it.
//
// # Why this is its own package, and small
//
// Every connector here is read-only, and that is a property with a test: a
// stolen credential from this store can read a directory and cannot change
// one. An action breaks that on purpose — suspending an account during an
// incident is worth having — so it is kept as far from a connector as it
// can be:
//
//   - An action is one request. A fixed method, a fixed host, a path with
//     one place for the thing acted on, and a body that is a constant. There
//     is no template language: nothing about the request can be computed
//     from anything but which account it is.
//   - The thing acted on is one identifier, of one platform, matched against
//     a pattern before it goes anywhere near a URL.
//   - It has its own credential, named apart from the one that reads, so
//     that installing an action is a separate decision with a separate
//     secret, and removing it leaves reading untouched.
//   - It says in words what it does and how it is undone. One that cannot
//     be undone says that instead.
//
// Nothing here sends anything. It builds the request; whoever holds the
// incident, the approval and the network decides whether it goes.
package action

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Request is one HTTP request an action makes.
type Request struct {
	Method string `json:"method"`
	// Path carries {target} exactly once.
	Path string `json:"path"`
	// Body is sent as written. It is a constant: no part of it comes from
	// anywhere but this file.
	Body string `json:"body,omitempty"`
}

// Target is what an action acts on.
type Target struct {
	// Issuer is the platform whose identifier it is: the entity an event
	// or finding names as okta:00u1 is a target for an okta action.
	Issuer string `json:"issuer"`
	// Pattern is what the identifier must look like, anchored.
	Pattern string `json:"pattern"`
	// What says it in words: "an Okta user id".
	What string `json:"what"`
}

// Action is one thing that may be done to one tool.
type Action struct {
	Name  string `json:"name"`
	Tool  string `json:"tool"`
	Title string `json:"title"`
	Host  string `json:"host"`
	// Secret is the name of the credential, and Scheme what goes before it
	// in the Authorization header.
	Secret string `json:"secret"`
	Scheme string `json:"scheme"`

	Target Target  `json:"target"`
	Does   Request `json:"does"`
	// Undo reverses it. Nil means it cannot be reversed from here.
	Undo *Request `json:"undo,omitempty"`

	// Effect is what happens, for whoever has to approve it, and Reverts
	// how it is put back — or that it cannot be.
	Effect  string `json:"effect"`
	Reverts string `json:"reverts"`
}

// Reversible reports whether the action can be undone from here.
func (a Action) Reversible() bool { return a.Undo != nil }

var (
	nameShape = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,48}$`)
	// An identifier as platforms write them: no separator a URL gives
	// meaning to.
	safeTarget = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`)
	methods    = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}
)

func checkHost(h string) error {
	if h == "" || strings.ContainsAny(h, "/:@*?# ") || net.ParseIP(h) != nil ||
		!strings.Contains(h, ".") {
		return fmt.Errorf("%q is not one ordinary hostname", h)
	}
	return nil
}

func (r Request) validate(what string) error {
	if !methods[r.Method] {
		return fmt.Errorf("%s uses %q; an action is POST, PUT, PATCH or "+
			"DELETE. Reading is a connector's", what, r.Method)
	}
	if !strings.HasPrefix(r.Path, "/") || strings.Count(r.Path, "{target}") != 1 ||
		strings.ContainsAny(r.Path, "?#\\ ") || strings.Contains(r.Path, "..") ||
		strings.ContainsAny(strings.Replace(r.Path, "{target}", "", 1), "{}") {
		return fmt.Errorf("%s: a path starts with /, names {target} once, "+
			"and carries nothing else that varies", what)
	}
	if r.Body != "" {
		if len(r.Body) > 2048 || strings.Contains(r.Body, "{target}") ||
			!json.Valid([]byte(r.Body)) {
			return fmt.Errorf("%s: a body is a small constant piece of JSON. "+
				"What is acted on goes in the path, where it is one segment",
				what)
		}
	}
	return nil
}

// Validate refuses an action that could do more than it says.
func (a Action) Validate() error {
	if !nameShape.MatchString(a.Name) {
		return fmt.Errorf("%q is not an action's name", a.Name)
	}
	if strings.TrimSpace(a.Tool) == "" || strings.TrimSpace(a.Title) == "" {
		return fmt.Errorf("%s needs a tool and a title", a.Name)
	}
	if err := checkHost(a.Host); err != nil {
		return fmt.Errorf("%s: %w", a.Name, err)
	}
	if !nameShape.MatchString(a.Secret) || !strings.Contains(a.Secret, "action") {
		return fmt.Errorf("%s: the credential's name says it is for "+
			"actions, as okta-action-token. One shared with a connector "+
			"makes the credential that reads into one that writes", a.Name)
	}
	if a.Scheme == "" || strings.ContainsAny(a.Scheme, " \r\n:") {
		return fmt.Errorf("%s: the scheme is one word, as Bearer or SSWS", a.Name)
	}
	if !nameShape.MatchString(a.Target.Issuer) || strings.TrimSpace(a.Target.What) == "" {
		return fmt.Errorf("%s does not say what it acts on", a.Name)
	}
	p := a.Target.Pattern
	if !strings.HasPrefix(p, "^") || !strings.HasSuffix(p, "$") {
		return fmt.Errorf("%s: the target's pattern is anchored at both ends",
			a.Name)
	}
	if _, err := regexp.Compile(p); err != nil {
		return fmt.Errorf("%s: %w", a.Name, err)
	}
	if err := a.Does.validate(a.Name); err != nil {
		return err
	}
	if a.Undo != nil {
		if err := a.Undo.validate(a.Name + "'s undo"); err != nil {
			return err
		}
	}
	if strings.TrimSpace(a.Effect) == "" || strings.TrimSpace(a.Reverts) == "" {
		return fmt.Errorf("%s does not say what it does and how it is put "+
			"back. Somebody approves this from those two sentences", a.Name)
	}
	return nil
}

// Accepts reports whether a value is something this action may act on.
func (a Action) Accepts(target string) error {
	re, err := regexp.Compile(a.Target.Pattern)
	if err != nil {
		return err
	}
	if !safeTarget.MatchString(target) || !re.MatchString(target) {
		return fmt.Errorf("%q is not %s", target, a.Target.What)
	}
	return nil
}

// Build makes the request for one target: the action itself, or its undo.
// The credential is set by the caller, on the request this returns.
func (a Action) Build(target string, undo bool) (*http.Request, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	if err := a.Accepts(target); err != nil {
		return nil, err
	}
	r := a.Does
	if undo {
		if a.Undo == nil {
			return nil, fmt.Errorf("%s cannot be undone from here: %s",
				a.Name, a.Reverts)
		}
		r = *a.Undo
	}
	u := &url.URL{Scheme: "https", Host: a.Host,
		Path: strings.Replace(r.Path, "{target}", target, 1)}
	// Escaped as one segment, whatever the pattern allowed.
	u.RawPath = strings.Replace(r.Path, "{target}", url.PathEscape(target), 1)
	req, err := http.NewRequest(r.Method, u.String(), bytes.NewReader([]byte(r.Body)))
	if err != nil {
		return nil, err
	}
	if r.Body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// Says is the request in a line, for whoever is about to approve it.
func (a Action) Says(target string, undo bool) string {
	r := a.Does
	if undo && a.Undo != nil {
		r = *a.Undo
	}
	return r.Method + " https://" + a.Host +
		strings.Replace(r.Path, "{target}", target, 1)
}

// Entry is a shipped action and what a customer supplies to install it.
type Entry struct {
	About string `json:"about"`
	// Hosts are the hosts it may be installed for, by region; a host may
	// carry {org}, filled from a checked parameter.
	Hosts   map[string]string `json:"hosts"`
	Default string            `json:"default"`
	// Credential says what the credential is and the least it needs.
	Credential string `json:"credential"`
	Action     Action `json:"action"`
}

var orgShape = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// For returns the entry's action for one region and organisation, checked.
func (e Entry) For(region, org string) (Action, error) {
	if region == "" {
		region = e.Default
	}
	host, ok := e.Hosts[region]
	if !ok {
		return Action{}, fmt.Errorf("%s has no region %q", e.Action.Name, region)
	}
	if strings.Contains(host, "{org}") {
		org = strings.ToLower(strings.TrimSpace(org))
		if !orgShape.MatchString(org) {
			return Action{}, fmt.Errorf("%s needs --org: the organisation's "+
				"subdomain, one label", e.Action.Name)
		}
		host = strings.ReplaceAll(host, "{org}", org)
	}
	a := e.Action
	a.Host = host
	return a, a.Validate()
}

//go:embed catalogue/*.json
var catalogueFS embed.FS

// Catalogue is the actions that ship, by name.
func Catalogue() (map[string]Entry, error) {
	entries, err := catalogueFS.ReadDir("catalogue")
	if err != nil {
		return nil, err
	}
	out := map[string]Entry{}
	for _, f := range entries {
		b, err := catalogueFS.ReadFile("catalogue/" + f.Name())
		if err != nil {
			return nil, err
		}
		var e Entry
		if err := json.Unmarshal(b, &e); err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name(), err)
		}
		if e.Action.Name+".json" != f.Name() {
			return nil, fmt.Errorf("%s holds %s", f.Name(), e.Action.Name)
		}
		out[e.Action.Name] = e
	}
	return out, nil
}

// Names lists a catalogue in order.
func Names(c map[string]Entry) []string {
	out := make([]string, 0, len(c))
	for n := range c {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
