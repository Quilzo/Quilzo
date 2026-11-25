// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// The profiles a store can have.
const (
	// Standard is every feature on: a store nobody applied a profile to.
	Standard = "standard"
	// Security is the security install's: the catalogue off.
	Security = "security"
	// Public is the public instance's, which is not a store's profile at
	// all but a separate process that serves what it was sent
	// (internal/outpost). Named here so it cannot be applied to a store by
	// mistake.
	Public = "public"
)

// Feature is one thing the security profile switches off, and everywhere
// it is reached from.
type Feature struct {
	// Name is how a person names it to switch it back on.
	Name string `json:"name"`
	// Title is what it is called on a screen.
	Title string `json:"title"`
	// Why is why a security install has no use for it, which is what an
	// auditor reading the manifest needs to agree with.
	Why string `json:"why"`
	// Commands are the command-line commands it owns.
	Commands []string `json:"commands,omitempty"`
	// Admin and Site are the addresses it answers at on the admin and the
	// public site. An address covers itself and everything below it.
	Admin []string `json:"admin,omitempty"`
	Site  []string `json:"site,omitempty"`
	// Operations are its operations on the agent interface.
	Operations []string `json:"operations,omitempty"`
	// Also is what else stops, in words, where the feature is a behaviour
	// rather than an address: an agent run refused a browser, a site that
	// serves every visitor the same page.
	Also string `json:"also,omitempty"`
}

// catalogue is every feature the security profile switches off.
//
// A list somebody decided, not an inference: each entry is a feature the
// strategy names as having no security use, and each one's addresses are
// held to what the program serves by the tests that walk the router.
var catalogue = []Feature{
	{Name: "commerce", Title: "Payments and commerce",
		Why: "taking money, and checkout for shopping agents, have no part in the record of a " +
			"security programme, and each is a way for a stranger to reach the store",
		Commands: []string{"pay"}, Admin: []string{"/pay"},
		Site: []string{"/.well-known/ucp", "/ucp/"}},
	{Name: "social", Title: "Social posting",
		Why: "announcing publications to the fediverse publishes to the public from the site " +
			"itself, and takes in follows and posts from other servers",
		Commands: []string{"fediverse"},
		Site:     []string{"/.well-known/webfinger", "/@"},
		Also:     "the site does not federate or announce what it publishes"},
	{Name: "desktop", Title: "The desktop portal",
		Why: "working a person's own desktop is the weakest isolation the program has, and " +
			"nothing the security record does needs it",
		Commands: []string{"desktop"}},
	{Name: "browser-hands", Title: "Browser hands",
		Why: "an agent working a web browser reads pages other people wrote and acts on them; " +
			"the security crews read sealed evidence instead",
		Commands: []string{"browser"}, Admin: []string{"/mcp/browser/"},
		Also: "agent runs are refused a browser"},
	{Name: "experiments", Title: "Experiments",
		Why:      "testing page variants on visitors is marketing, with no security use",
		Commands: []string{"experiment"}, Admin: []string{"/experiments"},
		Operations: []string{"experiment_report"},
		Also:       "the site serves every visitor the same page"},
	{Name: "personalisation", Title: "Personalisation",
		Why:      "choosing a page by who is asking is marketing, with no security use",
		Commands: []string{"personalise"}, Admin: []string{"/personalise"},
		Also: "the site serves every visitor the same page"},
	{Name: "boards", Title: "Member boards",
		Why: "discussion boards take posts from the site's members, and a security install " +
			"has neither members' discussions nor a reason to accept strangers' posts",
		Commands: []string{"board"}, Admin: []string{"/boards"},
		Site: []string{"/board/", "/live/board/"}},
}

// Catalogue is every feature the security profile switches off, a copy.
func Catalogue() []Feature {
	out := make([]Feature, len(catalogue))
	for i, f := range catalogue {
		f.Commands = slices.Clone(f.Commands)
		f.Admin = slices.Clone(f.Admin)
		f.Site = slices.Clone(f.Site)
		f.Operations = slices.Clone(f.Operations)
		out[i] = f
	}
	return out
}

// Lookup is one feature by name.
func Lookup(name string) (Feature, bool) {
	for _, f := range Catalogue() {
		if f.Name == name {
			return f, true
		}
	}
	return Feature{}, false
}

// Names is every feature's name, for a message that says what there is.
func Names() []string {
	out := make([]string, 0, len(catalogue))
	for _, f := range catalogue {
		out = append(out, f.Name)
	}
	return out
}

// Change is one feature switched on or off, by a person, with a reason.
type Change struct {
	Feature string    `json:"feature"`
	On      bool      `json:"on"`
	Reason  string    `json:"reason"`
	By      string    `json:"by"`
	At      time.Time `json:"at"`
}

// State is a store's profile, and every change made since it was applied.
//
// Changes from before the last application are not here: applying a
// profile is starting from it again, and the audit log holds what came
// before.
type State struct {
	Profile string    `json:"profile"`
	Since   time.Time `json:"since,omitzero"`
	By      string    `json:"by,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	Changes []Change  `json:"changes,omitempty"`
}

// Name is the profile's name, Standard for a store nobody applied one to.
func (s *State) Name() string {
	if s == nil || s.Profile == "" {
		return Standard
	}
	return s.Profile
}

// Last is the change that set a feature as it is, if one did.
func (s *State) Last(name string) (Change, bool) {
	if s == nil {
		return Change{}, false
	}
	for i := len(s.Changes) - 1; i >= 0; i-- {
		if s.Changes[i].Feature == name {
			return s.Changes[i], true
		}
	}
	return Change{}, false
}

// On reports whether a feature is on: as the last change to it set it, or
// else as the profile has it.
func (s *State) On(name string) bool {
	if ch, ok := s.Last(name); ok {
		return ch.On
	}
	return s.Name() != Security
}

// Off is every feature that is off, in the catalogue's order.
func (s *State) Off() []Feature {
	var out []Feature
	for _, f := range Catalogue() {
		if !s.On(f.Name) {
			out = append(out, f)
		}
	}
	return out
}

// Apply makes profile the store's, starting from it again.
func (s *State) Apply(profile, reason, by string, now time.Time) error {
	switch profile {
	case Standard, Security:
	case Public:
		return errors.New("the public profile is a public instance's, made with " +
			"quilzo init --profile public on its own host, and not a store's")
	default:
		return fmt.Errorf("%q is not a profile; there are %s and %s", profile, Security, Standard)
	}
	if strings.TrimSpace(by) == "" {
		return errors.New("a profile is applied by somebody: nobody was named")
	}
	// The first application is the install, and says so itself. Changing
	// one profile for another afterwards is a decision about what this
	// installation runs, and needs its reason as switching one feature does.
	reason = strings.TrimSpace(reason)
	if s.Profile != "" && reason == "" {
		return errors.New("a reason is required: changing the profile changes what this " +
			"installation runs, and the record has to say why")
	}
	s.Profile, s.Since, s.By, s.Reason, s.Changes = profile, now.UTC(), by, reason, nil
	return nil
}

// Switch turns one feature on or off, with a reason, and returns the change.
func (s *State) Switch(name string, on bool, reason, by string, now time.Time) (Change, error) {
	if _, ok := Lookup(name); !ok {
		return Change{}, fmt.Errorf("%q is not a feature the profile switches; there are %s",
			name, strings.Join(Names(), ", "))
	}
	if strings.TrimSpace(by) == "" {
		return Change{}, errors.New("a feature is switched by somebody: nobody was named")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		word := "off"
		if on {
			word = "on"
		}
		return Change{}, fmt.Errorf("a reason is required: switching %s %s changes what this "+
			"installation runs, and the record has to say why", name, word)
	}
	if s.On(name) == on {
		word := "off"
		if on {
			word = "on"
		}
		return Change{}, fmt.Errorf("%s is %s already", name, word)
	}
	ch := Change{Feature: name, On: on, Reason: reason, By: by, At: now.UTC()}
	s.Changes = append(s.Changes, ch)
	return ch, nil
}

// RefusesCommand reports whether a command belongs to a feature that is
// off, and which.
func (s *State) RefusesCommand(cmd string) (Feature, bool) {
	for _, f := range s.Off() {
		if slices.Contains(f.Commands, cmd) {
			return f, true
		}
	}
	return Feature{}, false
}

// RefusesOperation reports whether an agent-interface operation belongs to
// a feature that is off.
func (s *State) RefusesOperation(op string) (Feature, bool) {
	for _, f := range s.Off() {
		if slices.Contains(f.Operations, op) {
			return f, true
		}
	}
	return Feature{}, false
}

// Refuses reports whether an address on a surface belongs to a feature that
// is off.
func (s *State) Refuses(on Surface, path string) (Feature, bool) {
	for _, f := range s.Off() {
		for _, p := range f.addresses(on) {
			if Covers(p, path) {
				return f, true
			}
		}
	}
	return Feature{}, false
}

func (f Feature) addresses(on Surface) []string {
	switch on {
	case AdminSurface:
		return f.Admin
	case SiteSurface:
		return f.Site
	}
	return nil
}

// Covers reports whether an address in the catalogue covers a requested
// path: itself, and everything below it.
//
// Below means after a slash, so /pay covers /pay/act and not /payroll. An
// address that ends in a slash is a subtree already, as the router has it.
func Covers(address, path string) bool {
	if strings.HasSuffix(address, "/") {
		return strings.HasPrefix(path, address)
	}
	return path == address || strings.HasPrefix(path, address+"/")
}

// Load reads a state. A missing file is the standard profile; one that
// cannot be read, or that names something this version does not know, is
// an error, because guessing what it meant is guessing which features run.
func Load(path string) (*State, error) {
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &State{}, nil
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	st := &State{}
	if err := dec.Decode(st); err != nil {
		return nil, fmt.Errorf("the profile at %s does not parse: %w", path, err)
	}
	switch st.Name() {
	case Standard, Security:
	default:
		return nil, fmt.Errorf("the profile at %s is %q, which this version does not know", path, st.Profile)
	}
	for _, ch := range st.Changes {
		if _, ok := Lookup(ch.Feature); !ok {
			return nil, fmt.Errorf("the profile at %s switches %q, which this version does not have",
				path, ch.Feature)
		}
	}
	sort.SliceStable(st.Changes, func(i, j int) bool { return st.Changes[i].At.Before(st.Changes[j].At) })
	return st, nil
}

// Save writes a state, readable only by the store's owner: it says what
// this installation runs, which is as much the store's business as its
// settings.
func Save(path string, st *State) error {
	body, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, append(body, '\n'), 0o600)
}

// Closed is the state a profile that cannot be read stands for: the
// security profile, everything in the catalogue off.
//
// Closed and not open, because a profile file anybody can spoil would
// otherwise be a way to switch every feature back on without a reason.
func Closed() *State { return &State{Profile: Security} }
