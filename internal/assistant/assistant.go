// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package assistant

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// Assistant is one chatbot, as its owner declared it.
//
// Declared as data, like a form or a listing, and for the same reason: what a
// public-facing thing may read and may do is decided where it can be reviewed
// and diffed, not assembled at request time from whatever a prompt says.
type Assistant struct {
	Name  string `json:"name"`
	Title string `json:"title"`
	// Greeting is the first thing a visitor sees.
	Greeting string `json:"greeting,omitempty"`
	// Instructions are tone and focus. They cannot widen what the assistant
	// reads or does; the prompt tells the model so, and the code enforces it
	// whatever the model does.
	Instructions string `json:"instructions,omitempty"`
	// Pages confines what it reads to pages under these prefixes. Empty is
	// every published page.
	Pages []string `json:"pages,omitempty"`
	// Exclude removes pages under these prefixes, after Pages.
	Exclude []string `json:"exclude,omitempty"`
	// Actions are what it may offer to do. Nothing else.
	Actions []Action `json:"actions,omitempty"`
	// Refusal is what it says when it does not know.
	Refusal string `json:"refusal,omitempty"`
	// Passages is how many are retrieved per question. Default 5.
	Passages int `json:"passages,omitempty"`
	// Public serves it on the published site at /ask/NAME. Off, it answers
	// only in the admin's test console.
	Public bool `json:"public,omitempty"`
	// UseModel answers with the configured model when there is one. Off, it
	// is always extractive — no model call, no cost, nothing sent anywhere.
	UseModel bool `json:"use_model,omitempty"`
}

// ActionKind is a closed list of what an assistant can offer.
type ActionKind string

const (
	// Link offers a page on this site. No side effect at all.
	Link ActionKind = "link"
	// Form fills in one of the site's declared forms, which the visitor sees
	// and submits. The form's own validation, rate limit and storage apply;
	// the assistant only pre-fills it.
	Form ActionKind = "form"
)

// Action is one thing an assistant may offer to do.
type Action struct {
	Name string     `json:"name"`
	Kind ActionKind `json:"kind"`
	// Target is the page for a link, the form name for a form.
	Target      string `json:"target"`
	Description string `json:"description"`
	// Fields are the form fields the model may pre-fill. A field not listed
	// here is never filled by the model, however it asks.
	Fields []string `json:"fields,omitempty"`
}

func (a Action) fieldNames() []string { return a.Fields }

// Proposal is an action offered to a visitor, waiting for them.
type Proposal struct {
	Action Action            `json:"action"`
	Args   map[string]string `json:"args,omitempty"`
}

var reName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Limits on what an owner can declare, so a declaration cannot be the way a
// prompt grows to a size that costs more than the page it serves.
const (
	MaxInstructions = 4000
	MaxActions      = 12
	MaxArg          = 500
)

// Validate refuses a declaration that could not work or could not be
// trusted to.
func (a Assistant) Validate() error {
	if !reName.MatchString(a.Name) {
		return fmt.Errorf("%q is not a usable name: lower-case letters, "+
			"digits and hyphens, as it appears in /ask/NAME", a.Name)
	}
	if strings.TrimSpace(a.Title) == "" {
		return fmt.Errorf("%s needs a title a visitor will see", a.Name)
	}
	if len(a.Instructions) > MaxInstructions {
		return fmt.Errorf("%s's instructions are over %d characters",
			a.Name, MaxInstructions)
	}
	if a.Passages < 0 || a.Passages > 12 {
		return fmt.Errorf("%s retrieves %d passages; between 1 and 12",
			a.Name, a.Passages)
	}
	if len(a.Actions) > MaxActions {
		return fmt.Errorf("%s declares %d actions, over %d", a.Name,
			len(a.Actions), MaxActions)
	}
	seen := map[string]bool{}
	for _, ac := range a.Actions {
		if !reName.MatchString(ac.Name) {
			return fmt.Errorf("action %q is not a usable name", ac.Name)
		}
		if seen[ac.Name] {
			return fmt.Errorf("%s declares the action %s twice", a.Name, ac.Name)
		}
		seen[ac.Name] = true
		if strings.TrimSpace(ac.Description) == "" {
			return fmt.Errorf("action %s has no description, so neither a "+
				"model nor a visitor can tell what it does", ac.Name)
		}
		switch ac.Kind {
		case Link:
			if len(ac.Fields) > 0 {
				return fmt.Errorf("action %s is a link and has fields", ac.Name)
			}
		case Form:
			if len(ac.Fields) == 0 {
				return fmt.Errorf("action %s pre-fills a form and names no "+
					"field it may fill", ac.Name)
			}
		default:
			return fmt.Errorf("action %s is a %q; an action is a link or a "+
				"form", ac.Name, ac.Kind)
		}
		if strings.TrimSpace(ac.Target) == "" || strings.ContainsAny(ac.Target, "\\:") ||
			strings.Contains(ac.Target, "..") || strings.HasPrefix(ac.Target, "//") {
			return fmt.Errorf("action %s's target %q is not a page or form "+
				"on this site", ac.Name, ac.Target)
		}
	}
	return nil
}

func (a Assistant) depth() int {
	if a.Passages <= 0 {
		return 5
	}
	return a.Passages
}

func (a Assistant) refusal() string {
	if s := strings.TrimSpace(a.Refusal); s != "" {
		return s
	}
	return "I could not find that on this site."
}

// Reads reports whether the assistant may read a page.
func (a Assistant) Reads(page string) bool {
	under := func(prefix string) bool {
		prefix = strings.Trim(prefix, "/")
		return prefix == "" || page == prefix || strings.HasPrefix(page, prefix+"/")
	}
	if len(a.Pages) > 0 {
		ok := false
		for _, p := range a.Pages {
			if under(p) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for _, p := range a.Exclude {
		if under(p) {
			return false
		}
	}
	return true
}

// Propose turns a model's request into an offer, or refuses it.
//
// The model names an action and supplies arguments. Only a declared action
// is offered; only its declared fields are kept, each bounded and made one
// line. What comes back is shown to the visitor, who decides — nothing runs
// here.
func (a Assistant) Propose(call ActionCall) (Proposal, error) {
	for _, ac := range a.Actions {
		if ac.Name != call.Name {
			continue
		}
		p := Proposal{Action: ac}
		if ac.Kind == Form {
			allowed := map[string]bool{}
			for _, f := range ac.Fields {
				allowed[f] = true
			}
			for k, v := range call.Args {
				if !allowed[k] {
					continue
				}
				v = oneLine(v)
				if len(v) > MaxArg {
					v = v[:MaxArg]
				}
				if p.Args == nil {
					p.Args = map[string]string{}
				}
				p.Args[k] = v
			}
		}
		return p, nil
	}
	return Proposal{}, fmt.Errorf("%q is not an action this assistant has",
		call.Name)
}

// Set is every assistant a site declares.
type Set struct {
	Assistants []Assistant `json:"assistants"`
}

// Get finds one by name.
func (s *Set) Get(name string) (Assistant, bool) {
	for _, a := range s.Assistants {
		if a.Name == name {
			return a, true
		}
	}
	return Assistant{}, false
}

// Put adds or replaces one, after validating it.
func (s *Set) Put(a Assistant) error {
	if err := a.Validate(); err != nil {
		return err
	}
	for i := range s.Assistants {
		if s.Assistants[i].Name == a.Name {
			s.Assistants[i] = a
			return nil
		}
	}
	s.Assistants = append(s.Assistants, a)
	sort.Slice(s.Assistants, func(i, j int) bool {
		return s.Assistants[i].Name < s.Assistants[j].Name
	})
	return nil
}

// Remove deletes one.
func (s *Set) Remove(name string) bool {
	for i := range s.Assistants {
		if s.Assistants[i].Name == name {
			s.Assistants = append(s.Assistants[:i], s.Assistants[i+1:]...)
			return true
		}
	}
	return false
}

// Load reads a set; a missing file is an empty set.
func Load(path string) (*Set, error) {
	s := &Set{}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("%s is not a set of assistants: %w", path, err)
	}
	for _, a := range s.Assistants {
		if err := a.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return s, nil
}

// Save writes a set atomically.
func Save(path string, s *Set) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, b, 0o600)
}
