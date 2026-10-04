// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package assistant

import (
	"encoding/json"
	"fmt"
	"net/url"
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
	// Documents are files from the media library it may also read, by id.
	// Chosen one by one: the library holds drafts, contracts and whatever
	// else somebody uploaded, and none of it is knowledge until an owner
	// says so.
	Documents []string `json:"documents,omitempty"`
	// Embed are the sites allowed to show it in a frame, as origins like
	// https://shop.example. Empty means it can be framed by nobody but this
	// site, which is the safe default for a page that takes input.
	Embed []string `json:"embed,omitempty"`
	// Handoff lets a visitor ask for a person. The conversation that follows
	// is the one thing about an assistant that is stored, from the moment
	// the visitor chooses it, and it is answered from the admin's inbox.
	Handoff bool `json:"handoff,omitempty"`
	// HandoffDays is how long such a conversation is kept after it last
	// moved. Zero is the default of thirty; at most ninety.
	HandoffDays int `json:"handoff_days,omitempty"`
	// Static lets a static copy of the site answer too: `ipfs write` and
	// `export` carry the conversation page and the passages it answers
	// from, and the visitor's browser does the answering. Published pages
	// only, because the passages ship as a file anybody can download, and a
	// document is knowledge the owner chose to quote from, not to publish.
	// Extractive only, because a static host has no model to ask.
	Static bool `json:"static,omitempty"`
	// Voice lets a visitor ask by speaking and hear the answer read out,
	// both on their own device: the microphone is offered only where the
	// browser recognises speech on the device, and only local voices read.
	// Nothing a visitor says reaches this server or anybody else's; what
	// arrives is the question as text, as if typed.
	Voice bool `json:"voice,omitempty"`
	// Translate answers in the visitor's language: their browser translates
	// the question into the site's language and the answer back, on the
	// device, and says so. The answer is still the site's own, checked
	// against its pages in the site's language; the translation is shown as
	// one, with the original a click away.
	Translate bool `json:"translate,omitempty"`
	// Launcher puts the assistant on the site's pages: a button in a corner
	// that opens it in a panel, without leaving the page. Nil is no launcher.
	Launcher *Launcher `json:"launcher,omitempty"`
}

// Launcher is how an assistant appears on the site's pages.
//
// Without a script the button is a link to the conversation page, so it
// works for everybody; with one, the conversation opens beside the page.
type Launcher struct {
	// Style is "bubble" (a round button), "pill" (a button with a label) or
	// "tab" (a tab on the edge of the window).
	Style string `json:"style,omitempty"`
	// Side is "right" or "left".
	Side string `json:"side,omitempty"`
	// Label is what a pill or a tab says. Default "Ask".
	Label string `json:"label,omitempty"`
	// Panel is "float", over the corner of the page, or "side", docked
	// beside it with the page moved over to make room.
	Panel string `json:"panel,omitempty"`
	// Pages limits the launcher to pages under these prefixes.
	Pages []string `json:"pages,omitempty"`
	// Suggestions are questions offered before the first one is asked.
	Suggestions []string `json:"suggestions,omitempty"`
	// Nudge is a short line shown beside the button after a while, once a
	// visit, until the visitor dismisses it. Empty is no nudge, which is
	// the default: an interruption has to be chosen.
	Nudge string `json:"nudge,omitempty"`
	// NudgeAfter is how many seconds a page is open before the nudge
	// shows. Default 20.
	NudgeAfter int `json:"nudge_after,omitempty"`
	// NudgePages limits the nudge to pages under these prefixes.
	NudgePages []string `json:"nudge_pages,omitempty"`
}

// Limits on a launcher.
const (
	MaxSuggestions   = 4
	MaxSuggestionLen = 80
	MaxNudgeLen      = 120
	MaxLauncherLabel = 24
)

// Normalised is the launcher with its defaults filled in.
func (l Launcher) Normalised() Launcher {
	if l.Style == "" {
		l.Style = "bubble"
	}
	if l.Side == "" {
		l.Side = "right"
	}
	if l.Panel == "" {
		l.Panel = "float"
	}
	if strings.TrimSpace(l.Label) == "" {
		l.Label = "Ask"
	}
	if l.NudgeAfter == 0 {
		l.NudgeAfter = 20
	}
	return l
}

// On reports whether the launcher appears on the page at path.
func (l Launcher) On(path string) bool { return underAny(path, l.Pages) }

// NudgeOn reports whether the nudge may show on the page at path.
func (l Launcher) NudgeOn(path string) bool {
	if strings.TrimSpace(l.Nudge) == "" || !l.On(path) {
		return false
	}
	return underAny(path, l.NudgePages)
}

func underAny(path string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		if path == p || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/") || p == "/" {
			return true
		}
	}
	return false
}

func (l Launcher) validate(name string, public bool) error {
	if !public {
		return fmt.Errorf("%s has a launcher but is not public; the launcher opens what the site serves", name)
	}
	switch l.Style {
	case "", "bubble", "pill", "tab":
	default:
		return fmt.Errorf("%s's launcher style %q is not bubble, pill or tab", name, l.Style)
	}
	switch l.Side {
	case "", "right", "left":
	default:
		return fmt.Errorf("%s's launcher side %q is not right or left", name, l.Side)
	}
	switch l.Panel {
	case "", "float", "side":
	default:
		return fmt.Errorf("%s's panel %q is not float or side", name, l.Panel)
	}
	if len([]rune(l.Label)) > MaxLauncherLabel {
		return fmt.Errorf("%s's launcher label is over %d characters", name, MaxLauncherLabel)
	}
	if len(l.Suggestions) > MaxSuggestions {
		return fmt.Errorf("%s offers %d suggestions, over %d", name, len(l.Suggestions), MaxSuggestions)
	}
	for _, q := range l.Suggestions {
		if strings.TrimSpace(q) == "" || len([]rune(q)) > MaxSuggestionLen {
			return fmt.Errorf("%s's suggestion %q is empty or over %d characters", name, q, MaxSuggestionLen)
		}
	}
	if len([]rune(l.Nudge)) > MaxNudgeLen {
		return fmt.Errorf("%s's nudge is over %d characters; a nudge is a line, not a message", name, MaxNudgeLen)
	}
	if l.NudgeAfter != 0 && (l.NudgeAfter < 5 || l.NudgeAfter > 600) {
		return fmt.Errorf("%s's nudge waits %d seconds; between 5 and 600, so it never arrives with the page", name, l.NudgeAfter)
	}
	for _, list := range [][]string{l.Pages, l.NudgePages} {
		for _, p := range list {
			if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#\\") || strings.Contains(p, "..") {
				return fmt.Errorf("%q is not a page prefix: it starts with / and names a path", p)
			}
		}
	}
	return nil
}

// MaxHandoffDays is the longest a handed-off conversation may be kept.
const MaxHandoffDays = 90

// Keep is how long a handed-off conversation is kept after it last moved.
func (a Assistant) Keep() int {
	if a.HandoffDays <= 0 {
		return 30
	}
	return a.HandoffDays
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
	MaxDocuments    = 50
	MaxEmbed        = 10
)

var reDocID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Origin checks and normalises a site allowed to embed an assistant.
//
// HTTPS, a host, and nothing else: no path, no wildcard, no query. The value
// lands in a frame-ancestors directive, where a wildcard would let any site
// frame a page that takes input — the setup for clickjacking a visitor into
// sending a form — and a stray semicolon would end the directive and start
// another. http is allowed for localhost only, so an owner can try it.
func Origin(o string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(o))
	bad := func() (string, error) {
		return "", fmt.Errorf("%q is not a site that can embed a chatbot: "+
			"write it as https://example.com", o)
	}
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(o, "*; '\"\\") {
		return bad()
	}
	host := u.Hostname()
	switch u.Scheme {
	case "https":
	case "http":
		if host != "localhost" && host != "127.0.0.1" {
			return bad()
		}
	default:
		return bad()
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), nil
}

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
	if len(a.Documents) > MaxDocuments {
		return fmt.Errorf("%s reads %d documents, over %d", a.Name,
			len(a.Documents), MaxDocuments)
	}
	for _, id := range a.Documents {
		if !reDocID.MatchString(id) {
			return fmt.Errorf("%q is not a media library id", id)
		}
	}
	if len(a.Embed) > MaxEmbed {
		return fmt.Errorf("%s may be embedded by %d sites, over %d", a.Name,
			len(a.Embed), MaxEmbed)
	}
	for _, o := range a.Embed {
		if _, err := Origin(o); err != nil {
			return err
		}
	}
	if a.Static && !a.Public {
		return fmt.Errorf("%s answers on a static copy but is not public; "+
			"a static copy carries only what the live site serves", a.Name)
	}
	if a.HandoffDays < 0 || a.HandoffDays > MaxHandoffDays {
		return fmt.Errorf("%s keeps conversations for %d days; between 1 and "+
			"%d, or 0 for the default of thirty", a.Name, a.HandoffDays,
			MaxHandoffDays)
	}
	if a.Launcher != nil {
		if err := a.Launcher.validate(a.Name, a.Public); err != nil {
			return err
		}
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

// Launcher is the assistant that appears on the site's pages: the one
// public assistant with a launcher. A site has at most one, so two buttons
// never compete for the same corner.
func (s *Set) Launcher() (Assistant, bool) {
	for _, a := range s.Assistants {
		if a.Public && a.Launcher != nil {
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
	if a.Launcher != nil {
		for _, other := range s.Assistants {
			if other.Name != a.Name && other.Launcher != nil {
				return fmt.Errorf("%s already has the launcher; a site shows one, so take it off %s first", other.Name, other.Name)
			}
		}
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
