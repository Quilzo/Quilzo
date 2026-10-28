// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import (
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/schema"
)

// The permission card: what a package can do, worked out from the package
// itself and never from what its author says about it, in the words a
// person approving it reads.
//
// The card also decides how many people must approve. One is enough for a
// feature that stores and shows ordinary content. Two are needed when it
// holds personal data, collects anything from the public, sends anything
// outside, or adds an agent that acts on its own: the same rule the
// installation already keeps for actions on other tools.

// Line is one statement on the card. Flag marks why it matters: "personal",
// "special" (GDPR Article 9 data), "public", "sends" or "acts".
type Line struct {
	Text string `json:"text"`
	Flag string `json:"flag,omitempty"`
}

// Card is the permission card.
type Card struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Title   string `json:"title"`
	Purpose string `json:"purpose"`
	MadeBy  string `json:"made_by,omitempty"`

	Stores   []Line `json:"stores,omitempty"`
	Collects []Line `json:"collects,omitempty"`
	Shows    []Line `json:"shows,omitempty"`
	Sends    []Line `json:"sends,omitempty"`
	Agents   []Line `json:"agents,omitempty"`
	Chatbots []Line `json:"chatbots,omitempty"`
	// Roles are the roles people can be given in it. None is held by anybody
	// until somebody who may grant access assigns it.
	Roles []Line `json:"roles,omitempty"`

	// Risk is low, medium or high.
	Risk string `json:"risk"`
	// Approvers is how many different people must approve the install.
	Approvers int `json:"approvers"`
	// Because is why it needs two, one reason per line.
	Because []string `json:"because,omitempty"`
}

// Words in a field's name that mark it as about a person. Matched as whole
// words of the name, split on underscores and hyphens.
var personalWords = map[string]bool{
	"name": true, "firstname": true, "lastname": true, "surname": true, "fullname": true,
	"phone": true, "mobile": true, "tel": true, "email": true, "address": true, "street": true,
	"postcode": true, "zip": true, "birth": true, "birthday": true, "dob": true, "age": true,
	"gender": true, "passport": true, "ssn": true, "national": true, "ip": true,
	"salary": true, "iban": true, "account": true, "person": true, "member": true,
	"customer": true, "employee": true, "student": true, "contact": true,
}

// Words that mark a special category under GDPR Article 9, or data most
// regimes treat as sensitive.
var specialWords = map[string]bool{
	"health": true, "medical": true, "diagnosis": true, "patient": true, "condition": true,
	"medication": true, "allergy": true, "disability": true, "religion": true, "faith": true,
	"ethnicity": true, "race": true, "biometric": true, "genetic": true, "sexual": true,
	"orientation": true, "union": true, "criminal": true, "conviction": true, "political": true,
}

func words(name string) []string {
	return strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return r == '_' || r == '-' || r == ' ' || r == '.'
	})
}

// fieldClass says whether a type's field holds personal or special data.
func fieldClass(f schema.Field) string {
	class := ""
	if f.Kind == schema.Email {
		class = "personal"
	}
	for _, w := range words(f.Name + " " + f.Label) {
		if specialWords[w] {
			return "special"
		}
		if personalWords[w] {
			class = "personal"
		}
	}
	return class
}

// MakeCard works out the card.
func (p *Package) MakeCard() Card {
	c := Card{Name: p.Name, Version: p.Version, Title: p.Title, Purpose: p.Purpose}
	if p.Made != nil {
		c.MadeBy = p.Made.By
		if p.Made.Model != "" {
			c.MadeBy += " with " + p.Made.Model
		}
	}
	because := map[string]bool{}
	need := func(why string) { because[why] = true }

	typeClass := map[string]string{}
	typeFields := map[string][]string{}
	for _, t := range p.Types {
		var personal, special []string
		for _, f := range t.Fields {
			switch fieldClass(f) {
			case "special":
				special = append(special, f.Name)
			case "personal":
				personal = append(personal, f.Name)
			}
			typeFields[t.Name] = append(typeFields[t.Name], f.Name)
		}
		switch {
		case len(special) > 0:
			typeClass[t.Name] = "special"
		case len(personal) > 0:
			typeClass[t.Name] = "personal"
		}
	}
	for _, col := range p.Collections {
		t := col.Type
		line := Line{Text: fmt.Sprintf("Records in %q, each a %q with %d fields (%s)",
			col.Name, t, len(typeFields[t]), strings.Join(typeFields[t], ", "))}
		switch typeClass[t] {
		case "special":
			line.Flag = "special"
			line.Text += "; some fields look like health, belief or other special-category data"
			need("it stores what looks like special-category personal data")
		case "personal":
			line.Flag = "personal"
			line.Text += "; some fields are about people"
			need("it stores personal data")
		}
		c.Stores = append(c.Stores, line)
	}
	for _, t := range p.Types {
		bound := false
		for _, col := range p.Collections {
			bound = bound || col.Type == t.Name
		}
		if !bound {
			c.Stores = append(c.Stores, Line{Text: fmt.Sprintf("A content type %q with %d fields, for pages", t.Name, len(t.Fields))})
		}
	}

	for _, f := range p.Forms {
		var fields []string
		for _, fl := range f.Fields {
			fields = append(fields, fl.Name)
		}
		keep := f.Retention()
		text := fmt.Sprintf("A form %q asks visitors for %s, kept %d days", f.Name, strings.Join(fields, ", "), int(keep.Hours()/24))
		if f.Purpose != "" {
			text += ", for: " + f.Purpose
		}
		c.Collects = append(c.Collects, Line{Text: text, Flag: "personal"})
		need("it collects what visitors type into a form")
	}

	listings := map[string]listing.Listing{}
	for _, l := range p.Listings {
		listings[l.Name] = l
	}
	for _, pg := range p.Pages {
		where := "on the public site, once published"
		flag := "public"
		if mo, _ := pg.Body["members_only"].(bool); mo {
			where = "to signed-in members, once published"
			flag = ""
		}
		text := fmt.Sprintf("Page %q, added to the draft, shown %s", pg.Name, where)
		for _, ln := range listing.On(pg.Body) {
			l, ok := listings[ln]
			if !ok {
				text += fmt.Sprintf("; it shows listing %q, which this package does not declare", ln)
				continue
			}
			shown := strings.Join(l.Fields, ", ")
			if l.Exposes() {
				shown = "every field"
			}
			text += fmt.Sprintf("; it lists %q records showing %s", l.Collection, shown)
			for _, col := range p.Collections {
				if col.Name == l.Collection && typeClass[col.Type] != "" && flag == "public" {
					flag = "personal"
					need("a public page lists records about people")
				}
			}
		}
		c.Shows = append(c.Shows, Line{Text: text, Flag: flag})
	}
	for _, m := range p.Menus {
		entries := "entries"
		if len(m.Items) == 1 {
			entries = "entry"
		}
		c.Shows = append(c.Shows, Line{Text: fmt.Sprintf("A menu %q with %d %s", m.Name, len(m.Items), entries)})
	}
	if p.Site != nil {
		// First, because a package that is a whole site is read as one.
		c.Shows = append([]Line{p.Site.siteLine()}, c.Shows...)
	}

	for _, h := range p.Webhooks {
		what := "every event"
		if len(h.Types) > 0 {
			what = strings.Join(h.Types, ", ")
		}
		c.Sends = append(c.Sends, Line{Text: fmt.Sprintf("Tells %s about %s, signed", h.URL, what), Flag: "sends"})
		need("it sends events to another server")
	}

	for _, m := range p.Agents {
		line, sends, acts := agentLine(m)
		c.Agents = append(c.Agents, line)
		for _, s := range sends {
			c.Sends = append(c.Sends, Line{Text: s, Flag: "sends"})
		}
		if len(sends) > 0 {
			need("an agent it adds reaches other servers")
		}
		if acts {
			need("an agent it adds acts without asking first")
		}
	}

	for _, a := range p.Chatbots {
		text := fmt.Sprintf("A chatbot %q answering visitors from published pages", a.Name)
		if a.Launcher != nil {
			text += ", offered on every page"
		}
		c.Chatbots = append(c.Chatbots, Line{Text: text, Flag: "public"})
	}

	for _, r := range p.Roles {
		ar := p.AppRole(r)
		text := fmt.Sprintf("Role %q, %s: %s", ar.Name, r.Title, strings.Join(ar.Grants, "; "))
		c.Roles = append(c.Roles, Line{Text: text})
	}

	for why := range because {
		c.Because = append(c.Because, why)
	}
	sort.Strings(c.Because)
	switch {
	case len(c.Because) == 0:
		c.Risk, c.Approvers = "low", 1
	case len(c.Because) >= 3 || because["it stores what looks like special-category personal data"] ||
		because["an agent it adds acts without asking first"]:
		c.Risk, c.Approvers = "high", 2
	default:
		c.Risk, c.Approvers = "medium", 2
	}
	return c
}

// agentLine describes an agent: what it may do, where it reaches, and
// whether it acts without asking.
func agentLine(m agent.Manifest) (Line, []string, bool) {
	text := fmt.Sprintf("Agent %q (%s): %s. Autonomy %s", m.Name, m.Kind, m.Purpose, m.Autonomy)
	if len(m.Capabilities) > 0 {
		text += "; may " + strings.Join(m.Capabilities, ", ")
	}
	if len(m.AskFirst) > 0 {
		text += "; asks a person before " + strings.Join(m.AskFirst, ", ")
	}
	if m.Budget.Money != "" {
		text += "; spends at most " + m.Budget.Money + " a run"
	}
	var sends []string
	for _, t := range m.Tools {
		s := fmt.Sprintf("Agent %q calls tool %q at %s", m.Name, t.Name, t.Host)
		if t.Writes {
			s += ", which changes things there"
		}
		sends = append(sends, s)
	}
	if m.Browser != nil {
		if len(m.Browser.Read) > 0 {
			sends = append(sends, fmt.Sprintf("Agent %q reads web pages on %s", m.Name, strings.Join(m.Browser.Read, ", ")))
		}
		if len(m.Browser.Write) > 0 {
			sends = append(sends, fmt.Sprintf("Agent %q fills in and presses things on %s", m.Name, strings.Join(m.Browser.Write, ", ")))
		}
	}
	if m.Shell != nil && len(m.Shell.Hosts) > 0 {
		sends = append(sends, fmt.Sprintf("Agent %q runs commands that reach %s", m.Name, strings.Join(m.Shell.Hosts, ", ")))
	}
	if m.Program != nil {
		text += "; runs its own program, confined"
	}
	acts := m.Autonomy == agent.AutonomyPublish ||
		(m.Autonomy == agent.AutonomyDraft && len(m.AskFirst) == 0 && !m.HumanApproval && len(sends) > 0)
	line := Line{Text: text}
	if acts {
		line.Flag = "acts"
	}
	return line, sends, acts
}
