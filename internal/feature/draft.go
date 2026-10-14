// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/menu"
	"github.com/quilzo/quilzo/internal/schema"
)

// Drafting a feature from a sentence.
//
// A model may draft a package; it cannot install one, and the reader below
// decides what of its answer is kept. A model drafts only what describes
// content: types, collections, listings, forms, pages, menus and chatbots.
// It never drafts an agent, a webhook or anything else that reaches another
// server, because a host is something a person vouches for and not
// something a model makes up; those are added by a person, and the card
// shows them either way. Page sections are kept only when they are of a
// kind this program renders.

// draftedJSON is everything the reader accepts from a model.
type draftedJSON struct {
	Name        string                `json:"name"`
	Title       string                `json:"title"`
	Purpose     string                `json:"purpose"`
	Types       []schema.Type         `json:"types"`
	Collections []Collection          `json:"collections"`
	Listings    []listing.Listing     `json:"listings"`
	Forms       []form.Form           `json:"forms"`
	Pages       []Page                `json:"pages"`
	Menus       []menu.Menu           `json:"menus"`
	Chatbots    []assistant.Assistant `json:"chatbots"`
}

// DraftPrompt is the system prompt for drafting a package: the format, its
// limits, and the example, so the model writes what the reader keeps.
func DraftPrompt(sectionKinds []string) string {
	var b strings.Builder
	b.WriteString(`You design features for Quilzo, a content platform. A feature is a JSON package of building blocks that Quilzo already runs. Answer with one JSON object and nothing else.

Keys you may use, all optional except name, title and purpose:
- name: lower-case letters, digits and hyphens, starting with a letter.
- title: a few words. purpose: one or two plain sentences on what it is for.
- types: [{name, description, fields: [{name, kind, label, required, choices, max_len}]}]. A type is a flat list of fields. kind is one of text, longtext, number, boolean, date, url, email, slug, choice (needs choices) or list. Names are lower-case with underscores.
- collections: [{name, type}]: records of one of your types.
- listings: [{name, label, collection, where: [{field, match: "is", value}], fields, sort, rows}]: a query a page shows. Name the fields it shows.
- forms: [{name, label, intro, fields: [{name, label, kind, required, choices}], notice, purpose, basis, retention_days}]. Form field kinds: line, para, email, number, choice, agree. notice says what happens to the answers; basis is one of consent, contract, legal-obligation, vital-interests, public-task, legitimate-interests; consent needs a required agree field.
- pages: [{name, body: {title, members_only, sections: [...]}}]. Page names are lower-case words joined by hyphens. A section is an object with one key, its kind. To show a listing: {"listing": {"name": "LISTING"}}. To write prose: {"prose": {"title": "...", "paragraphs": ["...", "..."]}}.
- menus: [{name, label, items: [{id, label, kind: "page", target: PAGE, order}]}]: entries pointing at pages of this site.
- chatbots: [{name, title}].

Never add agents, webhooks, tools, hosts, URLs to other servers, secrets or access rules. Prefer members_only true for pages that list records about people. Keep it small: only what the request needs.
`)
	if len(sectionKinds) > 0 {
		b.WriteString("\nSection kinds this site renders: " + strings.Join(sectionKinds, ", ") + ".\n")
	}
	b.WriteString("\nAn example of a complete answer:\n")
	b.Write(draftExample())
	b.WriteString("\n")
	return b.String()
}

// draftExample is the example without its roles: a draft never holds
// access, so the model is not shown how to write it.
func draftExample() []byte {
	var p Package
	if err := json.Unmarshal(example, &p); err != nil {
		return bytes.TrimSpace(example)
	}
	p.Roles = nil
	b, err := json.MarshalIndent(&p, "", "  ")
	if err != nil {
		return bytes.TrimSpace(example)
	}
	return b
}

// ReadDraft reads a model's answer into a package, keeping only what a
// draft may hold, and says what it left out. by and from are its
// provenance: who asked, and what they asked for.
func ReadDraft(answer string, sectionKinds map[string]bool, by, from, model string, now time.Time) (*Package, []string, error) {
	answer = strings.TrimSpace(answer)
	// A model that wraps its JSON in a code fence is common enough to undo.
	if strings.HasPrefix(answer, "```") {
		answer = strings.TrimPrefix(strings.TrimPrefix(answer, "```json"), "```")
		if i := strings.LastIndex(answer, "```"); i >= 0 {
			answer = answer[:i]
		}
	}
	start, end := strings.Index(answer, "{"), strings.LastIndex(answer, "}")
	if start < 0 || end <= start {
		return nil, nil, fmt.Errorf("the model's answer holds no JSON object")
	}
	raw := []byte(answer[start : end+1])
	if len(raw) > MaxBytes {
		return nil, nil, fmt.Errorf("the model's draft is larger than a package may be")
	}
	var notes []string
	// Keys the reader does not keep are named, not silently lost.
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, nil, fmt.Errorf("the model's answer is not a JSON object: %w", err)
	}
	allowed := map[string]bool{"name": true, "title": true, "purpose": true, "types": true, "collections": true,
		"listings": true, "forms": true, "pages": true, "menus": true, "chatbots": true, "format": true, "version": true}
	var dropped []string
	for k := range keys {
		if !allowed[k] {
			dropped = append(dropped, k)
		}
	}
	sort.Strings(dropped)
	for _, k := range dropped {
		notes = append(notes, fmt.Sprintf("left out %q: a draft holds content blocks only; a person adds agents, webhooks and roles", k))
	}
	var d draftedJSON
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, notes, fmt.Errorf("the model's draft does not have a package's shape: %w", err)
	}
	for i := range d.Menus {
		kept := d.Menus[i].Items[:0]
		for _, it := range d.Menus[i].Items {
			if it.Kind == menu.External {
				notes = append(notes, fmt.Sprintf("menu %s: left out the entry %q, which points at another site", d.Menus[i].Name, it.Label))
				continue
			}
			kept = append(kept, it)
		}
		d.Menus[i].Items = kept
	}
	p := &Package{
		Format: Format, Name: d.Name, Version: "1.0.0", Title: d.Title, Purpose: d.Purpose,
		Made:  &Made{By: by, From: clip(from, 600), At: now.UTC(), Model: model},
		Types: d.Types, Collections: d.Collections, Listings: d.Listings, Forms: d.Forms,
		Menus: d.Menus, Chatbots: d.Chatbots,
	}
	for _, pg := range d.Pages {
		if pg.Body == nil {
			continue
		}
		if secs, ok := pg.Body["sections"].([]any); ok {
			var kept []any
			for _, s := range secs {
				m, ok := s.(map[string]any)
				if !ok || len(m) != 1 {
					notes = append(notes, fmt.Sprintf("page %s: left out a section that is not one kind", pg.Name))
					continue
				}
				for kind := range m {
					if sectionKinds != nil && !sectionKinds[kind] {
						notes = append(notes, fmt.Sprintf("page %s: left out a %q section, which this site does not render", pg.Name, kind))
						continue
					}
					kept = append(kept, s)
				}
			}
			pg.Body["sections"] = kept
		}
		p.Pages = append(p.Pages, pg)
	}
	return p, notes, nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
