// Package section is the page-builder half of the design: what a section is,
// and the four things you can do to one.
//
// # Why this is a package rather than a screen
//
// Because there are three interfaces and the operation has to be the same in
// all of them. Reordering a page is the thing people most want to do to a
// design and the thing the browser could not do at all: sections are content,
// so the terminal could always edit the JSON, and somebody who only ever opens
// the admin had no way to move a block down.
//
// Putting the moves here rather than in the handler means the screen, the
// command and the agent surface share one implementation of "insert at", and a
// bug in the index arithmetic is a bug in one place. It also means the moves
// are testable without a server.
//
// # Why a stub rather than an empty block
//
// Adding a section inserts a small piece of real content — a heading and an
// item or two — rather than an empty object. An empty section renders as
// nothing, so a screen that says "added" and a page that looks identical is a
// screen nobody trusts. The stub renders immediately, and every field in it is
// one somebody is about to overwrite.
//
// # Why the catalogue is checked against the markup
//
// A kind listed here that the layout does not implement is a section somebody
// can add and never see. A kind the layout implements and this does not list is
// a feature nobody can reach. Neither is detectable by reading one file, so a
// test in internal/starter reads both and fails on either — the same argument
// as the sample content that has to fill every field a starter declares.
package section

import (
	"fmt"
	"sort"
)

// Field is the key a page's sections live under.
const Field = "sections"

// Kind is one section type, and what to write when somebody adds it.
type Kind struct {
	// Name is the discriminator key. A section is a one-key object naming its
	// kind, because the template language has no way to compare values — so
	// the presence of the key *is* the type test.
	Name string
	// Summary is what it is for, in the words somebody choosing would use.
	Summary string
	// Group orders the list on a screen: what a page opens with, what carries
	// data, what carries media, what closes it.
	Group string
	// Stub is the content written when this kind is added.
	Stub map[string]any
}

// kinds is the catalogue, in the order somebody building a page reads it.
var kinds = []Kind{
	{
		Name: "features", Group: "telling", Summary: "A grid of cards, two to four across, optionally linked.",
		Stub: map[string]any{
			"title": "What you get", "columns": "3",
			"items": []any{
				map[string]any{"title": "First thing", "body": "Say what it is and why it matters."},
				map[string]any{"title": "Second thing", "body": "Two sentences is usually enough."},
				map[string]any{"title": "Third thing", "body": "Three cards read better than four."},
			},
		},
	},
	{
		Name: "split", Group: "telling", Summary: "An image beside prose. Set flip to put the image on the other side.",
		Stub: map[string]any{
			"eyebrow": "How it works", "title": "One idea, with a picture",
			"paragraphs": []any{
				"A split section takes a heading and any number of paragraphs.",
				"Leave the image out and it is prose at full width.",
			},
		},
	},
	{
		Name: "steps", Group: "telling", Summary: "A numbered sequence. Numbered because the order carries the meaning.",
		Stub: map[string]any{
			"title": "How it works",
			"items": []any{
				map[string]any{"title": "First", "body": "What somebody does first."},
				map[string]any{"title": "Then", "body": "And then this."},
				map[string]any{"title": "Finally", "body": "And it is done."},
			},
		},
	},
	{
		Name: "timeline", Group: "telling", Summary: "Dated entries down a rule: a changelog, a history, a roadmap.",
		Stub: map[string]any{
			"title": "What changed",
			"items": []any{
				map[string]any{"date": "2026-01-01", "title": "Something happened",
					"body": "A sentence about it."},
			},
		},
	},
	{
		Name: "prose", Group: "telling", Summary: "Paragraphs at a readable measure, with an optional heading.",
		Stub: map[string]any{
			"title": "A heading",
			"paragraphs": []any{
				"Replace this with the prose the section is actually for.",
				"It is a list of paragraphs rather than one rich-text field, so nothing here needs unescaped output.",
			},
		},
	},
	{
		Name: "faq", Group: "telling", Summary: "Questions that open and close. No script: it is details and summary.",
		Stub: map[string]any{
			"title": "Questions",
			"items": []any{
				map[string]any{"q": "A question somebody actually asks?",
					"a": "The answer, in a sentence or two."},
			},
		},
	},

	{
		Name: "metrics", Group: "data", Summary: "Labelled figures with a change and a bar. For a dashboard.",
		Stub: map[string]any{
			"title": "This month",
			"items": []any{
				map[string]any{"label": "A figure", "value": "1,284",
					"delta": "+18%", "state": "positive", "pct": 72},
				map[string]any{"label": "Another", "value": "310ms",
					"delta": "-40ms", "state": "positive", "pct": 34},
			},
		},
	},
	{
		Name: "bars", Group: "data", Summary: "A horizontal bar chart. Percentages come from the content, already worked out.",
		Stub: map[string]any{
			"title": "Where it came from",
			"items": []any{
				map[string]any{"name": "First", "amount": "48%", "pct": 48},
				map[string]any{"name": "Second", "amount": "31%", "pct": 31},
				map[string]any{"name": "Third", "amount": "21%", "pct": 21, "state": "caution"},
			},
		},
	},
	{
		Name: "donuts", Group: "data", Summary: "Ring charts, drawn with one gradient each.",
		Stub: map[string]any{
			"title": "Proportions",
			"items": []any{
				map[string]any{"pct": 82, "value": "82%", "label": "of the thing"},
				map[string]any{"pct": 61, "value": "61%", "label": "of the other"},
			},
		},
	},
	{
		Name: "table", Group: "data", Summary: "A data table with a caption and column headers.",
		Stub: map[string]any{
			"title": "The numbers", "caption": "What this table is of.",
			"columns": []any{"Name", "Value", "State"},
			"rows": []any{
				map[string]any{"cells": []any{"A row", "42", "fine"}},
				map[string]any{"cells": []any{"Another", "17", "watch"}},
			},
		},
	},
	{
		Name: "pricing", Group: "data", Summary: "Plan columns, one of them marked as featured.",
		Stub: map[string]any{
			"title": "Plans", "intro": "Say what the difference between them is.",
			"items": []any{
				map[string]any{"name": "Small", "price": "£0", "period": "/month",
					"body": "For one person.", "features": []any{"A thing", "Another thing"},
					"cta_label": "Start", "cta_href": "/start"},
				map[string]any{"name": "Larger", "price": "£24", "period": "/month",
					"featured": "featured", "body": "For a team.",
					"features":  []any{"Everything in Small", "And more"},
					"cta_label": "Choose this", "cta_href": "/start"},
			},
		},
	},

	{
		Name: "gallery", Group: "media", Summary: "A grid of pictures with captions, optionally linked.",
		Stub: map[string]any{
			"title": "Pictures", "shape": "square",
			"items": []any{
				map[string]any{"image": "/media/replace-me.png",
					"alt":     "Describe what is in the picture, for somebody who cannot see it",
					"caption": "A caption"},
			},
		},
	},
	{
		Name: "carousel", Group: "media", Summary: "A sideways scrolling row. Scroll-snap, no script, cannot advance on its own.",
		Stub: map[string]any{
			"title": "A row of things",
			"hint":  "Scroll sideways for more.",
			"items": []any{
				map[string]any{"title": "First", "body": "One card."},
				map[string]any{"title": "Second", "body": "Another."},
				map[string]any{"title": "Third", "body": "And a third."},
			},
		},
	},
	{
		Name: "video", Group: "media", Summary: "One video from this origin. Controls always, autoplay never.",
		Stub: map[string]any{
			"title":   "Watch this",
			"src":     "/media/replace-me.mp4",
			"caption": "A caption. A transcript link belongs here too.",
		},
	},
	{
		Name: "people", Group: "media", Summary: "Names, roles and portraits.",
		Stub: map[string]any{
			"title": "Who we are",
			"items": []any{
				map[string]any{"name": "A Name", "role": "What they do"},
			},
		},
	},
	{
		Name: "logos", Group: "media", Summary: "Wordmarks as type, because a logo strip of remote images is a row of requests to other people's servers.",
		Stub: map[string]any{
			"title": "In use at",
			"items": []any{"One", "Two", "Three", "Four"},
		},
	},

	{
		Name: "quote", Group: "closing", Summary: "A pulled quote with an attribution.",
		Stub: map[string]any{
			"text": "Something somebody actually said.",
			"by":   "Who said it", "role": "and what they do",
		},
	},
	{
		Name: "notice", Group: "closing", Summary: "A short banner in one of four tones: plain, positive, caution, critical.",
		Stub: map[string]any{
			"tone": "caution", "title": "Something worth saying at the top",
			"body": "One or two sentences.",
		},
	},
	{
		Name: "cta", Group: "closing", Summary: "A closing call to action, on the accent surface.",
		Stub: map[string]any{
			"title": "What next", "body": "Tell somebody the one thing to do.",
			"cta_label": "Do it", "cta_href": "/start",
		},
	},
}

// Kinds returns the catalogue, in reading order.
func Kinds() []Kind {
	out := make([]Kind, len(kinds))
	copy(out, kinds)
	return out
}

// Names lists the kinds alphabetically, for a message that has to be terse.
func Names() []string {
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, k.Name)
	}
	sort.Strings(out)
	return out
}

// Lookup returns one kind.
func Lookup(name string) (Kind, bool) {
	for _, k := range kinds {
		if k.Name == name {
			return k, true
		}
	}
	return Kind{}, false
}

// Groups lists the group names in catalogue order.
func Groups() []string {
	var out []string
	seen := map[string]bool{}
	for _, k := range kinds {
		if seen[k.Group] {
			continue
		}
		seen[k.Group] = true
		out = append(out, k.Group)
	}
	return out
}

// Placed is one section on a page, with where it is and what it is.
type Placed struct {
	Index int    `json:"index"`
	Kind  string `json:"kind"`
	// Label is a line of the section's own content, so a list of six sections
	// is readable rather than six rows saying "features". Empty when the
	// section carries nothing that names it.
	Label string `json:"label,omitempty"`
	// Items is how many entries it holds, for the kinds that hold a list.
	Items int `json:"items,omitempty"`
	// Unknown is true when the page names a kind the catalogue does not have.
	// Reported rather than hidden: it is either a kind somebody removed from a
	// layout or a typo, and both are things to see.
	Unknown bool `json:"unknown,omitempty"`
}

// On reads the sections off a page body.
func On(body any) []Placed {
	list, _ := sectionsOf(body)
	out := make([]Placed, 0, len(list))
	for i, entry := range list {
		m, ok := entry.(map[string]any)
		if !ok {
			out = append(out, Placed{Index: i, Kind: "?", Unknown: true})
			continue
		}
		name, inner := discriminator(m)
		p := Placed{Index: i, Kind: name}
		if _, known := Lookup(name); !known {
			p.Unknown = true
		}
		if inner != nil {
			p.Label = label(inner)
			if items, isList := inner["items"].([]any); isList {
				p.Items = len(items)
			}
			if paras, isList := inner["paragraphs"].([]any); isList && p.Items == 0 {
				p.Items = len(paras)
			}
		}
		out = append(out, p)
	}
	return out
}

// discriminator finds the one key that names a section's kind.
//
// A section is a single-key object. More than one key is ambiguous — the layout
// would render every kind it matched — so the first in catalogue order wins and
// the rest are reported by On as part of the same entry, deterministically
// rather than by map iteration order.
func discriminator(m map[string]any) (string, map[string]any) {
	for _, k := range kinds {
		if inner, ok := m[k.Name].(map[string]any); ok {
			return k.Name, inner
		}
		if _, present := m[k.Name]; present {
			return k.Name, nil
		}
	}
	// Not a kind this build knows. Report the key rather than nothing, so the
	// screen can say which one.
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "?", nil
	}
	return names[0], nil
}

// label picks the line that best names a section.
func label(inner map[string]any) string {
	for _, key := range []string{"title", "text", "name", "label", "caption"} {
		if v, ok := inner[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// Insert puts a new section of a kind at a position.
//
// A returned copy, never a mutation of the argument. The body comes out of the
// decoded content tree that other requests are reading, and writing into it
// would change what a concurrent render sees.
func Insert(body any, kind string, at int) (map[string]any, error) {
	k, known := Lookup(kind)
	if !known {
		return nil, fmt.Errorf(
			"there is no %q section. The kinds are: %v", kind, Names())
	}
	page, list := copyOf(body)
	if at < 0 || at > len(list) {
		at = len(list)
	}
	entry := any(map[string]any{k.Name: cloneValue(k.Stub)})
	next := make([]any, 0, len(list)+1)
	next = append(next, list[:at]...)
	next = append(next, entry)
	next = append(next, list[at:]...)
	page[Field] = next
	return page, nil
}

// Remove takes one section out.
func Remove(body any, at int) (map[string]any, error) {
	page, list := copyOf(body)
	if at < 0 || at >= len(list) {
		return nil, fmt.Errorf("there is no section %d; this page has %d",
			at, len(list))
	}
	next := make([]any, 0, len(list)-1)
	next = append(next, list[:at]...)
	next = append(next, list[at+1:]...)
	if len(next) == 0 {
		// An empty list and no list at all render the same, and the absent form
		// is the one that reads as "this page has no sections" in a diff.
		delete(page, Field)
		return page, nil
	}
	page[Field] = next
	return page, nil
}

// Move shifts one section by one position.
//
// By one rather than to an index, because the operation somebody performs is
// "further up" and an index is a translation they have to do in their head. A
// move off either end is refused rather than clamped: a button that does
// nothing is worse than one that is not offered, and the screen does not offer
// it.
func Move(body any, at, by int) (map[string]any, error) {
	page, list := copyOf(body)
	if at < 0 || at >= len(list) {
		return nil, fmt.Errorf("there is no section %d; this page has %d",
			at, len(list))
	}
	to := at + by
	if to < 0 || to >= len(list) {
		return nil, fmt.Errorf(
			"section %d cannot move %s; it is already at the %s",
			at, direction(by), edge(by))
	}
	next := make([]any, len(list))
	copy(next, list)
	next[at], next[to] = next[to], next[at]
	page[Field] = next
	return page, nil
}

func direction(by int) string {
	if by < 0 {
		return "up"
	}
	return "down"
}

func edge(by int) string {
	if by < 0 {
		return "top"
	}
	return "bottom"
}

// copyOf returns a shallow copy of a page body and its section list.
func copyOf(body any) (map[string]any, []any) {
	page := map[string]any{}
	if m, ok := body.(map[string]any); ok {
		for k, v := range m {
			page[k] = v
		}
	}
	list, _ := sectionsOf(body)
	return page, list
}

func sectionsOf(body any) ([]any, bool) {
	m, ok := body.(map[string]any)
	if !ok {
		return nil, false
	}
	list, isList := m[Field].([]any)
	return list, isList
}

// cloneValue deep-copies a stub, so two sections added from the same kind do not
// share the slices and maps inside it. Editing one would otherwise edit both,
// and the second one would appear to change on its own.
func cloneValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			out[k] = cloneValue(vv)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, vv := range t {
			out[i] = cloneValue(vv)
		}
		return out
	default:
		return v
	}
}
