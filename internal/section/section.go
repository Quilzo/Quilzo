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
	"strings"
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
			// Empty, so the field is there to fill in and the picker appears
			// beside it. A stub with no image key at all is what this had, and
			// the kind whose summary begins "An image beside prose" was one
			// you could not put an image in.
			"image": "", "alt": "",
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
			// No image. A stub pointing at a placeholder path publishes a
			// broken picture, which is worse than an empty section — found by
			// driving the Telegram editor and publishing what it produced.
			// The picker is how a file gets attached.
			"items": []any{
				map[string]any{"image": "",
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
			// Each card can carry a picture, so each card has the field and
			// the picker beside it. Empty rather than a path: a stub naming a
			// file no store holds publishes a broken picture.
			"items": []any{
				map[string]any{"title": "First", "body": "One card.",
					"image": "", "alt": ""},
				map[string]any{"title": "Second", "body": "Another.",
					"image": "", "alt": ""},
				map[string]any{"title": "Third", "body": "And a third.",
					"image": "", "alt": ""},
			},
		},
	},
	{
		Name: "video", Group: "media", Summary: "One video from this origin. Controls always, autoplay never.",
		Stub: map[string]any{
			"title": "Watch this",
			// No path. This said /media/replace-me.mp4, which no store holds:
			// adding a video section and publishing produced a player that
			// could not play anything, and the layout omits the element
			// entirely when there is nothing to put in it. The picker is how a
			// file gets attached.
			"src":     "",
			"poster":  "",
			"caption": "A caption. A transcript link belongs here too.",
		},
	},
	{
		Name: "people", Group: "media", Summary: "Names, roles and portraits.",
		Stub: map[string]any{
			"title": "Who we are",
			// A portrait field per person — the summary says portraits, and
			// without the key there is nowhere to choose one.
			"items": []any{
				map[string]any{"name": "A Name", "role": "What they do",
					"image": "", "alt": ""},
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

// MaxSections bounds a page's arrangement.
//
// A hundred is far past any page anybody designs and short of the point where
// rendering one is a cost worth thinking about. It exists so the number is a
// number rather than whatever a JSON file happened to contain.
const MaxSections = 100

// Problem is one thing wrong with a page's arrangement.
type Problem struct {
	// At is the section's position, or -1 for something about the page.
	At int
	// Detail is what is wrong, written for the person who wrote the page.
	Detail string
}

func (p Problem) String() string {
	if p.At < 0 {
		return p.Detail
	}
	return fmt.Sprintf("section %d: %s", p.At+1, p.Detail)
}

// Validate checks a page's arrangement against the catalogue.
//
// # Why a page's sections are checked and its fields are typed
//
// A section is not content of a kind somebody declared — it is one of a closed
// list this build ships, and which list that is has nothing to do with what the
// page is about. So a type cannot describe it and should not have to: a type
// with a "sections" field would be a type that has to be updated whenever a
// layout learns a new kind, in every site, and forgetting it would make an
// ordinary page unclassifiable.
//
// The consequence, before this existed, was that no page built the way the
// shipped layouts want could be typed at all — a hero is an object and sections
// are a list of objects, and the type system is flat by design. `posture scan`
// therefore reported every published page as untyped under a rule nothing could
// satisfy, and `quilzo type bind` was unusable for the product's own shape.
//
// # What is strict and what is not
//
// The kind is strict. A key that is not in the catalogue renders as nothing at
// all: a page with "gallry" on it is a page with a section missing and no
// message anywhere, which is the exact failure this closes.
//
// The fields inside are not. A layout may read a value the stub does not
// mention — a tone, a column count, whether an image is flipped — and refusing
// those would refuse pages that render correctly today. They are reported as
// advice, so a typo in a field name is visible without being fatal.
func Validate(body any) (blocking []Problem, advisory []Problem) {
	list, ok := sectionsOf(body)
	if !ok {
		// A page with no sections is not a page with a broken arrangement.
		return nil, nil
	}
	if len(list) > MaxSections {
		blocking = append(blocking, Problem{-1, fmt.Sprintf(
			"%d sections, and the limit is %d. Past that a page is not a page "+
				"and the render is unbounded", len(list), MaxSections)})
	}
	for i, entry := range list {
		m, isMap := entry.(map[string]any)
		if !isMap {
			blocking = append(blocking, Problem{i, fmt.Sprintf(
				"is %T, not an object naming one kind", entry)})
			continue
		}
		if len(m) == 0 {
			blocking = append(blocking, Problem{i, "is empty, so it names no kind"})
			continue
		}
		name, inner := discriminator(m)
		kind, known := Lookup(name)
		if !known {
			blocking = append(blocking, Problem{i, fmt.Sprintf(
				"%q is not a section kind, so this renders as nothing at all. "+
					"The kinds are: %s", name, strings.Join(Names(), ", "))})
			continue
		}
		if inner == nil {
			blocking = append(blocking, Problem{i, fmt.Sprintf(
				"%s carries %T rather than the fields of a section",
				name, m[name])})
			continue
		}
		// More than one kind on one entry is ambiguous: the first in catalogue
		// order renders and the rest are silently dropped.
		if len(m) > 1 {
			var also []string
			for k := range m {
				if k != name {
					also = append(also, k)
				}
			}
			sort.Strings(also)
			blocking = append(blocking, Problem{i, fmt.Sprintf(
				"names %s and also %s; one entry is one section, and only the "+
					"first would render", name, strings.Join(also, ", "))})
		}
		advisory = append(advisory, unknownFields(i, kind, inner)...)
	}
	return blocking, advisory
}

// unknownFields reports fields the stub for this kind does not mention.
//
// Advisory only. The stub is what a new section starts as, not the set of
// everything a layout reads, so a field absent from it may be perfectly good —
// and a page that renders correctly must not be refused because this list is
// shorter than the template's imagination.
func unknownFields(at int, kind Kind, inner map[string]any) []Problem {
	stub, ok := kind.Stub[kind.Name].(map[string]any)
	if !ok {
		// The stub is the section's inner object directly for some kinds.
		stub, ok = kind.Stub, true
	}
	if !ok || len(stub) == 0 {
		return nil
	}
	var out []Problem
	var unknown []string
	for k := range inner {
		if _, inStub := stub[k]; inStub {
			continue
		}
		if allowedAnywhere[k] {
			continue
		}
		unknown = append(unknown, k)
	}
	sort.Strings(unknown)
	for _, k := range unknown {
		out = append(out, Problem{at, fmt.Sprintf(
			"%s has no %q in its shipped shape. That may be a field your "+
				"layout reads, or it may be a typo nothing will render",
			kind.Name, k)})
	}
	return out
}

// allowedAnywhere are the presentation fields every kind accepts.
//
// Read by the shipped layouts on any section, so they are not typos and would
// otherwise be reported on every page that uses one.
var allowedAnywhere = map[string]bool{
	"tone": true, "align": true, "columns": true, "shape": true,
	"flip": true, "href": true, "featured": true, "chip": true,
	"chip_tone": true, "hint": true, "note": true, "footnote": true,
	"eyebrow": true, "intro": true, "title": true, "cta_label": true,
	"cta_href": true, "transcript_href": true, "transcript_label": true,
	"poster": true, "caption": true, "alt": true, "state": true,
}
