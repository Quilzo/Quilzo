// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assistant

import (
	"fmt"
	"sort"
	"strings"
)

// Question boxes: the sections that open a chatbot from a page.
//
// An ask section is a form whose action is /ask/NAME/, and the page renders
// whatever name it carries. A box naming a chatbot that does not exist, or
// one that is not public, is a box every visitor can type a question into
// and every visitor is answered "not found" from: the public site gives one
// answer for both, so that the route is not a way to learn what an owner is
// still building. Nothing about saving the page or publishing it said so.
//
// Checked where pages go live rather than where they are saved, for the
// reason a listing's name is: a box written before its chatbot still saves,
// as a draft, and the refusal arrives where it matters, naming the page and
// the section.

// SectionKind is the section a page uses to put a question box somewhere.
//
// Spelled here rather than imported, as internal/listing spells its own:
// this package does not depend on the page builder to say what a page asks
// of it. A test checks this against the catalogue in internal/section.
const SectionKind = "ask"

// BoxField is the field of that section naming the chatbot it opens.
const BoxField = "assistant"

// sectionsField is where a page keeps its sections. See internal/section.Field.
const sectionsField = "sections"

// Box is a question box that opens a chatbot visitors cannot reach.
type Box struct {
	Page string
	// At is the section's position on the page, from 0.
	At int
	// Title is the section's own heading, when it has one, so that the
	// person told about it can find it on a page with more than one.
	Title string
	// Names is the chatbot it opens, as written; empty when it names none.
	Names string
	// Why is what is wrong, written for the person who wrote the page.
	Why string
}

// String names the section the way a person counts them, from one.
func (b Box) String() string {
	where := fmt.Sprintf("section %d", b.At+1)
	if b.Title != "" {
		where += fmt.Sprintf(" (%s)", b.Title)
	}
	return where + ": " + b.Why
}

// Boxes is every question box on these pages that opens a chatbot visitors
// cannot reach, page by page in name order.
//
// find is how a name becomes a chatbot: a site's declared set, or, while a
// package is being installed, the package's own chatbots before the site's.
// It is asked only about boxes that name something, so a caller that reads
// a file to answer it reads nothing for a site with no question boxes.
func Boxes(pages map[string]any, find func(name string) (Assistant, bool)) []Box {
	names := make([]string, 0, len(pages))
	for name := range pages {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []Box
	for _, page := range names {
		m, ok := pages[page].(map[string]any)
		if !ok {
			continue
		}
		list, _ := m[sectionsField].([]any)
		for i, entry := range list {
			sec, _ := entry.(map[string]any)
			inner, isBox := sec[SectionKind].(map[string]any)
			if !isBox {
				continue
			}
			b := Box{Page: page, At: i}
			b.Title, _ = inner["title"].(string)
			// As written, not trimmed: the page puts it into the address as
			// it is, so " help" opens nothing even though "help" exists.
			b.Names, _ = inner[BoxField].(string)
			if strings.TrimSpace(b.Names) == "" {
				b.Why = "the question box names no chatbot, so it opens " +
					"nothing. Set its assistant to one of the site's public chatbots"
				out = append(out, b)
				continue
			}
			a, found := find(b.Names)
			switch {
			case !found:
				b.Why = fmt.Sprintf("the question box opens the chatbot %q, "+
					"which does not exist, so every question asked in it is "+
					"answered \"not found\"", b.Names)
			case !a.Public:
				b.Why = fmt.Sprintf("the question box opens the chatbot %s, "+
					"which is not public, so every question asked in it is "+
					"answered \"not found\". Make it public, or name one that is",
					b.Names)
			default:
				continue
			}
			out = append(out, b)
		}
	}
	return out
}

// Boxes is Boxes against this set.
func (s *Set) Boxes(pages map[string]any) []Box { return Boxes(pages, s.Get) }
