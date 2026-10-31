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

// Place names the section the way a person counts them, from one.
func (b Box) Place() string {
	where := fmt.Sprintf("section %d", b.At+1)
	if b.Title != "" {
		where += fmt.Sprintf(" (%s)", b.Title)
	}
	return where
}

// String is where the box is and what is wrong with it.
func (b Box) String() string { return b.Place() + ": " + b.Why }

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

// FirstPublic is the name of the first chatbot in this set visitors can
// reach, or nothing when there is none: what a new question box opens
// rather than a name the site may not have.
func (s *Set) FirstPublic() string {
	for _, a := range s.Assistants {
		if a.Public {
			return a.Name
		}
	}
	return ""
}

// Taking a chatbot away from the boxes that open it.
//
// Publishing asks a page whether its boxes open something, which is the half
// of the question a page can answer. The other half is the chatbot's.
// Removing one, or making it private, breaks every box that opens it at
// once, on the live site as much as in the draft, and nothing is published
// for the publish gate to refuse. So the change is refused instead, while a
// box still opens the chatbot, as a menu is refused while it points at a
// page that does not exist, and the refusal names the page and the section.

// PublicNames is the chatbots in this set that visitors can reach.
func (s *Set) PublicNames() map[string]bool {
	out := map[string]bool{}
	for _, a := range s.Assistants {
		if a.Public {
			out[a.Name] = true
		}
	}
	return out
}

// Withdrawing is the chatbots public in was, as PublicNames had them before
// a change, that this set leaves out or makes private, by name.
func (s *Set) Withdrawing(was map[string]bool) []string {
	var out []string
	for name := range was {
		if a, ok := s.Get(name); !ok || !a.Public {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// Withdrawn is the error for a change that would leave question boxes
// opening a chatbot it takes away from visitors.
type Withdrawn struct {
	// Names are the chatbots taken away that a box still opens.
	Names []string
	// Where is each box, as "the live page index, section 2 (Ask us), opens
	// help", live pages first.
	Where []string
}

func (e *Withdrawn) Error() string {
	it := "it"
	if len(e.Names) > 1 {
		it = "them"
	}
	return fmt.Sprintf("a question box still opens %s, so removing %s or "+
		"making %s private would answer every question asked there \"not "+
		"found\": %s. Point each box at another public chatbot or take it "+
		"out first, and publish that where the box is on a live page",
		strings.Join(e.Names, " and "), it, it, strings.Join(e.Where, "; "))
}

// Withdraws refuses a change to the chatbots that would leave a question
// box on these pages opening one that visitors could reach before it: was
// is PublicNames before the change, this set is after it, and live and
// draft are the site's pages, either of them empty when it has none yet.
//
// Only what the change takes away. A box that opened nothing before it is
// publishing's to refuse, and refusing an unrelated change over it would
// make every chatbot unchangeable until somebody else's draft was mended.
func (s *Set) Withdraws(was map[string]bool, live, draft map[string]any) error {
	gone := map[string]bool{}
	for _, name := range s.Withdrawing(was) {
		gone[name] = true
	}
	if len(gone) == 0 {
		return nil
	}
	e := &Withdrawn{}
	named := map[string]bool{}
	for _, side := range []struct {
		which string
		pages map[string]any
	}{{"live", live}, {"draft", draft}} {
		for _, b := range Boxes(side.pages, s.Get) {
			if !gone[b.Names] {
				continue
			}
			e.Where = append(e.Where, fmt.Sprintf("the %s page %s, %s, opens %s",
				side.which, b.Page, b.Place(), b.Names))
			if !named[b.Names] {
				named[b.Names] = true
				e.Names = append(e.Names, b.Names)
			}
		}
	}
	if len(e.Where) == 0 {
		return nil
	}
	sort.Strings(e.Names)
	return e
}
