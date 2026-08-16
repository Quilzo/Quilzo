package admin

import (
	"net/http"
	"strings"
)

// The documentation, in the product.
//
// Not a website, not a wiki, not a PDF somebody emails you. It ships in the
// binary and is served by the thing it describes, which has three consequences
// worth the file size: it cannot be a version behind, it works on an air-gapped
// deployment, and the "Help" link on every screen can point at the section
// about that screen rather than at a home page.
//
// That last one is why this is data rather than a folder of HTML. Each section
// has an anchor, the navigation table names an anchor per destination, and a
// test requires every named anchor to exist. A help link that lands on a
// heading that was renamed is worse than no help link, because the person
// following it concludes the feature was removed.

// section is one part of the documentation.
type section struct {
	// ID is the anchor. Stable: it is what the Help links point at, and
	// renaming one silently breaks every screen that names it.
	ID string
	// Title is the heading.
	Title string
	// Summary is one line, shown in the contents.
	Summary string
	// Body is the prose, as blocks.
	Body []block
}

// block is a piece of a section.
//
// A tiny vocabulary — paragraph, list, steps, table, code, note — rather than
// HTML in a Go string. The reason is the same one the template language has:
// content that is markup is content somebody eventually injects into. Here it
// is our own text, so the risk is lower, but the discipline buys something
// else — every block renders through one template, so the documentation cannot
// drift into eleven different visual treatments for the same idea.
type block struct {
	Kind string // "p", "list", "steps", "table", "code", "note", "warn", "sub"
	Text string // for p, code, note, warn, sub
	// Items is the content of a list or the ordered content of steps.
	Items []string
	// Head and Rows make a table.
	Head []string
	Rows [][]string
}

func p(text string) block         { return block{Kind: "p", Text: text} }
func sub(text string) block       { return block{Kind: "sub", Text: text} }
func note(text string) block      { return block{Kind: "note", Text: text} }
func warn(text string) block      { return block{Kind: "warn", Text: text} }
func code(text string) block      { return block{Kind: "code", Text: text} }
func list(items ...string) block  { return block{Kind: "list", Items: items} }
func steps(items ...string) block { return block{Kind: "steps", Items: items} }
func table(head []string, rows ...[]string) block {
	return block{Kind: "table", Head: head, Rows: rows}
}

// chapter groups sections in the contents.
type chapter struct {
	Name     string
	Sections []section
}

func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	// No permission check beyond being signed in. Documentation is not
	// privileged: somebody who cannot reach the security dashboard should
	// still be able to read what it would tell them and go and ask for it,
	// and a manual that is itself behind a permission is a manual nobody can
	// use to find out what permission they need.
	s.render(w, r, "docs.html", map[string]any{
		"Nav": "docs", "Title": "Documentation", "Principal": p,
		"Chapters": manual,
	})
}

// anchors is every section id, for the test that checks the Help links.
func anchors() map[string]bool {
	out := map[string]bool{}
	for _, c := range manual {
		for _, s := range c.Sections {
			out[s.ID] = true
		}
	}
	return out
}

// findSection is used by the tests and by the search in the contents.
func findSection(id string) (section, bool) {
	for _, c := range manual {
		for _, s := range c.Sections {
			if s.ID == id {
				return s, true
			}
		}
	}
	return section{}, false
}

// words counts the manual, so the test that asks whether this is real
// documentation has something to measure.
func words() int {
	n := 0
	for _, c := range manual {
		for _, s := range c.Sections {
			n += len(strings.Fields(s.Summary))
			for _, b := range s.Body {
				n += len(strings.Fields(b.Text))
				for _, i := range b.Items {
					n += len(strings.Fields(i))
				}
				for _, row := range b.Rows {
					for _, cell := range row {
						n += len(strings.Fields(cell))
					}
				}
			}
		}
	}
	return n
}
