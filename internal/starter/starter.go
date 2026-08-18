// Package starter ships ready-made templates and the content that fills them.
//
// # Why these are embedded rather than downloaded
//
// The usual shape for a theme library is a registry somebody fetches from. That
// is a supply chain, and a CMS theme is markup that runs on every page of a
// site — the highest-value place in the system to put something. WordPress's
// worst years are a catalogue of exactly this.
//
// So these compile into the binary. There is no fetch, no registry, no
// signature to verify because there is no transport, and `quilzo template use`
// cannot be pointed at a URL. A template that ships with the tool has the same
// provenance as the tool.
//
// # Why each one is also a test fixture
//
// Every starter template is parsed, rendered and run through the accessibility
// checks by the test suite, using the sample content below. A template shipped
// as a starting point is the first HTML most people will ever publish with this
// tool, and shipping one that fails the gate the tool enforces would be the
// most embarrassing possible bug: the product blocking its own examples.
package starter

import (
	"embed"
	"fmt"
	"sort"
)

//go:embed assets/*
var assets embed.FS

// Template is one starting point.
type Template struct {
	Name string
	// Summary is what it is for, in the terms someone choosing would use.
	Summary string
	// Fields names the content keys it reads, so `quilzo template show` can
	// answer "what do I have to fill in" without anyone reading the markup.
	Fields []string
	// Sample is content that renders the template completely. It doubles as
	// the fixture the tests render, so the sample cannot drift from the
	// template without something failing.
	Sample map[string]any
}

// HTML returns the template source.
func (t Template) HTML() (string, error) {
	b, err := assets.ReadFile("assets/" + t.Name + ".html")
	if err != nil {
		return "", fmt.Errorf("no starter template %q", t.Name)
	}
	return string(b), nil
}

// CSS is the stylesheet every starter shares.
//
// One stylesheet rather than one per template: they are the same design system,
// and four near-identical copies is four places for the contrast to drift apart.
func CSS() string {
	b, _ := assets.ReadFile("assets/site.css")
	return string(b)
}

var nav = []any{
	map[string]any{"href": "/", "label": "Home"},
	map[string]any{"href": "/about", "label": "About"},
	map[string]any{"href": "/contact", "label": "Contact"},
}

var templates = map[string]Template{
	"landing": {
		Name: "landing",
		Summary: "A marketing or product page: hero, feature cards, a quote. " +
			"The shape most requested for SaaS and launches.",
		Fields: []string{"title", "subtitle", "eyebrow", "brand", "nav",
			"cta_label", "cta_href", "secondary_label", "secondary_href",
			"features_title", "features", "quote", "quote_by", "body", "footer"},
		Sample: map[string]any{
			"title":     "Publishing you can prove",
			"eyebrow":   "New",
			"subtitle":  "Content addressed by hash, published by moving a pointer, and reversible without a backup.",
			"brand":     "Example",
			"nav":       nav,
			"cta_label": "Read the guide", "cta_href": "/guide",
			"secondary_label": "See pricing", "secondary_href": "/pricing",
			"features_title": "What you get",
			"features": []any{
				map[string]any{"title": "Immutable history",
					"body": "Every version is still there, addressed by its own hash."},
				map[string]any{"title": "Rollback that cannot half-finish",
					"body": "Publishing moves a pointer, so undoing it moves the pointer back."},
				map[string]any{"title": "Accessible by default",
					"body": "The publish gate refuses content that fails the checks."},
			},
			"quote":    "We moved a decade of pages across in an afternoon and nothing was lost.",
			"quote_by": "A person who has not said this, because this is sample text",
			"body":     "Replace this with whatever the page is actually about.",
			"footer":   "© Example. Built with quilzo.",
		},
	},
	"article": {
		Name: "article",
		Summary: "A single piece of writing: headline, standfirst, byline, date, " +
			"body, tags. For news, a blog, or a long-form page.",
		Fields: []string{"title", "standfirst", "section", "byline", "published",
			"hero", "hero_alt", "body", "tags", "canonical", "description",
			"brand", "nav", "footer"},
		Sample: map[string]any{
			"title":      "How the store works",
			"section":    "Engineering",
			"standfirst": "Git's object model, applied to content, and what that buys you.",
			"byline":     "A. Writer",
			"published":  "2026-08-15",
			"body":       "Replace this with the piece itself.",
			"tags":       []any{"architecture", "storage"},
			"brand":      "Example",
			"nav":        nav,
			"footer":     "© Example. Built with quilzo.",
		},
	},
	"docs": {
		Name: "docs",
		Summary: "A documentation page: sticky contents on the side, a code " +
			"example, a reference table.",
		Fields: []string{"title", "standfirst", "body", "contents", "example",
			"example_title", "rows", "col_a", "col_b", "description",
			"brand", "nav", "footer"},
		Sample: map[string]any{
			"title":      "Getting started",
			"standfirst": "Install, initialise, publish. Three commands.",
			"body":       "Replace this with the page's own prose.",
			"contents": []any{
				map[string]any{"href": "#install", "label": "Install"},
				map[string]any{"href": "#configure", "label": "Configure"},
				map[string]any{"href": "#publish", "label": "Publish"},
			},
			"example_title": "A first publish",
			"example":       "quilzo init\nquilzo add index=index.json\nquilzo publish",
			"col_a":         "Command", "col_b": "What it does",
			"rows": []any{
				map[string]any{"name": "quilzo init", "detail": "Creates a content store."},
				map[string]any{"name": "quilzo publish", "detail": "Moves the live pointer."},
			},
			"brand":  "Example",
			"nav":    nav,
			"footer": "© Example. Built with quilzo.",
		},
	},
	"portfolio": {
		Name: "portfolio",
		Summary: "Personal or studio work: a hero, a grid of projects with " +
			"images and roles, an about section and a contact card.",
		Fields: []string{"title", "subtitle", "available", "work_title", "work",
			"about_title", "about", "contact_title", "contact_body",
			"contact_label", "contact_href", "description", "brand", "nav", "footer"},
		Sample: map[string]any{
			"title":      "Selected work",
			"subtitle":   "Interfaces, systems, and the occasional typeface.",
			"available":  "Available from October",
			"work_title": "Projects",
			"work": []any{
				map[string]any{"title": "Wayfinding for a hospital",
					"href": "/work/wayfinding", "role": "Lead designer",
					"body": "Signage and a printed map, tested with patients."},
				map[string]any{"title": "A reading app",
					"href": "/work/reading", "role": "Design and build",
					"body": "Offline-first, and legible at 200% zoom."},
			},
			"about_title":   "About",
			"about":         "Replace this with a short biography.",
			"contact_title": "Work together?",
			"contact_body":  "Tell me what you are making and when it needs to exist.",
			"contact_label": "Send an email", "contact_href": "mailto:hello@example.com",
			"brand":  "Example",
			"nav":    nav,
			"footer": "© Example. Built with quilzo.",
		},
	},
}

// Get returns one template.
func Get(name string) (Template, bool) {
	t, ok := templates[name]
	return t, ok
}

// All returns every template, in a stable order.
func All() []Template {
	out := make([]Template, 0, len(templates))
	for _, t := range templates {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Names lists the template names.
func Names() []string {
	out := make([]string, 0, len(templates))
	for n := range templates {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
