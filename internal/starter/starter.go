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
// provenance as the tool. Bringing your own is a separate, explicit act with its
// own gate — see `quilzo template adopt` and internal/foreign.
//
// # Why each one is also a test fixture
//
// Every starter template is parsed, rendered and run through the accessibility
// checks by the test suite, using the sample content below. A template shipped
// as a starting point is the first HTML most people will ever publish with this
// tool, and shipping one that fails the gate the tool enforces would be the
// most embarrassing possible bug: the product blocking its own examples.
//
// # Why they share components and differ in tokens
//
// There used to be one stylesheet for all of them, and the reason was good: four
// near-identical copies is four places for the contrast to drift apart. It stops
// being good the moment the starters are supposed to look different from each
// other, which is the whole point of having more than one.
//
// So the split is by kind rather than by count. The component rules are shared —
// one copy of what a card is, where the focus ring goes, how a grid wraps — and
// each starter carries its own token block: colours, type stacks, radius,
// density. A starter can be square and dense or round and airy without owning a
// line of CSS, and the contrast gate runs over its tokens, so a design that
// would be unreadable does not ship.
package starter

import (
	"embed"
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/theme"
)

//go:embed assets/*
var assets embed.FS

// Template is one starting point.
type Template struct {
	Name string
	// Layout is the markup file this starter renders through, without its
	// extension. Several starters share one: a dashboard and a marketing page
	// are the same layout driven by different sections, and duplicating the
	// file to say so would be two files to keep in step.
	Layout string
	// Summary is what it is for, in the terms someone choosing would use.
	Summary string
	// Look describes the design in a sentence, because "landing" says what the
	// page does and nothing about what it looks like.
	Look string
	// Fields names the content keys it reads, so `quilzo template show` can
	// answer "what do I have to fill in" without anyone reading the markup.
	Fields []string
	// Tokens is this starter's theme: the values that make it look like itself.
	// Empty means the shipped palette, which is a deliberate choice for the
	// starters whose job is to be neutral.
	Tokens map[string]string
	// Sample is content that renders the template completely. It doubles as
	// the fixture the tests render, so the sample cannot drift from the
	// template without something failing.
	Sample map[string]any
}

// HTML returns the template source.
func (t Template) HTML() (string, error) {
	layout := t.Layout
	if layout == "" {
		layout = t.Name
	}
	b, err := assets.ReadFile("assets/" + layout + ".html")
	if err != nil {
		return "", fmt.Errorf("no layout %q for starter %q", layout, t.Name)
	}
	return string(b), nil
}

// LayoutName is the file this starter writes, without the extension.
func (t Template) LayoutName() string {
	if t.Layout == "" {
		return t.Name
	}
	return t.Layout
}

// Theme is this starter's token set, already validated.
//
// A starter whose own theme fails the contrast gate is a bug in this package,
// not a problem for the operator who chose it, so the findings come back here
// and a test refuses them.
func (t Template) Theme() (*theme.Theme, []theme.Finding) {
	return theme.New(t.Tokens, nil)
}

// CSS is the stylesheet a site is served: this starter's tokens, then the
// shared components.
func (t Template) CSS() string {
	th, _ := t.Theme()
	return Stylesheet(th)
}

// Components is the part of the design that is not editable.
//
// Not editable because it is where the accessibility work lives — the focus
// ring, the target sizes, the reduced-motion escape hatch, the forced-colours
// fallbacks. An operator who could replace this could remove all of it by
// accident, and there is no gate a free-form stylesheet can be held to.
func Components() string {
	b, _ := assets.ReadFile("assets/components.css")
	return string(b)
}

// Stylesheet assembles the tokens for a theme and the shared components.
//
// One function, so the public server, the preview, the static export and
// `template use` cannot disagree about what a site's stylesheet is. They used to
// read a file each.
func Stylesheet(th *theme.Theme) string {
	if th == nil {
		th, _ = theme.New(nil, nil)
	}
	// Tokens, then components, then the arrangement rules generated from this
	// site's breakpoints — last, so they win, and separate because a container
	// query cannot read a custom property.
	return th.CSS() + "\n" + Components() + th.Responsive()
}

// CSS is the default stylesheet: the shipped palette and the components.
func CSS() string { return Stylesheet(nil) }

var nav = []any{
	map[string]any{"href": "/", "label": "Home"},
	map[string]any{"href": "/about", "label": "About"},
	map[string]any{"href": "/contact", "label": "Contact"},
}

var templates = map[string]Template{
	// -- the universal one ----------------------------------------------------
	//
	// This is the answer to "can it do the kind of page I have in mind". The
	// layout renders an ordered list of typed sections, so the page's shape is
	// content rather than markup: reorder them, drop one, use the same kind
	// twice with different data. Nineteen kinds, and adding a twentieth is a
	// change to one file that every site picks up.
	"sections": {
		Name: "sections", Layout: "page",
		Summary: "A page assembled from sections you order yourself: hero, " +
			"features, metrics, charts, split, gallery, carousel, video, steps, " +
			"timeline, quote, logos, pricing, FAQ, table, people, prose, " +
			"notice, call to action.",
		Look: "Rounded, generous, a tinted hero. The shipped palette.",
		Fields: []string{"title", "description", "hero", "sections", "footer",
			"header_cta_label", "header_cta_href", "brand_mark", "breadcrumbs",
			"share_image", "share_image_alt"},
		Sample: map[string]any{
			"title":       "Everything, in the order you choose",
			"description": "One layout, nineteen kinds of section, arranged by the content rather than the markup.",
			"hero": map[string]any{
				"eyebrow": "New", "style": "center", "surface": "surface-wash",
				"lead":      "Sections are data. Reorder them, drop one, use the same kind twice — without touching a template.",
				"cta_label": "Read the guide", "cta_href": "/guide",
				"secondary_label": "See the sections", "secondary_href": "#features",
			},
			"header_cta_label": "Get started", "header_cta_href": "/start",
			"share_image":     "https://example.com/share.png",
			"share_image_alt": "The words Quilzo over a tinted panel",
			"breadcrumbs": []any{
				map[string]any{"label": "Home", "href": "/"},
				map[string]any{"label": "Sections"},
			},
			"sections": []any{
				map[string]any{"features": map[string]any{
					"title": "What a section can be", "columns": "3",
					"intro": "Each of these is one object in a list. The order on the page is the order in the file.",
					"items": []any{
						map[string]any{"title": "Features", "body": "A grid of cards, two to four across, optionally linked.", "chip": "Grid"},
						map[string]any{"title": "Metrics", "body": "Labelled figures with a change and a bar, for a dashboard.", "chip": "Data"},
						map[string]any{"title": "Split", "body": "An image beside prose, flipped if you want it the other way.", "chip": "Media"},
					},
				}},
				map[string]any{"metrics": map[string]any{
					"title": "Figures, drawn in CSS",
					"items": []any{
						map[string]any{"label": "Pages published", "value": "1,284", "delta": "+18% this month", "state": "positive", "pct": 72},
						map[string]any{"label": "Median build", "value": "310ms", "delta": "-40ms", "state": "positive", "pct": 34},
						map[string]any{"label": "Storage used", "value": "8.1 GB", "note": "of 20 GB", "state": "caution", "pct": 41},
					},
				}},
				map[string]any{"bars": map[string]any{
					"title": "Where the traffic came from",
					"items": []any{
						map[string]any{"name": "Search", "amount": "48%", "pct": 48},
						map[string]any{"name": "Direct", "amount": "31%", "pct": 31},
						map[string]any{"name": "Referral", "amount": "14%", "pct": 14, "state": "caution"},
						map[string]any{"name": "Social", "amount": "7%", "pct": 7, "state": "critical"},
					},
					"footnote": "Every bar is a percentage the content carries. The template has no arithmetic, so the number arrives ready.",
				}},
				map[string]any{"steps": map[string]any{
					"title": "How a page gets published",
					"items": []any{
						map[string]any{"title": "Write it", "body": "Content is typed and validated as you save."},
						map[string]any{"title": "Check it", "body": "The gate renders every page and refuses the ones a reader could not use."},
						map[string]any{"title": "Move the pointer", "body": "Publishing sets one ref. Undoing it sets it back."},
					},
				}},
				map[string]any{"carousel": map[string]any{
					"title": "A carousel that cannot run away with itself",
					"hint":  "Scroll sideways. It does not advance on its own, and there is no script behind it.",
					"items": []any{
						map[string]any{"title": "Scroll-snap", "body": "The browser does the paging, so a keyboard and a screen reader both work."},
						map[string]any{"title": "No autoplay", "body": "A carousel that moves on its own is the thing WCAG 2.2.2 is about."},
						map[string]any{"title": "Still a list", "body": "Announced as a list of three, because that is what it is."},
					},
				}},
				map[string]any{"quote": map[string]any{
					"text": "We reordered the whole homepage over lunch and never opened the template.",
					"by":   "A person who has not said this", "role": "because this is sample text",
				}},
				map[string]any{"pricing": map[string]any{
					"title": "Plans", "intro": "Three columns, one of them marked.",
					"items": []any{
						map[string]any{"name": "Solo", "price": "£0", "period": "/month", "body": "One site, one editor.",
							"features":  []any{"Unlimited pages", "Instant rollback", "Accessibility gate"},
							"cta_label": "Start", "cta_href": "/start"},
						map[string]any{"name": "Studio", "price": "£24", "period": "/month", "featured": "featured",
							"body":      "For a team that ships weekly.",
							"features":  []any{"Everything in Solo", "Staged environments", "Scheduled publication", "Audit trail"},
							"cta_label": "Choose Studio", "cta_href": "/start?plan=studio"},
						map[string]any{"name": "Estate", "price": "£96", "period": "/month", "body": "Many sites, one policy.",
							"features":  []any{"Everything in Studio", "Replica targets", "Retention policy"},
							"cta_label": "Talk to us", "cta_href": "/contact"},
					},
					"footnote": "Sample prices. Nothing here is for sale.",
				}},
				map[string]any{"faq": map[string]any{
					"title": "Questions",
					"items": []any{
						map[string]any{"q": "Can I add a section kind of my own?",
							"a": "Yes — a kind is one block in the layout file, and adding one does not touch any other."},
						map[string]any{"q": "Does reordering need a deploy?",
							"a": "No. The order lives in the page, so it is an edit and it rolls back like any other."},
					},
				}},
				map[string]any{"split": map[string]any{
					"eyebrow": "How it works", "title": "An image beside prose",
					"image": "/media/placeholder.png",
					"alt":   "A diagram of a commit pointing at a tree of pages",
					"paragraphs": []any{
						"A split section takes an image, a heading and any number of paragraphs.",
						"Set flip and the image goes on the other side. Leave the image out and it is prose at full width.",
					},
					"cta_label": "Read the storage chapter", "cta_href": "/storage",
				}},
				map[string]any{"gallery": map[string]any{
					"title": "A gallery", "shape": "square",
					"items": []any{
						map[string]any{"image": "/media/placeholder.png",
							"alt": "A notebook lying open on a desk", "caption": "Linen notebook"},
						map[string]any{"image": "/media/placeholder.png",
							"alt": "A brass pen beside a sheet of paper", "caption": "Brass pen"},
					},
				}},
				map[string]any{"video": map[string]any{
					"title":            "A video, served from this origin",
					"src":              "/media/placeholder.mp4",
					"caption":          "Controls always, autoplay never — a video that starts on its own is what 1.4.2 is about.",
					"transcript_label": "Read the transcript instead",
					"transcript_href":  "/transcript",
				}},
				map[string]any{"timeline": map[string]any{
					"title": "What changed",
					"items": []any{
						map[string]any{"date": "2026-08-01", "title": "Layouts",
							"body": "A page names the layout it renders through."},
						map[string]any{"date": "2026-08-14", "title": "Themes",
							"body": "Colour, type and spacing became a checked token set."},
					},
				}},
				map[string]any{"people": map[string]any{
					"title": "Who made it",
					"items": []any{
						map[string]any{"name": "A. Maintainer", "role": "Everything, so far",
							"href": "/people/a-maintainer"},
						map[string]any{"name": "You, possibly", "role": "Three merged pull requests and commit access"},
					},
				}},
				map[string]any{"logos": map[string]any{
					"title": "In use at",
					"items": []any{"Northgate", "Ashby & Co", "Larkspur", "Fen Press"},
				}},
				map[string]any{"prose": map[string]any{
					"title": "And ordinary prose",
					"paragraphs": []any{
						"A prose section is a list of paragraphs at a readable measure.",
						"It is a list rather than one rich-text field because a starter that reached for raw would teach that on the first page anybody writes.",
					},
				}},
				map[string]any{"cta": map[string]any{
					"title":     "Start from this and delete what you do not need",
					"body":      "Every section below the hero is optional, and an absent one renders nothing at all.",
					"cta_label": "Use this starter", "cta_href": "/start",
				}},
			},
			"footer": "© Example. Built with Quilzo.",
		},
	},

	// -- a dashboard ----------------------------------------------------------
	//
	// The same layout as sections, with a denser theme and the data-shaped
	// kinds. Proof that the token split does real work: nothing here is a
	// different component, and it does not look like the same site.
	"dashboard": {
		Name: "dashboard", Layout: "page",
		Summary: "An analytics or operations page: metric tiles with change and " +
			"bars, horizontal bar charts, donuts, and a wide data table.",
		Look: "Dense and square. Compact spacing, a small radius, a mono face " +
			"for figures, and semantic colour that is not the accent.",
		Fields: []string{"title", "description", "head_title", "standfirst",
			"eyebrow", "sections", "footer"},
		Tokens: map[string]string{
			"radius": "6px", "radius-pill": "6px", "density": "0.82",
			"text-base": "1rem", "scale": "1.2", "line": "1.5",
			"page-width": "78rem", "measure": "72ch",
			"font-display": "grotesque", "font-body": "system", "font-mono": "mono",
			"primary": "#0b4f6c", "primary.dark": "#8ecfe8",
			"primary-container": "#d3e9f2", "primary-container.dark": "#0d3b50",
			"on-primary-container": "#04212e", "on-primary-container.dark": "#d3e9f2",
			"surface": "#f4f6f7", "surface.dark": "#0f1214",
			"surface-container": "#e8ecee", "surface-container.dark": "#191d20",
			"surface-container-low": "#eef1f2", "surface-container-low.dark": "#15191b",
			"tertiary-container": "#e5e2f4", "tertiary-container.dark": "#2f2c47",
			"on-tertiary-container": "#1c1a2b", "on-tertiary-container.dark": "#e5e2f4",
		},
		Sample: map[string]any{
			"title":       "Operations",
			"description": "Yesterday's figures, and the three that moved.",
			"eyebrow":     "Updated hourly",
			"head_title":  "Operations",
			"standfirst":  "Every figure on this page is a value the content carries. Nothing is computed in the template, because the template cannot compute.",
			"sections": []any{
				map[string]any{"metrics": map[string]any{
					"items": []any{
						map[string]any{"label": "Orders", "value": "1,942", "delta": "+7.4%", "state": "positive", "pct": 74},
						map[string]any{"label": "Revenue", "value": "£38,410", "delta": "+2.1%", "state": "positive", "pct": 61},
						map[string]any{"label": "Refund rate", "value": "1.8%", "delta": "+0.4pt", "state": "caution", "pct": 18},
						map[string]any{"label": "Late shipments", "value": "37", "delta": "+12", "state": "critical", "pct": 9},
						map[string]any{"label": "Stock cover", "value": "24 days", "note": "target 30", "state": "caution", "pct": 80},
						map[string]any{"label": "Uptime", "value": "99.98%", "delta": "no change", "state": "positive", "pct": 100},
					},
				}},
				map[string]any{"bars": map[string]any{
					"title": "Orders by channel",
					"items": []any{
						map[string]any{"name": "Web", "amount": "1,102", "pct": 57},
						map[string]any{"name": "Wholesale", "amount": "540", "pct": 28},
						map[string]any{"name": "Marketplace", "amount": "212", "pct": 11, "state": "caution"},
						map[string]any{"name": "Phone", "amount": "88", "pct": 4, "state": "critical"},
					},
				}},
				map[string]any{"donuts": map[string]any{
					"title": "Fulfilment",
					"items": []any{
						map[string]any{"pct": 82, "value": "82%", "label": "shipped same day"},
						map[string]any{"pct": 61, "value": "61%", "label": "packed before noon"},
						map[string]any{"pct": 24, "value": "24%", "label": "awaiting stock"},
					},
				}},
				map[string]any{"table": map[string]any{
					"title":   "Slowest routes",
					"caption": "Median transit time over the last seven days.",
					"columns": []any{"Route", "Median", "P95", "Volume", "State"},
					"rows": []any{
						map[string]any{"cells": []any{"Leeds → Bristol", "2d 4h", "5d 1h", "412", "watch"}},
						map[string]any{"cells": []any{"Glasgow → Cardiff", "3d 1h", "6d 8h", "188", "late"}},
						map[string]any{"cells": []any{"London → Dublin", "2d 22h", "4d 9h", "96", "watch"}},
					},
				}},
				map[string]any{"notice": map[string]any{
					"tone": "caution", "title": "Two routes are outside target",
					"body": "This block is a section like any other, so the page says so at the top when it matters and carries nothing when it does not.",
				}},
			},
			"footer": "© Example. Figures are illustrative.",
		},
	},

	// -- marketing ------------------------------------------------------------
	"landing": {
		Name: "landing", Layout: "landing",
		Summary: "A marketing or product page: hero, feature cards, a quote. " +
			"The shape most requested for SaaS and launches.",
		Look: "A washed hero drawn in CSS, centred, round, and airy.",
		Fields: []string{"title", "subtitle", "eyebrow", "brand", "nav",
			"cta_label", "cta_href", "secondary_label", "secondary_href",
			"features_title", "features", "quote", "quote_by", "body", "footer",
			"logos", "logos_title", "closing_title", "closing_body"},
		Tokens: map[string]string{
			"radius": "20px", "density": "1.1", "scale": "1.32",
			"font-display": "geometric",
		},
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
			"logos_title":   "In use at",
			"logos":         []any{"Northgate", "Ashby & Co", "Larkspur", "Meridian", "Fen Press"},
			"quote":         "We moved a decade of pages across in an afternoon and nothing was lost.",
			"quote_by":      "A person who has not said this, because this is sample text",
			"body":          "Replace this with whatever the page is actually about.",
			"closing_title": "Start with one page",
			"closing_body":  "Install it, publish something, and roll it back to see what that costs.",
			"footer":        "© Example. Built with Quilzo.",
		},
	},

	// -- editorial ------------------------------------------------------------
	"article": {
		Name: "article", Layout: "article",
		Summary: "A single piece of writing: headline, standfirst, byline, date, " +
			"body, tags. For news, a blog, or a long-form page.",
		Look: "Editorial. An old-style serif for headings, a narrow measure, " +
			"and warm paper rather than white.",
		Fields: []string{"title", "standfirst", "section", "byline", "published",
			"hero", "hero_alt", "body", "tags", "canonical", "description",
			"brand", "nav", "footer", "paragraphs", "pull_quote", "pull_quote_by",
			"hero_caption", "reading_time", "updated"},
		Tokens: map[string]string{
			"font-display": "oldstyle", "font-body": "humanist",
			"scale": "1.36", "line": "1.72", "measure": "62ch",
			"radius": "4px", "page-width": "58rem", "density": "1.05",
			"surface": "#faf8f4", "surface.dark": "#14120f",
			"surface-container": "#f0ece3", "surface-container.dark": "#211e19",
			"surface-container-low": "#f5f2ec", "surface-container-low.dark": "#1a1815",
			"surface-container-lowest": "#fffdf9", "surface-container-lowest.dark": "#0f0d0b",
			"on-surface": "#1b1813", "on-surface.dark": "#e8e3d9",
			"on-surface-variant": "#4a443a", "on-surface-variant.dark": "#c4bcae",
			"primary": "#7a2e12", "primary.dark": "#f0b193",
			"primary-container": "#f4ddd0", "primary-container.dark": "#5a2110",
			"on-primary-container": "#2c1006", "on-primary-container.dark": "#f4ddd0",
			"outline": "#6d6455", "outline-variant": "#c9c0b0",
			"outline.dark": "#8e8474", "outline-variant.dark": "#4a443a",
			"focus-ring": "#7a2e12", "focus-ring.dark": "#f0b193",
		},
		Sample: map[string]any{
			"title":        "How the store works",
			"section":      "Engineering",
			"standfirst":   "Git's object model, applied to content, and what that buys you.",
			"byline":       "A. Writer",
			"published":    "2026-08-15",
			"reading_time": "6 min read",
			"body":         "Replace this with the piece itself.",
			"paragraphs": []any{
				"Every object is addressed by the hash of its own bytes. A page is a hash, a set of pages is a tree, and a commit names a tree and its parents.",
				"Four things follow, and none of them are features anybody had to write: nothing is edited, publishing is a pointer move, caching is exact, and integrity is checkable.",
			},
			"pull_quote":    "There is no UPDATE and no DELETE, so every previous version is still addressable.",
			"pull_quote_by": "The storage chapter",
			"tags":          []any{"architecture", "storage"},
			"brand":         "Example",
			"nav":           nav,
			"footer":        "© Example. Built with Quilzo.",
		},
	},

	// -- documentation --------------------------------------------------------
	"docs": {
		Name: "docs", Layout: "docs",
		Summary: "A documentation page: sticky contents on the side, a code " +
			"example, numbered steps, a reference table and a questions list.",
		Look: "Utilitarian and tight. A small radius, a sticky sidebar, and " +
			"mono for anything you would type.",
		Fields: []string{"title", "standfirst", "body", "contents", "example",
			"example_title", "rows", "col_a", "col_b", "description",
			"brand", "nav", "footer", "paragraphs", "steps", "steps_title",
			"notices", "faq", "faq_title", "eyebrow", "updated"},
		Tokens: map[string]string{
			"radius": "8px", "radius-pill": "8px", "density": "0.9",
			"scale": "1.22", "page-width": "72rem", "measure": "74ch",
			"font-display": "system", "font-body": "system",
			"primary": "#0f4d3d", "primary.dark": "#8bd6bf",
			"primary-container": "#cfe9e0", "primary-container.dark": "#0d3b30",
			"on-primary-container": "#04211a", "on-primary-container.dark": "#cfe9e0",
			"secondary-container": "#dce7e3", "secondary-container.dark": "#2c3d38",
			"on-secondary-container": "#101a17", "on-secondary-container.dark": "#dce7e3",
			"focus-ring": "#0f4d3d", "focus-ring.dark": "#8bd6bf",
		},
		Sample: map[string]any{
			"title":      "Getting started",
			"eyebrow":    "Guide",
			"standfirst": "Install, initialise, publish. Three commands.",
			"body":       "Replace this with the page's own prose.",
			"contents": []any{
				map[string]any{"href": "#install", "label": "Install"},
				map[string]any{"href": "#configure", "label": "Configure"},
				map[string]any{"href": "#publish", "label": "Publish"},
			},
			"example_title": "A first publish",
			"example":       "quilzo init\nquilzo add index=index.json\nquilzo publish",
			"steps_title":   "What each command does",
			"steps": []any{
				map[string]any{"title": "Create the store", "body": "One directory, content-addressed, no database.", "example": "quilzo init"},
				map[string]any{"title": "Add a page", "body": "Typed and validated as it is written.", "example": "quilzo add index=index.json"},
				map[string]any{"title": "Move the pointer", "body": "The gate runs first and refuses what a reader could not use.", "example": "quilzo publish"},
			},
			"notices": []any{
				map[string]any{"tone": "caution", "title": "The gate can refuse",
					"body": "A page with an unlabelled image does not publish. Overriding is possible, explicit, and recorded in the commit."},
			},
			"col_a": "Command", "col_b": "What it does",
			"rows": []any{
				map[string]any{"name": "quilzo init", "detail": "Creates a content store."},
				map[string]any{"name": "quilzo publish", "detail": "Moves the live pointer."},
			},
			"faq_title": "Questions",
			"faq": []any{
				map[string]any{"q": "Where does the stylesheet come from?",
					"a": "The site's theme, generated from its tokens, followed by the shared components."},
				map[string]any{"q": "Can I bring a template from somewhere else?",
					"a": "Yes — quilzo template adopt converts one and reports everything it had to change."},
			},
			"brand":  "Example",
			"nav":    nav,
			"footer": "© Example. Built with Quilzo.",
		},
	},

	// -- work -----------------------------------------------------------------
	"portfolio": {
		Name: "portfolio", Layout: "portfolio",
		Summary: "Personal or studio work: a hero, a grid of projects with " +
			"images and roles, a gallery, an about section and a contact card.",
		Look: "Stark and typographic. Near-black on near-white, square corners, " +
			"an industrial face, and the work carrying the colour.",
		Fields: []string{"title", "subtitle", "available", "work_title", "work",
			"about_title", "about", "contact_title", "contact_body",
			"contact_label", "contact_href", "description", "brand", "nav", "footer",
			"gallery", "gallery_title", "clients", "clients_title"},
		Tokens: map[string]string{
			"radius": "0px", "radius-pill": "0px", "border": "1px",
			"scale": "1.42", "tracking-display": "-0.04em", "density": "1.05",
			"font-display": "industrial", "font-body": "grotesque",
			"page-width": "74rem",
			"surface":    "#fbfbfa", "surface.dark": "#0b0b0b",
			"surface-container": "#efefed", "surface-container.dark": "#161616",
			"surface-container-low": "#f5f5f3", "surface-container-low.dark": "#111111",
			"surface-container-lowest": "#ffffff", "surface-container-lowest.dark": "#070707",
			"surface-container-high": "#e6e6e3", "surface-container-high.dark": "#1f1f1f",
			"on-surface": "#0d0d0d", "on-surface.dark": "#f0f0ee",
			"on-surface-variant": "#3f3f3d", "on-surface-variant.dark": "#c0c0bc",
			"primary": "#1a1a1a", "primary.dark": "#f0f0ee",
			"primary-container": "#e8e8e5", "primary-container.dark": "#1c1c1c",
			"on-primary-container": "#0d0d0d", "on-primary-container.dark": "#f0f0ee",
			"on-primary": "#ffffff", "on-primary.dark": "#0b0b0b",
			"secondary-container": "#e0e0dd", "secondary-container.dark": "#242424",
			"on-secondary-container": "#111111", "on-secondary-container.dark": "#eaeae8",
			"tertiary-container": "#e9e4d8", "tertiary-container.dark": "#28241b",
			"on-tertiary-container": "#191710", "on-tertiary-container.dark": "#e9e4d8",
			"outline": "#5f5f5c", "outline-variant": "#c2c2be",
			"outline.dark": "#8a8a86", "outline-variant.dark": "#3a3a38",
			"focus-ring": "#0d0d0d", "focus-ring.dark": "#f0f0ee",
		},
		Sample: map[string]any{
			"title":      "Selected work",
			"subtitle":   "Interfaces, systems, and the occasional typeface.",
			"available":  "Available from October",
			"work_title": "Projects",
			"work": []any{
				map[string]any{"title": "Wayfinding for a hospital",
					"href": "/work/wayfinding", "role": "Lead designer", "year": "2025",
					"body": "Signage and a printed map, tested with patients."},
				map[string]any{"title": "A reading app",
					"href": "/work/reading", "role": "Design and build", "year": "2024",
					"body": "Offline-first, and legible at 200% zoom."},
			},
			"clients_title": "Worked with",
			"clients":       []any{"Northgate", "Ashby & Co", "Larkspur", "Fen Press"},
			"about_title":   "About",
			"about":         "Replace this with a short biography.",
			"contact_title": "Work together?",
			"contact_body":  "Tell me what you are making and when it needs to exist.",
			"contact_label": "Send an email", "contact_href": "mailto:hello@example.com",
			"brand":  "Example",
			"nav":    nav,
			"footer": "© Example. Built with Quilzo.",
		},
	},

	// -- commerce -------------------------------------------------------------
	"catalogue": {
		Name: "catalogue", Layout: "catalogue",
		Summary: "A shop: a filterable index of records with prices and " +
			"availability, a detail page for one record, and an enquiry form.",
		Look: "Warm and product-forward. Square images, a soft ground, and " +
			"availability carried by a labelled state rather than colour alone.",
		Fields: []string{"title", "intro", "eyebrow", "description", "filters",
			"footer", "form", "form_title", "fields", "privacy", "form_submit",
			"body_paragraphs", "basket_label", "basket_href"},
		Tokens: map[string]string{
			"radius": "14px", "density": "1", "scale": "1.28",
			"font-display": "transitional", "font-body": "humanist",
			"surface": "#fbf7f3", "surface.dark": "#14110e",
			"surface-container": "#f1e9e1", "surface-container.dark": "#221d18",
			"surface-container-low": "#f7f1eb", "surface-container-low.dark": "#1a1613",
			"surface-container-lowest": "#fffcf9", "surface-container-lowest.dark": "#0f0d0b",
			"on-surface": "#1c1713", "on-surface.dark": "#ebe3da",
			"on-surface-variant": "#4b4239", "on-surface-variant.dark": "#c8bdb0",
			"primary": "#5c4020", "primary.dark": "#e6c39a",
			"primary-container": "#eddcc6", "primary-container.dark": "#432f16",
			"on-primary-container": "#241705", "on-primary-container.dark": "#eddcc6",
			"secondary-container": "#e6ded2", "secondary-container.dark": "#38312a",
			"on-secondary-container": "#181410", "on-secondary-container.dark": "#e6ded2",
			"tertiary-container": "#dde5dd", "tertiary-container.dark": "#28322a",
			"on-tertiary-container": "#131813", "on-tertiary-container.dark": "#dde5dd",
			"outline": "#6d6357", "outline-variant": "#c9beb0",
			"outline.dark": "#8d8275", "outline-variant.dark": "#4b4239",
			"focus-ring": "#5c4020", "focus-ring.dark": "#e6c39a",
		},
		Sample: map[string]any{
			"title":   "Everything for sale",
			"eyebrow": "Catalogue",
			"intro":   "Prices include tax. Anything marked made to order ships in three weeks.",
			"filters": []any{
				map[string]any{"href": "/shop", "label": "Everything"},
				map[string]any{"href": "/shop?range=desk", "label": "Desk"},
				map[string]any{"href": "/shop?range=archive", "label": "Archive"},
			},
			"body_paragraphs": []any{
				"This page reads its products through a declared listing, which is what decides which fields are public.",
				"A record's own page exists because another page declared itself the detail route for the same listing — so the links here point somewhere real or render as plain text.",
			},
			"form": "enquiry", "form_title": "Wholesale enquiry",
			"form_submit": "Send enquiry",
			"fields": []any{
				map[string]any{"name": "shop", "label": "Shop name", "type": "text", "required": true},
				map[string]any{"name": "contact", "label": "Your name", "type": "text", "required": true},
				map[string]any{"name": "email", "label": "Email", "type": "email", "required": true},
				map[string]any{"name": "detail", "label": "Anything else", "textarea": true,
					"hint": "Which ranges, and roughly what volume."},
			},
			"privacy":      "We keep enquiries for two years and never pass them on.",
			"basket_label": "Basket", "basket_href": "/basket",
			"footer": "© Example. Built with Quilzo.",
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

// Layouts returns every layout file that ships, keyed by name.
//
// This is what a site is given when it wants all of them: a page can then name
// any layout in its own body and be rendered through it. Sharing one set means a
// site does not have to choose one design for every page it will ever have.
func Layouts() (map[string]string, error) {
	entries, err := assets.ReadDir("assets")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		name, isHTML := strings.CutSuffix(e.Name(), ".html")
		if !isHTML {
			continue
		}
		b, rerr := assets.ReadFile("assets/" + e.Name())
		if rerr != nil {
			return nil, rerr
		}
		out[name] = string(b)
	}
	return out, nil
}

// LayoutNames lists the layout files that ship, in a stable order.
func LayoutNames() []string {
	layouts, err := Layouts()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(layouts))
	for name := range layouts {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
