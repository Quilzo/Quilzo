package admin

import (
	"net/http"
)

// The help page, which every other page has linked to since the footer was
// written and which nothing served.
//
// It 404'd on every screen in the product for as long as the footer has
// existed. Nothing caught it because a link is not a route and no test knew
// the two were meant to agree; TestEveryLinkInTheInterfaceIsServed now does.
//
// What it says is a map, because the problem it is a symptom of was that
// people could not find things. Twenty-six capabilities were in the product
// and not in this interface at once, and the reason nobody noticed is that
// there was no page whose job was to list what exists. This is that page: one
// line per screen, and the command that does the same thing, so somebody who
// read about a feature can find where it lives instead of concluding it was
// never built.

// screen is one destination, described once.
type screen struct {
	Path string
	Name string
	// What it is for, in a sentence. Not a feature list: a person reading this
	// is looking for one thing and scanning, and a paragraph per row is a page
	// nobody reads to the bottom of.
	Does string
	// Command is the equivalent on the command line, so the two surfaces can be
	// seen to be the same product. Empty where there is no equivalent.
	Command string
}

// screens is the map, grouped the way the navigation is grouped.
var screens = []struct {
	Group string
	Rows  []screen
}{
	{"Build", []screen{
		{"/", "Pages", "Every page in the draft, and which of them differ from what is live.", "scrivet log"},
		{"/records", "Data", "Collections of records — an application's data rather than a site's pages.", "scrivet records list"},
		{"/types", "Types", "What a page or a record is allowed to contain, and which pages must satisfy which type.", "scrivet types"},
		{"/media", "Media", "Images and files, with what each one cost and what it was converted to.", "scrivet media add"},
		{"/languages", "Languages", "The locales this site is served in and how much of it each one has.", "scrivet lang list"},
		{"/assist", "Assistant", "Describe a site and get a draft to edit. Nothing is written until you accept it.", "scrivet assist"},
	}},
	{"Publish", []screen{
		{"/review", "Review", "What is about to change, what the accessibility checks say, and the button that publishes it.", "scrivet diff"},
		{"/publishing", "Publishing", "Environments and promotion, work scheduled for later, and who is holding which page.", "scrivet env list"},
		{"/history", "History", "Every commit, and rolling back to one of them.", "scrivet log"},
		{"/transfer", "Transfer", "Bring a site in, take one out, or start from a template.", "scrivet export"},
	}},
	{"Trust", []screen{
		{"/provenance", "Provenance", "Which pages were written by a model, recorded so publishing can require it.", "scrivet provenance"},
		{"/logs", "Log", "The audit record, and whether its hash chain still verifies.", "scrivet auditlog"},
		{"/security", "Security", "The posture scan, the code scanner, the generated policy, the inventory, and the store's own integrity.", "scrivet posture"},
	}},
	{"Administer", []screen{
		{"/people", "People", "Who has access, who is signed in, and taking either away.", "scrivet auth list"},
		{"/access", "Access", "What each role may do, resolved against the rules as written.", "scrivet auth show"},
		{"/integrations", "Integrations", "Webhooks, log forwarding, the identity provider, and extensions.", "scrivet webhook list"},
		{"/settings", "Settings", "Every setting this store has, with the ones that weaken security marked as such.", "scrivet config list"},
		{"/playground", "API", "Call the content API against this store, from this origin, without a client.", "scrivet serve"},
	}},
}

func (s *Server) handleHelp(w http.ResponseWriter, r *http.Request) {
	// Authenticated, but not authorised beyond that: a map of the interface is
	// not privileged information, and gating it would mean somebody who cannot
	// reach a screen also cannot find out that it exists to ask for.
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	s.render(w, r, "help.html", map[string]any{
		"Title": "Help", "Principal": p, "Groups": screens,
	})
}
