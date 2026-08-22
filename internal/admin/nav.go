package admin

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
)

// The navigation, as data.
//
// It was markup — nineteen list items written out twice, once per orientation
// — and markup cannot answer the three questions now being asked of it: what
// order does this person want their tabs in, which of them may this person
// actually use, and where in the documentation is the page they are looking
// at explained.
//
// So it is a table. The table is the single place a destination exists: adding
// a screen means adding a row, and the row carries its group, the permission
// it needs, and its documentation anchor. Three tests read it — one checks
// every path is served, one checks every anchor exists in the documentation,
// and one checks nothing is in the mux that is not either here or written
// down as deliberately absent.

// destination is one place a person can go.
type destination struct {
	// Key identifies it in a stored order. Stable across renames of the label,
	// because a person's saved arrangement should survive us rewording a tab.
	Key   string
	Label string
	Path  string
	Group string
	// Doc is the documentation section that explains this screen. The footer
	// link on every page points at it, so "Help" means help with what you are
	// looking at rather than help in general.
	Doc string
	// Needs is the least permission that makes this screen useful. Somebody
	// without it does not see the entry.
	//
	// Hidden rather than shown-and-refused. A menu full of doors that answer
	// "you cannot do that here" teaches people to ignore the menu, and it also
	// tells a reader exactly which administrative screens exist to go asking
	// for. The refusal still happens at the handler — this is presentation,
	// never the control.
	Needs auth.Action
}

// groups are the sections, in their default order.
//
// Named for what somebody is doing rather than for how the code is arranged.
// The earlier attempt used Build / Publish / Trust / Administer, and "Trust"
// was the one nobody could place: it held provenance, the log and the security
// dashboard, which are three answers to "can I show somebody this is right" —
// so Assurance, which is the word the people who ask for it use.
var groups = []string{
	"Content",        // what you make
	"Release",        // how it goes out
	"Assurance",      // evidence that it is right
	"Administration", // who may do what, and what this talks to
	"Reference",      // how any of it works
}

// destinations is every screen, in the default order.
var destinations = []destination{
	{"pages", "Pages", "/", "Content", "pages", auth.ActView},
	{"records", "Data", "/records", "Content", "data", auth.ActView},
	{"types", "Types", "/types", "Content", "types", auth.ActView},
	{"structure", "Structure", "/structure", "Content", "structure", auth.ActView},
	{"listings", "Listings", "/listings", "Content", "listings", auth.ActView},
	{"forms", "Forms", "/forms", "Content", "forms", auth.ActEditDraft},
	{"media", "Media", "/media", "Content", "media", auth.ActView},
	{"design", "Design", "/design", "Content", "templates", auth.ActEditDraft},
	{"sections", "Sections", "/sections", "Content", "templates", auth.ActEditDraft},
	{"languages", "Languages", "/languages", "Content", "languages", auth.ActView},
	{"assist", "Assistant", "/assist", "Content", "ai", auth.ActEditDraft},

	{"review", "Review", "/review", "Release", "publishing", auth.ActView},
	{"publishing", "Publishing", "/publishing", "Release", "environments", auth.ActView},
	{"history", "History", "/history", "Release", "history", auth.ActView},
	{"transfer", "Transfer", "/transfer", "Release", "transfer", auth.ActView},
	{"decentralised", "Permanent web", "/decentralised", "Release", "ipfs", auth.ActView},

	{"provenance", "Provenance", "/provenance", "Assurance", "provenance", auth.ActView},
	{"security", "Security", "/security", "Assurance", "security", auth.ActGrant},
	{"logs", "Log", "/logs", "Assurance", "logging", auth.ActGrant},

	{"agents", "Agents", "/agents", "Administration", "agents", auth.ActGrant},
	{"people", "People", "/people", "Administration", "users", auth.ActGrant},
	{"access", "Access", "/access", "Administration", "auth", auth.ActGrant},
	{"integrations", "Integrations", "/integrations", "Administration", "integrations", auth.ActGrant},
	{"settings", "Settings", "/settings", "Administration", "settings", auth.ActEditDraft},

	{"start", "Get started", "/start", "Reference", "start", auth.ActView},
	{"playground", "API", "/playground", "Reference", "api", auth.ActView},
	{"profile", "You", "/profile", "Reference", "profile", auth.ActView},
}

// DocsBase is where the manual lives.
//
// It used to be compiled in: about 1,800 lines of Go describing every screen,
// served at /docs, with eight screenshots embedded in the binary. That made
// the documentation a release artefact — a wording fix waited for a build, and
// a screenshot went stale the moment a screen changed.
//
// It is now a site of its own, so it can be corrected the day somebody notices
// rather than the next time somebody ships. The cost is that the link target
// is no longer verifiable by compiling this program, which is what docSections
// below exists to hold on to.
const DocsBase = "https://quilzo.github.io/"

// docSections is every anchor the published manual carries.
//
// The contract with the site, written down on this side of it. When the manual
// was in this repository a test could read it and prove that the Help link on
// every screen landed on a section that existed; the manual is now in another
// repository and that proof is not available at compile time.
//
// So the list is declared, a test checks every screen against it, and the site
// checks its own pages against the same list in its CI. Neither half proves the
// other, but each one fails loudly on its own side, and the failure a reader
// actually suffers — Help landing on nothing — needs both halves to be wrong.
//
// A link that lands on a heading somebody renamed is worse than no link: the
// person following it concludes the feature was removed, which is the belief
// the documentation exists to correct.
var docSections = map[string]bool{
	// One per screen, named by the destination table above.
	"pages": true, "data": true, "types": true, "structure": true,
	"listings": true, "forms": true, "media": true, "languages": true,
	"ai": true, "publishing": true, "environments": true, "history": true,
	"transfer": true, "ipfs": true, "provenance": true, "security": true,
	"logging": true, "users": true, "auth": true, "integrations": true,
	"settings": true, "api": true, "profile": true, "start": true,
	"agents": true,

	// Sections no screen owns, because they explain a concept or a surface
	// rather than a destination. Named individually so that one quietly
	// disappearing from the site is a change somebody made on purpose.
	"setup": true, "concepts": true, "privacy": true,
	"cli": true, "mcp": true, "templates": true,
}

// DocURL is the address of one section of the manual.
func DocURL(anchor string) string {
	if anchor == "" {
		return DocsBase
	}
	return DocsBase + "#" + anchor
}

// docFor returns the documentation anchor for a screen key.
//
// Used by the footer on every page, so "Help" lands on the section about the
// thing in front of you. A key with no row returns the introduction, which is
// the right answer for a page that is not a navigation destination — the
// sign-in screen, a message, a conflict.
func docFor(navKey string) string {
	for _, d := range destinations {
		if d.Key == navKey {
			return d.Doc
		}
	}
	return "start"
}

// navGroup is a rendered section.
type navGroup struct {
	Name  string
	Items []navItem
}

// navItem is a rendered entry.
type navItem struct {
	destination
	Current bool
}

// navFor builds the navigation for one request.
//
// Three things decide it: what this person may do, the order they have chosen,
// and which screen they are on. All three are per-request, and none of them is
// cached — the alternative is a cache whose staleness is a permission.
func (s *Server) navigation(r *http.Request, p principal, current string) []navGroup {
	allowed := make([]destination, 0, len(destinations))
	for _, d := range destinations {
		if s.Policy != nil && !s.Policy.Evaluate(p.Name, d.Needs, "/").Allowed {
			continue
		}
		allowed = append(allowed, d)
	}
	ordered := applyOrder(allowed, storedOrder(r))

	byGroup := map[string][]navItem{}
	for _, d := range ordered {
		byGroup[d.Group] = append(byGroup[d.Group], navItem{
			destination: d, Current: d.Key == current,
		})
	}
	out := make([]navGroup, 0, len(groups))
	for _, name := range groups {
		if items := byGroup[name]; len(items) > 0 {
			out = append(out, navGroup{Name: name, Items: items})
		}
	}
	return out
}

// NavOrderCookie holds a person's chosen arrangement.
const NavOrderCookie = "quilzo_nav_order"

// storedOrder reads the arrangement from the request.
//
// A cookie rather than a stored preference on the server, for the same reason
// the nav position is: this is a fact about a screen somebody is looking at,
// not a fact about the store. Two people sharing an account should not fight
// over it, and it must not survive into somebody else's session.
func storedOrder(r *http.Request) []string {
	c, err := r.Cookie(NavOrderCookie)
	if err != nil {
		return nil
	}
	raw, err := url.QueryUnescape(c.Value)
	if err != nil {
		return nil
	}
	var out []string
	for _, key := range strings.Split(raw, ",") {
		if key = strings.TrimSpace(key); key != "" {
			out = append(out, key)
		}
	}
	return out
}

// applyOrder sorts destinations by a stored arrangement.
//
// Anything the arrangement does not mention keeps its position relative to the
// others and goes last within its group. That is what makes a saved order
// survive a new screen being added: the arrangement is a preference about the
// screens somebody knew about, and a screen they have never seen should appear
// rather than be silently hidden by an old cookie.
func applyOrder(in []destination, order []string) []destination {
	if len(order) == 0 {
		return in
	}
	at := make(map[string]int, len(order))
	for i, key := range order {
		at[key] = i
	}
	out := append([]destination(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		pi, oki := at[out[i].Key]
		pj, okj := at[out[j].Key]
		switch {
		case oki && okj:
			return pi < pj
		case oki:
			return true
		case okj:
			return false
		}
		return false // both unknown: keep the table's order
	})
	return out
}

// handleNavOrder moves one destination up or down.
//
// Buttons rather than dragging. WCAG 2.2 2.5.7 says no function may require a
// drag gesture, and this project's answer has always been that reordering is
// something you press or type — which is also faster, works on a phone, and
// works for somebody using only a keyboard.
func (s *Server) handleNavOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	// Start from what this person can see, in their current arrangement, so a
	// move is relative to what is in front of them rather than to a table they
	// have never seen.
	current := applyOrder(visibleTo(s, p), storedOrder(r))
	keys := make([]string, 0, len(current))
	for _, d := range current {
		keys = append(keys, d.Key)
	}

	switch {
	case r.FormValue("reset") != "":
		clearCookie(w, r, NavOrderCookie)
		http.Redirect(w, r, "/profile#arrangement", http.StatusSeeOther)
		return
	case r.FormValue("key") != "":
		keys = move(keys, r.FormValue("key"), r.FormValue("direction"))
	}

	http.SetCookie(w, &http.Cookie{
		Name: NavOrderCookie, Value: url.QueryEscape(strings.Join(keys, ",")),
		Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil, MaxAge: 365 * 24 * 3600,
	})
	http.Redirect(w, r, "/profile#arrangement", http.StatusSeeOther)
}

// move shifts one key one place, within its own group.
//
// Within the group, because the groups are the structure and a tab that could
// wander out of its section would leave somebody with Media under
// Administration wondering what they had done. Somebody who wants a different
// structure wants a different product, and this is a preference rather than a
// redesign.
func move(keys []string, key, direction string) []string {
	group := groupOf(key)
	if group == "" {
		return keys
	}
	// Positions of this group's members, in the current arrangement.
	var idx []int
	for i, k := range keys {
		if groupOf(k) == group {
			idx = append(idx, i)
		}
	}
	for n, i := range idx {
		if keys[i] != key {
			continue
		}
		var swap int
		switch direction {
		case "up":
			if n == 0 {
				return keys
			}
			swap = idx[n-1]
		case "down":
			if n == len(idx)-1 {
				return keys
			}
			swap = idx[n+1]
		default:
			return keys
		}
		keys[i], keys[swap] = keys[swap], keys[i]
		return keys
	}
	return keys
}

func groupOf(key string) string {
	for _, d := range destinations {
		if d.Key == key {
			return d.Group
		}
	}
	return ""
}

// visibleTo is the destinations a principal may use.
func visibleTo(s *Server, p principal) []destination {
	out := make([]destination, 0, len(destinations))
	for _, d := range destinations {
		if s.Policy != nil && !s.Policy.Evaluate(p.Name, d.Needs, "/").Allowed {
			continue
		}
		out = append(out, d)
	}
	return out
}

func clearCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
	})
}
