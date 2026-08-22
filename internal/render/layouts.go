package render

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Layouts is every template a site can render a page through.
//
// # Why this is here and not in the public server
//
// The site used to render every URL through one string. That is the reason a
// dashboard, a product page and a marketing page all had to live inside one
// file behind a chain of {% if %} — and the reason the demo's product card is
// written out four times, once per listing that needed it.
//
// Letting a page name its layout is a small change with one large trap, and it
// is the same trap Sources was written to close. Five things render a page: the
// public server, the detail route, the accessibility gate that refuses a
// publish, the admin preview and the static export. If each of them decides for
// itself which template a page gets, they will disagree, and the failure is
// silent in the worst direction: the gate passes a document nobody is served
// while the page readers actually receive is broken.
//
// So layout resolution happens exactly once, here, next to DetailOf — which
// reads its declaration off a page body in the same way for the same reason.
//
// # Why a missing layout is refused rather than defaulted
//
// A page naming "dashboard" on a site with no dashboard layout could quietly
// render through the default. It does not: it is an error at the point of use.
// Falling back means the page somebody wrote looks nothing like the page they
// designed, with no message anywhere, and the first person to notice is a
// reader. Refusing is louder and shorter to diagnose.
type Layouts struct {
	// byName holds the parsed source of each layout, keyed by the name a page
	// asks for. Never nil after New.
	byName map[string]string
	// fallback is the layout a page gets when it does not name one. It is
	// "page" — the file every existing store already has — so a site written
	// before layouts existed keeps rendering exactly as it did.
	fallback string
}

// DefaultLayout is the layout a page with no declaration renders through, and
// the base name of the file it comes from: templates/page.html.
const DefaultLayout = "page"

// A layout name arrives from content, and content is what users supply. It
// lands in a map lookup here and in a filename at the edges, so it is matched
// against a pattern rather than cleaned: lowercase, digits and single hyphens.
// No dots and no separators, which is what keeps "../../etc/passwd" from being
// a layout name anybody can write into a page.
var reLayout = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)

// ValidLayoutName reports whether a name may be used as a layout.
//
// Exported because the loaders at the edges — the site command, the admin, the
// starter writer — all have to refuse the same set, and three copies of a
// pattern is three chances for one of them to be looser than the others.
func ValidLayoutName(name string) bool { return reLayout.MatchString(name) }

// NewLayouts builds the set from name-to-source pairs.
//
// The default layout has to be present. A site with no page.html has nothing to
// render anything through, and reporting that here is better than every caller
// discovering it separately when a request arrives.
func NewLayouts(sources map[string]string) (Layouts, error) {
	if len(sources) == 0 {
		return Layouts{}, fmt.Errorf("no layouts: nothing can be rendered")
	}
	byName := make(map[string]string, len(sources))
	for name, src := range sources {
		if !ValidLayoutName(name) {
			return Layouts{}, fmt.Errorf(
				"%q is not a usable layout name. Lowercase letters, digits "+
					"and hyphens — it becomes both a filename and something a "+
					"page can name, so the set has to be narrow", name)
		}
		byName[name] = src
	}
	if _, ok := byName[DefaultLayout]; !ok {
		return Layouts{}, fmt.Errorf(
			"there is no %s layout. Every page that does not name one renders "+
				"through it, so it is the one layout a site cannot be without",
			DefaultLayout)
	}
	return Layouts{byName: byName, fallback: DefaultLayout}, nil
}

// OneLayout wraps a single template as the default layout.
//
// The shape every caller had before this existed, kept so a caller that
// genuinely has one template — `quilzo render` against a file named on the
// command line, a test fixture — does not have to build a map to say so.
func OneLayout(src string) Layouts {
	return Layouts{byName: map[string]string{DefaultLayout: src}, fallback: DefaultLayout}
}

// LayoutOf reads the layout a page body declares.
//
// Empty means the page did not declare one, which is the common case and is not
// an error. The second return distinguishes "declared nothing" from "declared
// something unusable", because those deserve different messages: the first is
// every page ever written before this feature, the second is a typo.
func LayoutOf(body any) (string, bool) {
	m, ok := body.(map[string]any)
	if !ok {
		return "", true
	}
	name, _ := m["layout"].(string)
	name = strings.TrimSpace(name)
	if name == "" {
		return "", true
	}
	return name, ValidLayoutName(name)
}

// For returns the template source a page renders through, and the layout name
// it resolved to.
//
// The name comes back as well as the source because callers report it: the
// export writes it into a manifest, the preview shows it, and an error that
// says which layout was chosen is the difference between a five-minute
// diagnosis and an afternoon.
func (l Layouts) For(body any) (name, src string, err error) {
	if len(l.byName) == 0 {
		return "", "", fmt.Errorf("no layouts are loaded")
	}
	declared, ok := LayoutOf(body)
	if !ok {
		return "", "", fmt.Errorf(
			"a page declares layout %q, which is not a usable name",
			declared)
	}
	if declared == "" {
		return l.fallback, l.byName[l.fallback], nil
	}
	src, found := l.byName[declared]
	if !found {
		return "", "", fmt.Errorf(
			"a page asks for the %q layout and this site has %s. A page is not "+
				"rendered through a layout it did not ask for, because the "+
				"result would be a page nobody designed and no message "+
				"anywhere saying so",
			declared, l.describe())
	}
	return declared, src, nil
}

// Source returns one layout by name.
func (l Layouts) Source(name string) (string, bool) {
	src, ok := l.byName[name]
	return src, ok
}

// Names lists the layouts, in a stable order, with the default first.
//
// Default first because that is the order somebody reads a list of choices in:
// the one you get if you say nothing, then the alternatives.
func (l Layouts) Names() []string {
	out := make([]string, 0, len(l.byName))
	for name := range l.byName {
		if name == l.fallback {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	if _, ok := l.byName[l.fallback]; ok {
		out = append([]string{l.fallback}, out...)
	}
	return out
}

// Len is how many layouts there are.
func (l Layouts) Len() int { return len(l.byName) }

// Default is the layout used by a page that names none.
func (l Layouts) Default() string { return l.fallback }

func (l Layouts) describe() string {
	names := l.Names()
	if len(names) == 1 {
		return "only " + names[0]
	}
	return strings.Join(names, ", ")
}

// Missing lists the layouts pages ask for that this set does not have.
//
// This is the check that belongs at publish time. Resolving one page at a time
// reports the first failure; an operator about to publish wants all of them,
// because fixing them one deploy at a time is how a migration takes a week.
func (l Layouts) Missing(pages map[string]any) map[string]string {
	out := map[string]string{}
	for page, body := range pages {
		declared, ok := LayoutOf(body)
		if declared == "" {
			continue
		}
		if !ok {
			out[page] = declared
			continue
		}
		if _, found := l.byName[declared]; !found {
			out[page] = declared
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
