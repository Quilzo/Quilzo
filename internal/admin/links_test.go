package admin

import (
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// A link is not a route, and nothing in this project knew the two were meant
// to agree.
//
// The footer on every single page linked to /help. Nothing served /help. It
// had 404'd on every screen in the product since the footer was written, and
// it survived a red-team pass, an enterprise-customer pass, a contrast audit
// and a full test suite — because every one of those looked at pages that
// existed, and this was a page that did not.
//
// So: parse the hrefs out of the templates, parse the registrations out of the
// mux, and require the first set to be inside the second. It is the same shape
// as the coverage test in cmd/quilzo — walk the source rather than trust a
// list somebody maintains — and for the same reason, which is that the list
// somebody maintains is the thing that was wrong.
func TestEveryLinkInTheInterfaceIsServed(t *testing.T) {
	served := servedRoutes(t)
	if len(served) < 10 {
		t.Fatalf("found %d routes; the parse is wrong and a test that sees "+
			"nothing passes", len(served))
	}

	links := templateLinks(t)
	if len(links) < 10 {
		t.Fatalf("found %d links; the parse is wrong", len(links))
	}

	var dead []string
	for _, l := range links {
		if !resolves(served, l.href) {
			dead = append(dead, l.href+"  (in "+l.file+")")
		}
	}
	if len(dead) > 0 {
		sort.Strings(dead)
		t.Errorf("these links are rendered and nothing serves them:\n  %s",
			strings.Join(dead, "\n  "))
	}
}

// Every form must post somewhere that exists, for the same reason.
//
// A dead link is a 404 the person can back out of. A dead form action is work
// they had already typed.
func TestEveryFormActionIsServed(t *testing.T) {
	served := servedRoutes(t)
	var dead []string
	for _, a := range templateActions(t) {
		if !resolves(served, a.href) {
			dead = append(dead, a.href+"  (in "+a.file+")")
		}
	}
	if len(dead) > 0 {
		sort.Strings(dead)
		t.Errorf("these forms post to nothing:\n  %s", strings.Join(dead, "\n  "))
	}
}

// resolves reports whether the mux would route this path.
//
// Go's ServeMux matches a pattern ending in "/" as a prefix, so /page/ serves
// /page/about. Matching that rule here rather than comparing strings means a
// link into a subtree is not reported as dead.
//
// "/" is excluded from that rule, and excluding it is the whole difference
// between this test working and this test being decorative. It is the mux's
// catch-all, so taking it as a prefix makes every string on earth resolve —
// which is exactly what happened on the first run: the suite went green while
// seven links in the navigation pointed at nothing. handlePages answers 404
// for any path but the root, so the root is an exact match here too.
func resolves(served map[string]bool, href string) bool {
	if served[href] {
		return true
	}
	for pattern := range served {
		if pattern == "/" {
			continue
		}
		if strings.HasSuffix(pattern, "/") && strings.HasPrefix(href, pattern) {
			return true
		}
	}
	return false
}

var (
	reHandle    = regexp.MustCompile(`mux\.(?:HandleFunc|Handle)\("([^"]+)"`)
	reHandleVar = regexp.MustCompile(`mux\.(?:HandleFunc|Handle)\(([A-Za-z_]\w*),`)
	reConst     = regexp.MustCompile(`(?m)^const (\w+) = "([^"]+)"`)
	reHref      = regexp.MustCompile(`href="([^"{}]*)"`)
	reAction    = regexp.MustCompile(`action="([^"{}]*)"`)
)

func servedRoutes(t *testing.T) map[string]bool {
	t.Helper()
	// Read from disk rather than from the embedded assets: server.go is the
	// registration list, it is not embedded, and a test that walks the source
	// is the only thing that cannot fall behind it.
	b, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)

	out := map[string]bool{}
	for _, m := range reHandle.FindAllStringSubmatch(src, -1) {
		out[m[1]] = true
	}
	// A route registered through a named constant, because one of them is: the
	// upload path is exempt from the form body limit and the exemption has to
	// name the same string the registration does. Resolving the constant here
	// means the two can be written once rather than twice, which is the
	// situation that produced the duplicated navigation.
	consts := map[string]string{}
	for _, m := range reConst.FindAllStringSubmatch(src, -1) {
		consts[m[1]] = m[2]
	}
	for _, m := range reHandleVar.FindAllStringSubmatch(src, -1) {
		if v, ok := consts[m[1]]; ok {
			out[v] = true
		} else {
			t.Errorf("a route is registered through %s and this test cannot "+
				"resolve it, so anything linking to it would be reported as "+
				"dead. Declare it as a plain string constant in server.go.", m[1])
		}
	}
	return out
}

type link struct{ href, file string }

func templateLinks(t *testing.T) []link   { return scan(t, reHref) }
func templateActions(t *testing.T) []link { return scan(t, reAction) }

// scan pulls attribute values out of every template.
//
// Values containing a template action are skipped by the pattern itself: an
// href built from a variable cannot be checked against a list of routes
// without evaluating the template, and a check that guesses is worse than one
// that admits its scope.
func scan(t *testing.T, re *regexp.Regexp) []link {
	t.Helper()
	names, err := fs.Glob(assets, "assets/*.html")
	if err != nil {
		t.Fatal(err)
	}
	var out []link
	for _, name := range names {
		b, err := assets.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			href := m[1]
			// Off-site, in-page and non-navigational targets are not this
			// mux's business.
			if href == "" || strings.HasPrefix(href, "#") ||
				strings.HasPrefix(href, "http://") ||
				strings.HasPrefix(href, "https://") ||
				strings.HasPrefix(href, "mailto:") {
				continue
			}
			// A query string is not part of the route.
			if i := strings.IndexByte(href, '?'); i >= 0 {
				href = href[:i]
			}
			if href == "" {
				continue
			}
			out = append(out, link{href: href, file: strings.TrimPrefix(name, "assets/")})
		}
	}
	return out
}
