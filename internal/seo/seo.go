// Package seo produces the two artefacts that decide whether a migration keeps
// its search rankings: a sitemap and a redirect map.
//
// # lastmod, and why this one is true
//
// Google and Bing both say lastmod is the field that matters in a sitemap, and
// both say they ignore priority and changefreq entirely. Google also says
// something less often quoted: it may stop trusting lastmod altogether on sites
// where the value changes without the content changing.
//
// That caveat exists because almost every CMS lies. lastmod is emitted as the
// row's updated_at, which moves when an editor opens a page and saves it
// without changing a word, when a bulk operation touches every row, when a
// plugin rewrites metadata. The date is real; the claim it makes — that the
// content meaningfully changed — is not.
//
// Here it cannot be wrong. Content is addressed by hash, so a page's identity
// *is* its content, and "when did this page last change" has an exact answer:
// the commit where its object id stopped matching the previous one. Editing a
// page and saving the same bytes produces the same id, so the date does not
// move. Republishing the whole site does not move it either.
//
// This is the rare case where an architectural decision made for one reason
// turns out to satisfy an external requirement nobody could otherwise meet.
//
// # Redirects
//
// A migration loses rankings when old URLs stop resolving. The research is
// consistent: a 1:1 map has to exist before launch rather than after, chains
// beyond two hops may never be followed to the end, and redirects should stay
// for at least a year and preferably forever.
//
// So chains are flattened at write time rather than followed at request time —
// a → b → c becomes a → c and b → c, which makes a chain impossible to create
// rather than something to avoid. Loops are refused. And because the importer
// knows the URL every page had in the old system, the map is generated rather
// than typed.
package seo

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// MaxURLsPerSitemap is the hard limit both Google and Bing enforce. Beyond it a
// sitemap index is required, and a file over the limit is not truncated by the
// crawler — it is rejected.
const MaxURLsPerSitemap = 50000

// MaxSitemapBytes is the other hard limit, uncompressed.
const MaxSitemapBytes = 50 << 20

// Entry is one URL in a sitemap.
type Entry struct {
	// Loc is the absolute URL.
	Loc string
	// LastMod is when the page's content last actually changed, which here
	// means the commit where its object id stopped matching the previous one.
	// Zero means unknown, and unknown is omitted rather than filled in with
	// today — a guessed lastmod is exactly the lie that makes crawlers stop
	// trusting the field.
	LastMod time.Time
}

// Sitemap renders a sitemap.
//
// priority and changefreq are deliberately absent. Google states plainly that
// it ignores both, so emitting them adds bytes to every crawl and invites
// somebody to spend an afternoon tuning numbers that do nothing.
func Sitemap(entries []Entry) (string, error) {
	if len(entries) > MaxURLsPerSitemap {
		return "", fmt.Errorf(
			"%d URLs is over the %d limit; a sitemap index is needed",
			len(entries), MaxURLsPerSitemap)
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
	for _, e := range entries {
		b.WriteString("  <url>\n")
		b.WriteString("    <loc>" + escapeXML(e.Loc) + "</loc>\n")
		if !e.LastMod.IsZero() {
			// W3C Datetime. Date-only is permitted and is the honest precision:
			// the commit has a timestamp, but "this changed on this day" is the
			// claim being made.
			b.WriteString("    <lastmod>" +
				e.LastMod.UTC().Format("2006-01-02") + "</lastmod>\n")
		}
		b.WriteString("  </url>\n")
	}
	b.WriteString("</urlset>\n")

	out := b.String()
	if len(out) > MaxSitemapBytes {
		return "", fmt.Errorf("the sitemap is %d bytes, over the %d limit",
			len(out), MaxSitemapBytes)
	}
	return out, nil
}

// escapeXML escapes the five characters that must be escaped in XML content.
//
// Hand-written rather than reached for from a library because the set is fixed
// and small, and because a page name containing an ampersand producing an
// invalid sitemap is a failure nobody notices until a crawler stops reading.
func escapeXML(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// -- redirects ---------------------------------------------------------------

// Redirect is one old path pointing at one new path.
type Redirect struct {
	// From is a path, always beginning with a slash. Not a URL: a redirect map
	// that carries hostnames is a redirect map that breaks when the site moves.
	From string `json:"from"`
	To   string `json:"to"`
	// Permanent chooses between 308 and 307.
	//
	// 308 rather than 301: they are equivalent to search engines, and 308
	// preserves the request method where 301 permits a browser to turn a POST
	// into a GET. That silent method change is a real bug for anything that
	// posts, and there is no cost to not having it.
	Permanent bool `json:"permanent"`
	// Note records where the entry came from, which matters when somebody finds
	// a redirect three years later and wonders whether it can go.
	Note string `json:"note,omitempty"`
}

// Status is the HTTP status this redirect uses.
func (r Redirect) Status() int {
	if r.Permanent {
		return 308
	}
	return 307
}

// Map is a set of redirects with no chains and no loops.
type Map struct {
	Redirects []Redirect `json:"redirects"`
	index     map[string]Redirect
}

// NewMap builds a map, flattening chains and refusing loops.
//
// Flattening at write time rather than following at request time is the whole
// design. Google's crawler follows a limited number of hops, and a URL three or
// four deep in a chain may never be crawled to its destination — so the
// PageRank at the origin never arrives. Making a chain impossible to store is
// better than documenting that chains are bad.
func NewMap(in []Redirect) (*Map, error) {
	m := &Map{index: map[string]Redirect{}}

	// Normalise first, so /a/ and /a are not two different keys with different
	// destinations — which is how a redirect map develops a contradiction
	// nobody can see by reading it.
	byFrom := map[string]Redirect{}
	for _, r := range in {
		from, err := normalisePath(r.From)
		if err != nil {
			return nil, fmt.Errorf("redirect from %q: %w", r.From, err)
		}
		to, err := normaliseTarget(r.To)
		if err != nil {
			return nil, fmt.Errorf("redirect to %q: %w", r.To, err)
		}
		if from == to {
			return nil, fmt.Errorf("%s redirects to itself", from)
		}
		if existing, dup := byFrom[from]; dup && existing.To != to {
			return nil, fmt.Errorf(
				"%s is redirected to both %s and %s; which one applies would "+
					"depend on ordering", from, existing.To, to)
		}
		r.From, r.To = from, to
		byFrom[from] = r
	}

	// Resolve each destination to its final target, refusing cycles.
	for from, r := range byFrom {
		seen := map[string]bool{from: true}
		target := r.To
		hops := 0
		for {
			next, chained := byFrom[target]
			if !chained {
				break
			}
			if seen[target] {
				return nil, fmt.Errorf(
					"redirect loop: %s eventually points back at itself", from)
			}
			seen[target] = true
			target = next.To
			if hops++; hops > 64 {
				return nil, fmt.Errorf("redirect chain from %s is longer than "+
					"64 hops", from)
			}
		}
		if target != r.To {
			r.Note = strings.TrimSpace(r.Note + fmt.Sprintf(
				" (flattened from %s, which redirected onward)", r.To))
			r.To = target
		}
		m.index[from] = r
	}

	for _, r := range m.index {
		m.Redirects = append(m.Redirects, r)
	}
	sort.Slice(m.Redirects, func(i, j int) bool {
		return m.Redirects[i].From < m.Redirects[j].From
	})
	return m, nil
}

// Lookup finds a redirect for a request path.
func (m *Map) Lookup(path string) (Redirect, bool) {
	if m == nil {
		return Redirect{}, false
	}
	norm, err := normalisePath(path)
	if err != nil {
		return Redirect{}, false
	}
	r, ok := m.index[norm]
	return r, ok
}

// Len reports how many redirects are held.
func (m *Map) Len() int {
	if m == nil {
		return 0
	}
	return len(m.index)
}

// normalisePath makes a source path comparable.
func normalisePath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("empty")
	}
	// A full URL is accepted and reduced to its path, because that is what a
	// WordPress export contains and asking people to strip it by hand is asking
	// for a map with hostnames in half the rows.
	if strings.Contains(p, "://") {
		u, err := url.Parse(p)
		if err != nil {
			return "", err
		}
		p = u.Path
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	// A query string in a redirect source cannot be matched reliably — the
	// order of parameters is not fixed — so it is refused rather than silently
	// ignored, which would produce a rule that never fires.
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		return "", fmt.Errorf("a redirect source cannot carry a query string " +
			"or fragment; parameter order is not fixed, so the rule would " +
			"match unpredictably")
	}
	// Collapse repeated slashes and strip the trailing one, so /a//b/ and /a/b
	// are the same key.
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	if strings.Contains(p, "..") {
		return "", fmt.Errorf("a redirect path cannot contain ..")
	}
	return p, nil
}

// normaliseTarget allows an absolute URL, since a redirect off-site is a real
// thing, but refuses anything that is not http(s).
func normaliseTarget(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("empty")
	}
	// Any scheme at all, not just the ones written with "://". The first
	// version tested for "://" and let javascript: and data: through to be
	// treated as relative paths — mangled rather than exploited, but a check
	// that quietly rewrites hostile input is a check that will eventually be
	// moved somewhere it does not rewrite it.
	if scheme := schemeOf(p); scheme != "" {
		if scheme != "http" && scheme != "https" {
			return "", fmt.Errorf("scheme %q is not allowed in a redirect "+
				"target; javascript: and data: in a Location header are an "+
				"open redirect with extra steps", scheme)
		}
		u, err := url.Parse(p)
		if err != nil {
			return "", err
		}
		if u.Host == "" {
			return "", fmt.Errorf("a redirect target with a scheme needs a host")
		}
		return u.String(), nil
	}
	// A relative target is a path, and gets the same treatment as a source
	// except that a query string is fine on the way out.
	base, query, hasQuery := strings.Cut(p, "?")
	norm, err := normalisePath(base)
	if err != nil {
		return "", err
	}
	if hasQuery {
		return norm + "?" + query, nil
	}
	return norm, nil
}

// schemeOf returns the URI scheme of a reference, or empty if it is relative.
//
// RFC 3986: a scheme is ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) then ":".
// A relative reference cannot have a colon in its first path segment, which is
// what makes this decidable — /a:b is a path, a:b is a URI.
func schemeOf(s string) string {
	if strings.HasPrefix(s, "/") {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			continue
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
			continue
		case c == ':' && i > 0:
			return strings.ToLower(s[:i])
		}
		return ""
	}
	return ""
}

// SourcePath normalises a redirect source, so callers building a map can tell
// whether a URL actually moved before emitting an entry for it.
//
// Exported because the importer needs exactly this comparison: most pages keep
// their path across a migration, and emitting self-redirects for them produces
// a map that NewMap refuses in full.
func SourcePath(p string) (string, error) { return normalisePath(p) }
