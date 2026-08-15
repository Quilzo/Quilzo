package seo

import (
	"encoding/xml"
	"strings"
	"testing"
	"time"
)

func day(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 14, 30, 0, 0, time.UTC)
}

// -- sitemap -----------------------------------------------------------------

func TestASitemapIsValidXML(t *testing.T) {
	out, err := Sitemap([]Entry{
		{Loc: "https://example.com/", LastMod: day(2026, 8, 15)},
		{Loc: "https://example.com/about"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		URLs []struct {
			Loc     string `xml:"loc"`
			LastMod string `xml:"lastmod"`
		} `xml:"url"`
	}
	if err := xml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("the sitemap does not parse: %v\n%s", err, out)
	}
	if len(parsed.URLs) != 2 {
		t.Fatalf("got %d urls", len(parsed.URLs))
	}
	if parsed.URLs[0].LastMod != "2026-08-15" {
		t.Errorf("lastmod is %q", parsed.URLs[0].LastMod)
	}
	// An unknown date is omitted, not filled in with today. A guessed lastmod
	// is exactly the lie that makes crawlers stop trusting the field.
	if parsed.URLs[1].LastMod != "" {
		t.Errorf("an unknown lastmod was invented: %q", parsed.URLs[1].LastMod)
	}
}

// Google states plainly that it ignores both. Emitting them adds bytes to every
// crawl and invites somebody to spend an afternoon tuning numbers that do
// nothing.
func TestPriorityAndChangefreqAreNotEmitted(t *testing.T) {
	out, err := Sitemap([]Entry{{Loc: "https://example.com/"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, dead := range []string{"priority", "changefreq"} {
		if strings.Contains(out, dead) {
			t.Errorf("the sitemap emits <%s>, which Google ignores", dead)
		}
	}
}

// A page name containing an ampersand producing an invalid sitemap is a failure
// nobody notices until a crawler quietly stops reading it.
func TestURLsAreEscapedIntoValidXML(t *testing.T) {
	out, err := Sitemap([]Entry{
		{Loc: `https://example.com/a?x=1&y=2`},
		{Loc: `https://example.com/<script>`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "x=1&y=2") {
		t.Error("a raw ampersand was emitted, which makes the XML invalid")
	}
	var parsed struct {
		URLs []struct {
			Loc string `xml:"loc"`
		} `xml:"url"`
	}
	if err := xml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("the sitemap does not parse: %v", err)
	}
	if parsed.URLs[0].Loc != "https://example.com/a?x=1&y=2" {
		t.Errorf("round trip lost the URL: %q", parsed.URLs[0].Loc)
	}
}

// A file over the limit is not truncated by a crawler, it is rejected — so
// producing one silently would mean a site with no working sitemap at all.
func TestTheURLLimitIsEnforced(t *testing.T) {
	many := make([]Entry, MaxURLsPerSitemap+1)
	for i := range many {
		many[i] = Entry{Loc: "https://example.com/p"}
	}
	if _, err := Sitemap(many); err == nil {
		t.Error("a sitemap over the 50,000 URL limit was produced")
	}
	if !strings.Contains(mustErr(t, many), "index") {
		t.Error("the error should say a sitemap index is needed")
	}
}

func mustErr(t *testing.T, e []Entry) string {
	t.Helper()
	_, err := Sitemap(e)
	if err == nil {
		t.Fatal("expected an error")
	}
	return err.Error()
}

// -- redirects ---------------------------------------------------------------

// Google's crawler follows a limited number of hops, so a URL three or four
// deep may never be crawled to its destination and the PageRank at the origin
// never arrives. Flattening at write time makes a chain impossible to store
// rather than something to remember not to create.
func TestChainsAreFlattenedAtWriteTime(t *testing.T) {
	m, err := NewMap([]Redirect{
		{From: "/old", To: "/middle", Permanent: true},
		{From: "/middle", To: "/new", Permanent: true},
		{From: "/ancient", To: "/old", Permanent: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, from := range []string{"/old", "/ancient"} {
		r, ok := m.Lookup(from)
		if !ok {
			t.Fatalf("%s was lost", from)
		}
		if r.To != "/new" {
			t.Errorf("%s points at %s; every hop should resolve to the final "+
				"destination", from, r.To)
		}
	}
	// And the flattening is recorded, so somebody reading the map later can
	// see it was not typed that way.
	if r, _ := m.Lookup("/ancient"); !strings.Contains(r.Note, "flattened") {
		t.Errorf("the flattening was not recorded: %q", r.Note)
	}
}

func TestLoopsAreRefused(t *testing.T) {
	for _, cycle := range [][]Redirect{
		{{From: "/a", To: "/b"}, {From: "/b", To: "/a"}},
		{{From: "/a", To: "/b"}, {From: "/b", To: "/c"}, {From: "/c", To: "/a"}},
	} {
		if _, err := NewMap(cycle); err == nil {
			t.Errorf("a redirect loop was accepted: %v", cycle)
		}
	}
	if _, err := NewMap([]Redirect{{From: "/a", To: "/a"}}); err == nil {
		t.Error("a self-redirect was accepted")
	}
}

// Two rules for the same source with different destinations is a contradiction,
// and resolving it by ordering means the behaviour depends on which line
// somebody happened to add first.
func TestContradictoryRulesAreRefused(t *testing.T) {
	_, err := NewMap([]Redirect{
		{From: "/a", To: "/b"},
		{From: "/a/", To: "/c"}, // same source after normalisation
	})
	if err == nil {
		t.Fatal("two destinations for one source were accepted")
	}
	if !strings.Contains(err.Error(), "ordering") {
		t.Errorf("the error should say why this cannot be resolved: %v", err)
	}
	// The same rule twice is fine.
	if _, err := NewMap([]Redirect{
		{From: "/a", To: "/b"}, {From: "/a/", To: "/b"},
	}); err != nil {
		t.Errorf("a duplicate of the same rule was refused: %v", err)
	}
}

// /a/ and /a are the same place. Treating them differently is how a map
// develops a contradiction nobody can see by reading it.
func TestPathsAreNormalisedBeforeComparison(t *testing.T) {
	m, err := NewMap([]Redirect{{From: "https://old.example/blog/post/", To: "/post"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, ask := range []string{"/blog/post", "/blog/post/", "//blog//post"} {
		if _, ok := m.Lookup(ask); !ok {
			t.Errorf("%s did not match the rule", ask)
		}
	}
}

// javascript: or data: in a Location header is an open redirect with extra
// steps, and the browser will follow it.
func TestDangerousRedirectTargetsAreRefused(t *testing.T) {
	for _, target := range []string{
		"javascript:alert(1)", "data:text/html,<script>x</script>",
		"file:///etc/passwd", "vbscript:msgbox",
	} {
		if _, err := NewMap([]Redirect{{From: "/a", To: target}}); err == nil {
			t.Errorf("a redirect to %q was accepted", target)
		}
	}
	// An ordinary off-site redirect is legitimate and must still work.
	if _, err := NewMap([]Redirect{
		{From: "/a", To: "https://elsewhere.example/x"}}); err != nil {
		t.Errorf("an off-site redirect was refused: %v", err)
	}
}

// A query string in a source cannot be matched reliably, because parameter
// order is not fixed. Refusing is better than accepting a rule that never
// fires.
func TestAQueryStringInASourceIsRefused(t *testing.T) {
	if _, err := NewMap([]Redirect{{From: "/a?id=1", To: "/b"}}); err == nil {
		t.Error("a redirect source with a query string was accepted")
	}
	// On the target it is fine, and must be preserved.
	m, err := NewMap([]Redirect{{From: "/a", To: "/b?ref=old"}})
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := m.Lookup("/a"); r.To != "/b?ref=old" {
		t.Errorf("the target query string was lost: %q", r.To)
	}
}

// 308 rather than 301: equivalent to search engines, and 308 preserves the
// request method where 301 permits a browser to turn a POST into a GET.
func TestPermanentRedirectsUse308(t *testing.T) {
	if got := (Redirect{Permanent: true}).Status(); got != 308 {
		t.Errorf("a permanent redirect is %d; 301 lets a browser silently "+
			"change POST to GET", got)
	}
	if got := (Redirect{Permanent: false}).Status(); got != 307 {
		t.Errorf("a temporary redirect is %d", got)
	}
}

func TestATraversalPathIsRefused(t *testing.T) {
	if _, err := NewMap([]Redirect{{From: "/../../etc/passwd", To: "/x"}}); err == nil {
		t.Error("a traversal source was accepted")
	}
}

func TestAnEmptyMapIsUsable(t *testing.T) {
	m, err := NewMap(nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Len() != 0 {
		t.Error("an empty map is not empty")
	}
	if _, ok := m.Lookup("/anything"); ok {
		t.Error("an empty map matched something")
	}
	// A nil map must be safe to call, since the server holds one before any
	// redirects are configured.
	var nilMap *Map
	if _, ok := nilMap.Lookup("/x"); ok || nilMap.Len() != 0 {
		t.Error("a nil map is not inert")
	}
}

// The scheme check has to model RFC 3986 rather than search for "://", or
// javascript: and data: slip past as relative paths. It also has to leave
// genuine relative paths alone, including the ones containing a colon.
func TestSchemeDetectionMatchesTheGrammar(t *testing.T) {
	cases := map[string]string{
		"javascript:alert(1)":   "javascript",
		"JavaScript:alert(1)":   "javascript",
		"data:text/html,x":      "data",
		"vbscript:msgbox":       "vbscript",
		"https://example.com/a": "https",
		"http://example.com/a":  "http",
		"h+t-t.p1://x/":         "h+t-t.p1",
		// Relative references, which must not be mistaken for schemes.
		"/a:b":       "",
		"/blog/post": "",
		"post":       "",
		"./a":        "",
		"":           "",
		":leading":   "",
		"1scheme:/x": "", // a scheme cannot start with a digit
	}
	for in, want := range cases {
		if got := schemeOf(in); got != want {
			t.Errorf("schemeOf(%q) = %q, wanted %q", in, got, want)
		}
	}
}

// A path that happens to contain a colon is still a path.
func TestRelativeTargetsWithColonsStillWork(t *testing.T) {
	m, err := NewMap([]Redirect{{From: "/old", To: "/notes/10:30-standup"}})
	if err != nil {
		t.Fatalf("a relative path containing a colon was refused: %v", err)
	}
	if r, _ := m.Lookup("/old"); r.To != "/notes/10:30-standup" {
		t.Errorf("the target was altered: %q", r.To)
	}
}

// A sitemap declares hreflang with xhtml:link. Only for translations that
// exist — telling a crawler a page is available in a language it is not means
// offering it to a reader who then finds it missing.
func TestAlternatesAreEmittedAsXHTMLLinks(t *testing.T) {
	out, err := Sitemap([]Entry{{
		Loc: "https://example.com/about",
		Alternates: []Alternate{
			{Locale: "en", Href: "https://example.com/about"},
			{Locale: "fr", Href: "https://example.com/fr/about"},
			{Locale: "x-default", Href: "https://example.com/about"},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`xmlns:xhtml="http://www.w3.org/1999/xhtml"`,
		`hreflang="fr"`, `href="https://example.com/fr/about"`,
		`hreflang="x-default"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the sitemap omits %q:\n%s", want, out)
		}
	}
	var parsed struct {
		URLs []struct {
			Loc   string `xml:"loc"`
			Links []struct {
				Rel      string `xml:"rel,attr"`
				Hreflang string `xml:"hreflang,attr"`
				Href     string `xml:"href,attr"`
			} `xml:"link"`
		} `xml:"url"`
	}
	if err := xml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("the sitemap does not parse: %v", err)
	}
	if len(parsed.URLs[0].Links) != 3 {
		t.Errorf("got %d alternates", len(parsed.URLs[0].Links))
	}
}

// A single-language site's sitemap must be unchanged by this feature existing.
func TestASingleLanguageSitemapDeclaresNoExtraNamespace(t *testing.T) {
	out, err := Sitemap([]Entry{{Loc: "https://example.com/"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "xhtml") {
		t.Errorf("a sitemap with no alternates declares the xhtml namespace:\n%s",
			out)
	}
}

// -- what a redirect target may contain --------------------------------------

// Found by fuzzing. A backslash is a forward slash to a browser — the WHATWG
// URL standard says so for special schemes — so Location: /\evil.example is
// read as an authority and the visitor arrives at evil.example. Collapsing
// repeated slashes without collapsing backslashes checked the separator
// somebody polite would type.
func TestABackslashAuthorityIsNotAnOpenRedirect(t *testing.T) {
	for _, to := range []string{
		`/\evil.example`, `\\evil.example`, `\/evil.example`,
		`/\/evil.example`, `//evil.example`, `/\\evil.example/path`,
	} {
		m, err := NewMap([]Redirect{{From: "/a", To: to}})
		if err != nil {
			continue // refused outright is also correct
		}
		r, ok := m.Lookup("/a")
		if !ok {
			continue
		}
		got := r.To
		if strings.HasPrefix(got, "//") || strings.HasPrefix(got, `/\`) ||
			strings.HasPrefix(got, `\`) {
			t.Errorf("%q became %q, which a browser reads as an authority",
				to, got)
		}
	}
}

// A control character is refused when the rule is written, not filtered when
// it is emitted. Go's header writer turns a newline into a space, so this was
// never response splitting; the map is also exported to CDN and web-server
// configuration, where a line is a rule.
func TestControlCharactersAreRefusedInARule(t *testing.T) {
	for _, bad := range []string{
		"java\nscript:alert(1)", "/a\nRedirect /b https://evil.example",
		"/a\r\nX: y", "/a\x00b", "/a\tb", "/ok\x1b[2J",
	} {
		if _, err := NewMap([]Redirect{{From: "/x", To: bad}}); err == nil {
			t.Errorf("target %q was accepted", bad)
		}
		if _, err := NewMap([]Redirect{{From: bad, To: "/ok"}}); err == nil {
			t.Errorf("source %q was accepted", bad)
		}
	}
}

// And the ordinary rules an administrator actually writes must survive all of
// that, including the off-site redirect that is a legitimate thing to want.
func TestNormalRedirectRulesAreStillAccepted(t *testing.T) {
	m, err := NewMap([]Redirect{
		{From: "/old", To: "/new", Permanent: true},
		{From: "/shop", To: "https://partner.example/catalogue"},
		{From: "/a/b/", To: "/a/c?utm_source=x"},
		{From: "https://old.example/legacy", To: "/modern"},
	})
	if err != nil {
		t.Fatalf("a map of ordinary rules was refused: %v", err)
	}
	if m.Len() != 4 {
		t.Errorf("kept %d of 4 rules", m.Len())
	}
	if r, ok := m.Lookup("/shop"); !ok || r.To != "https://partner.example/catalogue" {
		t.Errorf("the off-site redirect did not survive: %+v", r)
	}
}

// A percent-encoded control character is three printable characters going in
// and a raw one coming out, if anything in between decodes it — and url.Parse
// does, on the branch that strips a hostname from a target.
//
// Found by fuzzing, by a route that also explains it: collapsing backslashes
// to slashes turned \:\\ into /://, manufacturing the scheme separator that
// sent the value down the URL-parsing branch in the first place. A check
// placed before a transformation is a check on a different string, so the
// value is checked again on the way out.
func TestAPercentEncodedControlCharacterCannotSurviveNormalisation(t *testing.T) {
	for _, to := range []string{
		"/a%00b",
		"/a%0Ab",
		"/a%0D%0AX-Injected:%20yes",
		`0000000000000000000\:\\%00x`,
		"https://ok.example/a%0Ab",
		"/a%09b",
	} {
		m, err := NewMap([]Redirect{{From: "/x", To: to}})
		if err != nil {
			continue // refused outright is the other correct answer
		}
		r, ok := m.Lookup("/x")
		if !ok {
			continue
		}
		if err := noControls(r.To); err != nil {
			t.Errorf("%q normalised to %q, which carries a control "+
				"character: %v", to, r.To, err)
		}
	}
}

// And the same on the source side, since a rule's key is exported too.
func TestAPercentEncodedControlCharacterIsRefusedInASource(t *testing.T) {
	for _, from := range []string{"/a%00b", "/a%0D%0Ab", `/a\:\\%0Ab`} {
		if _, err := NewMap([]Redirect{{From: from, To: "/ok"}}); err == nil {
			// Accepted is only correct if the stored key is clean, and the
			// key is what normalisePath returned.
			got, nerr := normalisePath(from)
			if nerr != nil {
				continue
			}
			if err := noControls(got); err != nil {
				t.Errorf("%q normalised to %q: %v", from, got, err)
			}
		}
	}
}
