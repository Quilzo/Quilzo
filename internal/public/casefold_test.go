// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/starter"
	"github.com/quilzo/quilzo/internal/store"
)

// refolded is text whose lower case is written in a different number of
// bytes from the text itself.
//
// Every place below found a tag in strings.ToLower(page) and cut the page at
// that offset, which is only the page's offset when lowering kept every byte
// where it was. İ is two bytes and lowers to i, one, so a Turkish title put
// each insertion a byte early per İ; Ⱥ grows from two to three, and a byte
// that is not UTF-8 grows to U+FFFD's three, so the offset overshoots and,
// near the end of a page, runs off it.
var refolded = []struct{ name, text string }{
	{"Turkish", "İstanbul, İzmir ve İzmit"},
	{"Kelvin sign", "300 \u212A ölçüldü"},
	{"growing", strings.Repeat("\u023A", 40)},
	{"not UTF-8", "caf\xe9 cr\xe8me br\xfbl\xe9e"},
}

// refoldedPage is a document with the text in every place a tag search
// passes over on its way: before <html>, in the head and in the body.
func refoldedPage(x string) string {
	return "<!doctype html>\n<!-- " + x + " -->\n<HTML lang=\"tr\"><Head><title>" + x +
		"</title><meta name=\"description\" content=\"" + x + "\"></HEAD>\n" +
		"<Body class=\"x\"><h1>" + x + "</h1><p>" + x + "</p></BODY></html>"
}

// noPanic runs f, and reports a panic as the test's failure rather than
// stopping every test after it.
func noPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s panicked: %v", what, r)
		}
	}()
	f()
}

// The page a visitor is served, with a Turkish title: the manifest link and
// everything after it go at the end of the head, after </title>, and not
// inside it.
func TestATurkishTitleKeepsTheHeadIntact(t *testing.T) {
	for _, title := range []string{"İstanbul, İzmir ve İzmit", "300 \u212A ölçüldü"} {
		st := published(t, map[string]any{"index": map[string]any{"title": title}})
		w := get(st, "/", nil)
		body := w.Body.String()
		want := "<title>" + title + "</title>\n" + `<link rel="manifest" href="/manifest.webmanifest">`
		if w.Code != http.StatusOK || !strings.Contains(body, want) {
			t.Errorf("%q: the head's markup is not at the end of the head (%d):\n%s", title, w.Code, body)
		}
		if !utf8.ValidString(body) {
			t.Errorf("%q: the page was cut inside a character", title)
		}
	}
}

// Each insertion lands exactly before or after the tag it names, in the page
// as it is, whatever the text around it lowers to.
func TestEveryInsertionLandsAtTheTagInThePageItself(t *testing.T) {
	const m = `<meta name="m">`
	for _, c := range refolded {
		page := refoldedPage(c.text)

		head := strings.Index(page, "</HEAD>")
		noPanic(t, c.name+": insertBeforeHead", func() {
			if got, want := insertBeforeHead(page, m), page[:head]+m+"\n"+page[head:]; got != want {
				t.Errorf("%s: insertBeforeHead put the markup elsewhere:\n%s", c.name, got)
			}
		})

		end := strings.LastIndex(page, "</BODY>")
		noPanic(t, c.name+": insertBeforeBodyEnd", func() {
			if got, want := insertBeforeBodyEnd(page, m), page[:end]+m+page[end:]; got != want {
				t.Errorf("%s: insertBeforeBodyEnd put the markup elsewhere:\n%s", c.name, got)
			}
		})

		open := strings.Index(page, `<HTML lang="tr">`) + len(`<HTML lang="tr">`)
		noPanic(t, c.name+": afterOpeningHTML", func() {
			if got := afterOpeningHTML([]byte(page)); got != open {
				t.Errorf("%s: afterOpeningHTML = %d, the end of <html> is at %d", c.name, got, open)
			}
		})
	}
}

// A draft shared for review with a Turkish title carries its note inside the
// body, after the body's own tag.
func TestASharedDraftWithATurkishTitleHasItsNoteInTheBody(t *testing.T) {
	st := published(t, map[string]any{"index": map[string]any{"title": "Home"}})
	const id = "0123456789abcdef0123456789abcdef"
	for _, c := range refolded {
		page := refoldedPage(c.text)
		st.Shared = func(string) (string, bool) { return page, true }
		noPanic(t, c.name+": the shared draft", func() {
			body := get(st, "/shared/"+id, nil).Body.String()
			if !strings.Contains(body, `<Body class="x">`+sharedNote) {
				t.Errorf("%s: the note is not just inside the body:\n%s", c.name, body)
			}
		})
	}
}

// The site search form is still offered to a visitor's agent, and its field
// still described, when a Turkish heading comes before it and a Turkish label
// sits inside it.
func TestFormsAfterTurkishTextAreStillTools(t *testing.T) {
	st := toolSite(t)
	for _, c := range refolded {
		page := `<h1>` + c.text + `</h1><form class="search" method="get" action="/search" role="search">` +
			`<label for="q">` + c.text + `</label><input id="q" name="q" type="search"></form><p>` + c.text + `</p>`
		noPanic(t, c.name+": annotateTools", func() {
			out := st.annotateTools(page)
			for _, want := range []string{
				`role="search" toolname="search-site"`,
				`<input id="q" name="q" type="search" toolparamdescription="Words to look for.`,
			} {
				if !strings.Contains(out, want) {
					t.Errorf("%s: missing %q in\n%s", c.name, want, out)
				}
			}
		})
	}
}

// A search result's snippet is cut around the word that matched, in the text
// itself, however the text before it lowers.
func TestASnippetIsCutAroundTheMatchInTheTextItself(t *testing.T) {
	for _, c := range []struct{ name, text, query, want string }{
		// Sixty İ lowered sixty bytes shorter, so the window fell well before
		// the word and the snippet did not contain it.
		{"Turkish", strings.Repeat("İİİİ İzmir ", 15) + "kahvaltı menüsü burada.", "MENÜSÜ", "menüsü"},
		// Ⱥ lowers a byte longer, so the offset ran past the end of the text
		// and cutting it panicked.
		{"growing", strings.Repeat("\u023A", 100) + " word", "word", "word"},
		// And a word in another case still matches beyond ASCII, as it did.
		{"Unicode case", "Une ÉCOLE à Paris, près d'İstanbul Caddesi.", "école", "ÉCOLE"},
	} {
		body := map[string]any{"body": c.text}
		noPanic(t, c.name+": snippetFor", func() {
			got := snippetFor(body, []string{"body"}, c.query)
			if !strings.Contains(got, c.want) || !utf8.ValidString(got) {
				t.Errorf("%s: the snippet for %q is %q", c.name, c.query, got)
			}
		})
	}
}

// A layout that names its own canonical address keeps it, its letters in any
// ASCII case, and the server adds one only to a page that names none. The
// question is asked of the page itself, as HTML asks it, A to Z folded and
// nothing else.
//
// It was asked of strings.ToLower of every page served on a site with an
// address: a whole-page copy left behind when the tag searches beside it
// stopped lowering the page, 5 to 7 per cent of the CPU of serving the
// fullest starter page. That copy also turned rel="canonİcal", which a
// browser and a search engine read as no canonical at all, into one, so the
// page went out without its address.
func TestTheCanonicalLinkIsLookedForInThePageItself(t *testing.T) {
	st := published(t, map[string]any{"index": map[string]any{"title": "Home"}})
	const added = `<link rel="canonical" href="https://example.org/">`
	for _, c := range []struct {
		link string
		adds bool
	}{
		{`<LINK REL="CANONICAL" HREF="https://journal.example/">`, false},
		{`<link rel="Canonical" href="https://journal.example/">`, false},
		{`<link rel="canonİcal" href="https://journal.example/">`, true},
		{`<link rel="alternate" href="https://journal.example/">`, true},
	} {
		html := `<!doctype html><html lang="en"><head><title>Home</title>` + c.link +
			`</head><body><h1>Home</h1></body></html>`
		out := st.injectHead(html, "index", "", map[string]any{"title": "Home"})
		if got := strings.Contains(out, added); got != c.adds {
			t.Errorf("%s: the server's own canonical link added: %v, want %v\n%s", c.link, got, c.adds, out)
		}
	}
}

// BenchmarkAPublicPage serves the sections starter's own sample, the fullest
// page that ships, the way a visitor's browser asks for it.
func BenchmarkAPublicPage(b *testing.B) {
	st := sampleSite(b)
	h := st.Handler()
	serve := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		return w
	}
	first := serve()
	if first.Code != http.StatusOK || first.Body.Len() < 20000 {
		b.Fatalf("the page did not render: %d, %d bytes", first.Code, first.Body.Len())
	}
	b.ReportAllocs()
	for b.Loop() {
		serve()
	}
	b.ReportMetric(float64(first.Body.Len()), "page-bytes")
}

// BenchmarkFindingTagsInAPublicPage is the part of serving that page which
// looks for tags in it: the end of the head, the end of the body and the
// forms, on the page as it was served.
func BenchmarkFindingTagsInAPublicPage(b *testing.B) {
	st := sampleSite(b)
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	page := w.Body.String()
	b.ReportAllocs()
	for b.Loop() {
		out := insertBeforeHead(page, `<link rel="stylesheet" href="/agent.css">`)
		out = insertBeforeBodyEnd(out, `<div class="qz-launch"></div>`)
		st.annotateTools(out)
	}
}

// sampleSite publishes the sections starter's sample as a site's front page,
// on a site with an address, as every site that is served has. Without one
// the head is short of its canonical link, and of the search for one that
// the page was still lowered for.
func sampleSite(b *testing.B) *Site {
	b.Helper()
	s, err := store.Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	tpl, _ := starter.Get("sections")
	html, err := tpl.HTML()
	if err != nil {
		b.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{"index": tpl.Sample}, "first", "bench"); err != nil {
		b.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		b.Fatal(err)
	}
	st := New(s, render.OneLayout(html))
	st.Name, st.Index, st.BaseURL = "Example", "index", "https://example.org"
	return st
}
