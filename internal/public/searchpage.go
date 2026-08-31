package public

import (
	"net/http"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/search"
	"github.com/quilzo/quilzo/internal/tmpl"
)

// Search a reader can actually use.
//
// # What was unreachable, and why
//
// internal/search builds a full-text index of every published page at startup —
// hundreds of terms, ranked, with the fields each match came from — and the only
// way to reach it was /search.json. The comment there argued that a rendered
// results page was impossible:
//
//	"the template language deliberately cannot loop over something the server
//	computed at request time … A site that wants a rendered results page fetches
//	this, which is the one place a published site legitimately needs a script."
//
// Both halves were wrong.
//
// The language loops over request-time data everywhere. A listing with a
// parameter is resolved from the query string on every request and rendered as
// feeds; a detail page's record is looked up per request; the navigation is
// built per request. Search results are the same shape as feed rows and need no
// capability the renderer does not already have.
//
// And the script the second half calls for is forbidden by this site's own
// Content-Security-Policy: script-src 'none'. So the sanctioned route to the
// search feature was one the product's own security header blocks, and there is
// no setting that opens it. A feature reachable only by weakening the thing that
// makes the product what it is, is a feature nobody has.
//
// # How it works instead
//
// A GET form and a rendered page. The page named "search" — an ordinary page
// somebody published — is rendered with the results in its context, so the
// design comes from the same layouts as everything else and the whole exchange
// is one navigation with no script anywhere.
//
// # What a static copy can do
//
// Nothing, and it says so by 404ing: search is a question answered per request,
// like a form submission. The search page itself is in a bundle, its form is
// rendered, and a static host has nothing to answer it with. That is a property
// of static hosting rather than of this route, and it is the reason the page
// exists as a page rather than as a route with markup inside it.

// searchPageName is the page rendered for results.
//
// Fixed rather than configurable: a search page at a name only the operator
// knows is a search page no reader finds, and every layout that offers a search
// box has to know where to point it.
const searchPageName = "search"

// searchPage renders results through the site's own layouts.
func (st *Site) searchPage(w http.ResponseWriter, r *http.Request) {
	pages, hashes, err := st.pages()
	if err != nil {
		http.Error(w, "the site could not be read", http.StatusInternalServerError)
		return
	}
	body, published := pages[searchPageName]
	if !published {
		// No page, no results screen. Answering with a bare list of links
		// would be a page nobody designed, on a site whose whole claim is that
		// what is served is what somebody published.
		st.notFound(w, r)
		return
	}

	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(query) > maxQuery {
		// Bounded before tokenising, for the reason /search.json gives: a very
		// long query is not a search, and tokenising it is work somebody else
		// chose for this machine to do.
		http.Error(w, "the query is too long", http.StatusBadRequest)
		return
	}

	ctx, cerr := st.sources().For(searchPageName, body, firstOf(r.URL.Query()))
	if cerr != nil {
		http.Error(w, "this page could not be assembled",
			http.StatusInternalServerError)
		return
	}
	ctx["search"] = st.searchData(query, pages)

	_, layout, lerr := st.Layouts.For(body)
	if lerr != nil {
		http.Error(w, "this page could not be assembled",
			http.StatusInternalServerError)
		return
	}
	html, rerr := tmpl.Render(layout, ctx)
	if rerr != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	html = st.injectHead(html, searchPageName, hashes[searchPageName], body)

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	// No caching, for the reason the JSON route gives: a results page cached by
	// a proxy is a results page served to somebody who searched for something
	// else.
	h.Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(html))
}

// maxQuery bounds a query before it is tokenised.
const maxQuery = 200

// searchData is the results, in the shape a template reads.
//
// Plain maps and slices, like feeds and menus, because that is all the template
// language understands. An empty query is not an empty result set: the page has
// to be able to tell "you have not searched yet" from "nothing matched", and
// with no else in the language that means two booleans rather than one.
func (st *Site) searchData(query string, pages map[string]any) map[string]any {
	data := map[string]any{
		"query": query, "asked": query != "", "results": []any{},
		"count": float64(0), "empty": false,
	}
	if query == "" || st.Search == nil {
		return data
	}

	found := st.Search.Search(query, 20)
	rows := make([]any, 0, len(found))
	for _, res := range found {
		title := res.Title
		if title == "" {
			title = res.Page
		}
		href := "/" + res.Page
		if res.Page == st.indexName() {
			href = "/"
		}
		rows = append(rows, map[string]any{
			"title": title, "href": href, "page": res.Page,
			"snippet": snippetFor(pages[res.Page], res.Fields, query),
			// Where it matched, so a result says why it is here rather than
			// appearing by magic — the reason internal/search keeps Fields.
			"fields": strings.Join(res.Fields, ", "),
		})
	}
	data["results"] = rows
	data["count"] = float64(len(rows))
	data["empty"] = len(rows) == 0
	return data
}

// snippetFor is a line of context from the field a result matched in.
//
// Built here rather than stored in the index, because the index holds terms and
// the pages hold text: keeping a copy of every field's prose in the index would
// double what a search costs in memory to save what a lookup already has.
func snippetFor(body any, fields []string, query string) string {
	m, ok := body.(map[string]any)
	if !ok {
		return ""
	}
	terms := strings.Fields(strings.ToLower(query))
	sort.Strings(fields)
	for _, field := range fields {
		// Every string in the field, however deep — through the same traversal
		// the indexer used. A page's prose lives inside its sections, so
		// reading only the field's own top level found nothing to quote and
		// every result on a real site came out with an empty snippet.
		for _, text := range search.Strings(m[field]) {
			lower := strings.ToLower(text)
			for _, term := range terms {
				at := strings.Index(lower, term)
				if at < 0 {
					continue
				}
				return cutAround(text, at, len(term))
			}
		}
	}
	// A match in a field with no readable text — a boolean, a number — is still
	// a match, and an empty snippet is better than a misleading one.
	return ""
}

// cutAround takes about a line of text with the match inside it.
func cutAround(text string, at, length int) string {
	const window = 90
	start := at - window/2
	if start < 0 {
		start = 0
	}
	end := at + length + window/2
	if end > len(text) {
		end = len(text)
	}
	// Cut on a space where there is one nearby, so a snippet does not begin
	// mid-word.
	if start > 0 {
		if i := strings.IndexByte(text[start:], ' '); i >= 0 && i < 20 {
			start += i + 1
		}
	}
	if end < len(text) {
		if i := strings.LastIndexByte(text[:end], ' '); i > start {
			end = i
		}
	}
	// Collapsed to one line. A snippet is a line of context, and a field
	// holding a code example or a list of paragraphs carries newlines that
	// render inside a paragraph as one long run — seen on a page whose match
	// was in a recipe.
	out := strings.Join(strings.Fields(text[start:end]), " ")
	if start > 0 {
		out = "… " + out
	}
	if end < len(text) {
		out += " …"
	}
	return out
}
