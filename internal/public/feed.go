package public

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/listing"
)

// A feed, which this program did not have.
//
// # What was missing
//
// A CMS with an article starter, a journal in every example and a listing
// mechanism that already answers "the newest N of these" published no feed of
// any kind. Not RSS, not Atom, not JSON Feed. The demo site's own copy said
// "there is no newsletter — the page is here, and it has a feed if you use one",
// which was written in good faith and was false.
//
// # Why it is a listing rather than a scan of the pages
//
// Because which things belong in a feed is a decision, and the site already has
// a place to write decisions like that down. A feed built by walking every page
// would carry the terms page and the delivery page, and the way to stop it would
// be a second exclusion list nobody remembers to update. A listing already says
// what it selects, in what order, with what limit, and exposes only the fields
// it names — so a feed cannot leak a field the same listing keeps off a page.
//
// # Why Atom and JSON Feed and not RSS 2.0
//
// Atom because it is the one with a specification that answers the questions —
// dates are RFC 3339, ids are opaque, content type is declared — and RSS 2.0
// because it is what half the readers still want is a claim nobody has checked
// since about 2011. JSON Feed because the things reading feeds now are as often
// programs as they are readers, and handing a program XML to parse is a courtesy
// nobody asked for.
//
// Both come from the same rows in the same order, so a reader cannot see a
// different journal from a program.

// feedRoutes are the addresses a feed is served at.
//
// Fixed names rather than configurable ones: a feed at a path nobody can guess
// is a feed nobody finds, and both of these are where a reader's software looks.
const (
	atomPath = "/feed.xml"
	jsonPath = "/feed.json"
)

// feed serves the declared feed listing as Atom or JSON Feed.
func (st *Site) feed(w http.ResponseWriter, r *http.Request) {
	if st.Feed == "" || st.Listings == nil || st.Listings.Set == nil {
		// Nothing declared, nothing served. An empty feed is a claim that this
		// site publishes nothing, which is a different and worse thing to say
		// than "this site has no feed".
		http.NotFound(w, r)
		return
	}
	if st.BaseURL == "" {
		// A feed is a list of absolute URLs by definition, and Host is
		// attacker-controlled — the same reason the sitemap refuses.
		http.Error(w, "no base URL is configured, so a feed cannot name its "+
			"own entries; set site.base_url", http.StatusNotFound)
		return
	}

	l, ok := st.Listings.Set.Get(st.Feed)
	if !ok {
		http.Error(w, "the configured feed listing does not exist",
			http.StatusInternalServerError)
		return
	}
	idx, err := st.Listings.Index.For(st.Listings.Store, st.Listings.Tree,
		l.Collection)
	if err != nil {
		http.Error(w, "the feed could not be read", http.StatusInternalServerError)
		return
	}
	res, err := listing.Resolve(l, idx, nil)
	if err != nil {
		http.Error(w, "the feed could not be read", http.StatusInternalServerError)
		return
	}

	entries := st.feedEntries(l, res.Rows)
	updated := time.Unix(0, 0).UTC()
	for _, e := range entries {
		if e.at.After(updated) {
			updated = e.at
		}
	}

	h := w.Header()
	h.Set("Cache-Control", "public, max-age=300")
	if strings.HasSuffix(r.URL.Path, ".json") {
		st.jsonFeed(w, entries, updated)
		return
	}
	st.atomFeed(w, entries, updated)
}

// feedEntry is one item, in the shape both formats need.
type feedEntry struct {
	id      string
	title   string
	link    string
	summary string
	at      time.Time
}

// feedEntries turns listing rows into entries.
//
// Only fields the listing exposes, which is what keeps a feed from becoming a
// second, wider view of a collection. A row with no title is skipped: an entry
// whose title is empty renders in a reader as a blank line that cannot be
// clicked, and the row is almost certainly not an article.
func (st *Site) feedEntries(l *listing.Listing, rows []listing.Row) []feedEntry {
	base := strings.TrimSuffix(st.BaseURL, "/")
	detail := st.detailBase(l)

	out := make([]feedEntry, 0, len(rows))
	for _, row := range rows {
		title := firstText(row, "title", "name", "headline")
		if title == "" {
			continue
		}
		e := feedEntry{
			title:   title,
			summary: firstText(row, "summary", "standfirst", "description", "intro"),
			at:      rowTime(row),
		}
		if slug := firstText(row, "slug", "id"); slug != "" && detail != "" {
			e.link = base + detail + slug
		}
		// The id is the entry's own address when it has one, and the listing
		// and slug when it does not: an id has to be stable and unique, and a
		// reader that sees two different ids for one entry shows it twice.
		e.id = e.link
		if e.id == "" {
			e.id = fmt.Sprintf("%s#%s/%s", base, l.Name, firstText(row, "slug", "id"))
		}
		out = append(out, e)
	}
	return out
}

// detailBase is the path a record's page lives under, or "" when none does.
//
// The listing this feed reads first, then any detail page reading the same
// collection. Several listings select from one collection — everything, the
// newest, the ones in stock — and a record has one page whichever of them found
// it. Matching only on the listing's own name meant a feed built from "journal"
// found no page while every entry in it had one, and every item in the feed was
// a headline that could not be opened.
func (st *Site) detailBase(l *listing.Listing) string {
	pages, _, err := st.pages()
	if err != nil {
		return ""
	}
	names := make([]string, 0, len(pages))
	for name := range pages {
		names = append(names, name)
	}
	sort.Strings(names)

	fallback := ""
	for _, name := range names {
		body, ok := pages[name].(map[string]any)
		if !ok {
			continue
		}
		which, _ := body["detail"].(string)
		if which == "" {
			continue
		}
		if which == l.Name {
			return "/" + name + "/"
		}
		if fallback == "" && st.Listings != nil && st.Listings.Set != nil {
			if other, found := st.Listings.Set.Get(which); found &&
				other.Collection == l.Collection {
				fallback = "/" + name + "/"
			}
		}
	}
	return fallback
}

// rowTime reads whichever date a row carries.
//
// A feed is ordered by time whether or not the content thinks of itself that
// way, so a row with no date gets the zero time and sorts last rather than
// being dropped: a page with no date is still a page somebody published.
func rowTime(row listing.Row) time.Time {
	for _, key := range []string{"published", "date", "updated", "bath",
		"created"} {
		raw := text(row, key)
		if raw == "" {
			continue
		}
		for _, layout := range []string{time.RFC3339, "2006-01-02"} {
			if at, err := time.Parse(layout, raw); err == nil {
				return at.UTC()
			}
		}
	}
	if n, ok := row["created"].(float64); ok && n > 0 {
		return time.Unix(int64(n), 0).UTC()
	}
	return time.Time{}
}

// atomFeed writes RFC 4287.
//
// Written with encoding/xml rather than by hand, because a feed is XML somebody
// else's parser reads and an ampersand in a title is not a reason for their
// reader to show an error.
func (st *Site) atomFeed(w http.ResponseWriter, entries []feedEntry,
	updated time.Time) {

	type atomLink struct {
		Rel  string `xml:"rel,attr,omitempty"`
		Href string `xml:"href,attr"`
	}
	type atomEntry struct {
		Title string `xml:"title"`
		ID    string `xml:"id"`
		// A pointer, so an entry with nowhere to point omits the element
		// rather than carrying href="" — which a reader shows as an item that
		// cannot be opened.
		Updated string    `xml:"updated"`
		Link    *atomLink `xml:"link,omitempty"`
		Summary string    `xml:"summary,omitempty"`
	}
	type atomFeedDoc struct {
		XMLName xml.Name `xml:"http://www.w3.org/2005/Atom feed"`
		Title   string   `xml:"title"`
		ID      string   `xml:"id"`
		Updated string   `xml:"updated"`
		// Tagged, or encoding/xml writes the field name: this emitted <Links>
		// with a capital L, which is not an element any reader knows.
		Links   []atomLink  `xml:"link"`
		Entries []atomEntry `xml:"entry"`
	}

	base := strings.TrimSuffix(st.BaseURL, "/")
	doc := atomFeedDoc{
		Title:   st.Name,
		ID:      base + "/",
		Updated: updated.Format(time.RFC3339),
		Links: []atomLink{
			{Rel: "self", Href: base + atomPath},
			{Rel: "alternate", Href: base + "/"},
		},
	}
	for _, e := range entries {
		at := e.at
		if at.IsZero() {
			at = updated
		}
		entry := atomEntry{
			Title: e.title, ID: e.id, Updated: at.Format(time.RFC3339),
			Summary: e.summary,
		}
		if e.link != "" {
			entry.Link = &atomLink{Rel: "alternate", Href: e.link}
		}
		doc.Entries = append(doc.Entries, entry)
	}

	w.Header().Set("Content-Type", "application/atom+xml; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	st.tdmHeaders(w)
	_, _ = w.Write([]byte(xml.Header))
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return
	}
	_, _ = w.Write([]byte("\n"))
}

// jsonFeed writes JSON Feed 1.1.
func (st *Site) jsonFeed(w http.ResponseWriter, entries []feedEntry,
	updated time.Time) {

	base := strings.TrimSuffix(st.BaseURL, "/")
	items := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		item := map[string]any{"id": e.id, "title": e.title}
		if e.link != "" {
			item["url"] = e.link
		}
		if e.summary != "" {
			item["summary"] = e.summary
		}
		if !e.at.IsZero() {
			item["date_published"] = e.at.Format(time.RFC3339)
		}
		items = append(items, item)
	}
	w.Header().Set("Content-Type", "application/feed+json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// The mining reservation applies to a feed as much as to a page: a feed is
	// the content, in the form easiest to take.
	st.tdmHeaders(w)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version":       "https://jsonfeed.org/version/1.1",
		"title":         st.Name,
		"home_page_url": base + "/",
		"feed_url":      base + jsonPath,
		"items":         items,
	})
}
