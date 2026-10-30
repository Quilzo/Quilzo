// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/seo"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// recordsLayout shows a record's name, price and description, and puts its
// batch only in an attribute, between a header, navigation and footer that
// are the same on every page.
const recordsLayout = `<!doctype html><html lang="en"><head><title>{{ site.name }}</title></head><body>
<header><p>Marginalia, paper in small runs</p><nav><a href="/">Home</a> <a href="/product">Shop</a></nav></header>
<main>
{% if record %}<h1>{{ record.name }}</h1>
<dl><dt>Price</dt><dd>{{ record.price_display }}</dd></dl>
<p class="batch-{{ record.batch }}">{{ record.description }}</p>{% end %}
{% if page.title %}<h1>{{ page.title }}</h1>{% end %}
{% if page.intro %}<p>{{ page.intro }}</p>{% end %}
{% for r in search.results %}<p><a href="{{ r.href }}">{{ r.title }}</a></p>{% end %}
</main>
<footer><p>Every page says this.</p></footer>
</body></html>`

// recordsShop is a shop whose products are records with pages of their own,
// and around them every record a visitor cannot open: one the listing keeps
// out, one only in the draft, one behind a page for members, one behind a
// page whose publish window has not opened, an event that is over, one
// whose address redirects, and every one at an address another route
// answers; and a page not open yet at the address of a product that is.
func recordsShop(t *testing.T) (*Site, *store.Store) {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]any{
		"index":   map[string]any{"title": "Marginalia", "intro": "Paper, made in small runs."},
		"search":  map[string]any{"title": "Search"},
		"product": map[string]any{"detail": "catalogue", "detail_key": "slug"},
		"club":    map[string]any{"detail": "club", "detail_key": "slug", MembersOnlyField: true},
		"sale":    map[string]any{"detail": "sale", "detail_key": "slug", site.Starts: "2099-01-01"},
		"event":   map[string]any{"detail": "upcoming", "detail_key": "slug"},
		// Its records' addresses are the booking route's, so none of them
		// is a page anybody opens.
		"book": map[string]any{"detail": "catalogue", "detail_key": "slug"},
		// A page at a product's address that nobody opens yet: the product
		// is what that address shows.
		"product/brass-pen": map[string]any{"title": "Embargoed launch", "body": "Not yet.",
			site.Starts: "2099-01-01"},
	}
	if _, err := site.SaveDraft(s, pages, "shop", "test"); err != nil {
		t.Fatal(err)
	}
	putRecords(t, s, "products", []collection.Record{
		{ID: "0123456789abcdef0123456789abcdef", Fields: map[string]any{
			"slug": "brass-pen", "name": "Brass pen", "price_display": "£24.00",
			"description": "Turned from solid brass, and heavier than it looks.",
			"status":      "live", "sku": "MG-PN-BRS", "batch": "B7731",
			"cost_note": "Bought in from Acme."}},
		{ID: "11111111111111111111111111111111", Fields: map[string]any{
			"slug": "copper-pen", "name": "Copper pen", "price_display": "£60.00",
			"description": "Not on sale yet.", "status": "hidden"}},
		{ID: "22222222222222222222222222222222", Fields: map[string]any{
			"slug": "silver-pen", "name": "Silver pen", "price_display": "£90.00",
			"description": "For the sale.", "status": "sale"}},
		{ID: "77777777777777777777777777777777", Fields: map[string]any{
			"slug": "oak-ruler", "name": "Oak ruler", "price_display": "£8.00",
			"description": "Moved to the rulers page.", "status": "live"}},
	})
	putRecords(t, s, "club", []collection.Record{
		{ID: "33333333333333333333333333333333", Fields: map[string]any{
			"slug": "gold-nib", "name": "Gold nib", "price_display": "£120.00",
			"description": "For members."}},
	})
	putRecords(t, s, "events", []collection.Record{
		{ID: "44444444444444444444444444444444", Fields: map[string]any{
			"slug": "ink-tasting", "name": "Ink tasting", "date": "2099-06-01",
			"description": "Twelve inks, tried on four papers."}},
		{ID: "55555555555555555555555555555555", Fields: map[string]any{
			"slug": "rye-night", "name": "Rye night", "date": "2020-06-01",
			"description": "Over long ago."}},
	})
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	// Written after the publish, so only the draft has it.
	putRecords(t, s, "products", []collection.Record{
		{ID: "66666666666666666666666666666666", Fields: map[string]any{
			"slug": "steel-pen", "name": "Steel pen", "price_display": "£12.00",
			"description": "Still being written.", "status": "live"}},
	})

	set := &listing.Set{}
	shown := []string{"slug", "name", "price_display", "description", "batch", "cost_note"}
	for _, l := range []listing.Listing{
		{Name: "catalogue", Collection: "products", Fields: shown, Sort: "slug", Rows: 50,
			Where: []listing.Condition{{Field: "status", Match: listing.Is, Value: "live"}}},
		{Name: "sale", Collection: "products", Fields: shown, Sort: "slug", Rows: 50,
			Where: []listing.Condition{{Field: "status", Match: listing.Is, Value: "sale"}}},
		{Name: "club", Collection: "club", Fields: shown, Sort: "slug", Rows: 50},
		{Name: "upcoming", Collection: "events", Fields: []string{"slug", "name", "description", "date"},
			Sort: "date", Rows: 50, Where: []listing.Condition{{Field: "date", Match: listing.Upcoming}}},
	} {
		if err := set.Add(l); err != nil {
			t.Fatal(err)
		}
	}

	st := New(s, render.OneLayout(recordsLayout))
	moved, err := seo.NewMap([]seo.Redirect{{From: "/product/oak-ruler", To: "/rulers"}})
	if err != nil {
		t.Fatal(err)
	}
	st.Redirects = moved
	st.Name, st.BaseURL, st.IndexLive = "Marginalia", "https://example.org", true
	st.Listings = &listing.Resolver{Store: s, Index: collection.NewCache(), Set: set,
		Live: func() string {
			c, err := s.GetCommit(s.GetRef(site.RefLive))
			if err != nil {
				return ""
			}
			return c.Tree
		}}
	bots := &assistant.Set{}
	for _, a := range []assistant.Assistant{
		{Name: "help", Title: "Ask the shop", Public: true},
		{Name: "returns", Title: "Returns", Public: true, Exclude: []string{"product"}},
	} {
		if err := bots.Put(a); err != nil {
			t.Fatal(err)
		}
	}
	st.Assistants = &Assistants{Set: func() (*assistant.Set, error) { return bots, nil }}
	return st, s
}

// putRecords writes records into the draft, as the records screen does.
func putRecords(t *testing.T, s *store.Store, coll string, recs []collection.Record) {
	t.Helper()
	parent := s.GetRef(site.RefDraft)
	c, err := s.GetCommit(parent)
	if err != nil {
		t.Fatal(err)
	}
	tree, _, err := collection.PutMany(s, c.Tree, coll, recs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cid, err := s.PutCommit(store.Commit{Tree: tree, Parents: []string{parent},
		Message: "records", Author: "test", At: time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRef(site.RefDraft, cid); err != nil {
		t.Fatal(err)
	}
}

// Asked what a product costs, the shop's chatbot answers with the price on
// the product's page, and cites that page.
func TestAChatbotAnswersAboutAProductFromItsPage(t *testing.T) {
	st, _ := recordsShop(t)
	w := askPost(st, "help", "How much is the brass pen?")
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "£24.00") {
		t.Fatalf("the price was not answered: %d\n%s", w.Code, body)
	}
	if !strings.Contains(body, `href="/product/brass-pen"`) {
		t.Fatalf("the answer does not cite the product's page:\n%s", body)
	}
	// A chatbot told not to read the shop does not read its products.
	idx, err := st.assistantIndex(assistant.Assistant{Name: "returns", Public: true, Exclude: []string{"product"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range idx.Passages {
		if strings.HasPrefix(p.Page, "product") {
			t.Fatalf("a chatbot excluded from the shop read %s", p.Page)
		}
	}
}

// Site search and an agent asking the site find a product at its own page.
func TestSearchFindsAProductAtItsOwnPage(t *testing.T) {
	st, _ := recordsShop(t)

	var api struct {
		Results []struct{ Page, Title string } `json:"results"`
	}
	w := get(st, "/search.json?q=brass", nil)
	if err := json.Unmarshal(w.Body.Bytes(), &api); err != nil {
		t.Fatalf("%d %v\n%s", w.Code, err, w.Body.String())
	}
	if len(api.Results) != 1 || api.Results[0].Page != "product/brass-pen" || api.Results[0].Title != "Brass pen" {
		t.Fatalf("search.json: %+v", api.Results)
	}

	page := get(st, "/search?q=brass", nil).Body.String()
	if !strings.Contains(page, `<a href="/product/brass-pen">Brass pen</a>`) {
		t.Fatalf("the search page does not link the product:\n%s", page)
	}

	out := askJSON(t, st, "/ask?query=heavier+brass&streaming=false")
	results, _ := out["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("NLWeb: %v", out)
	}
	r := results[0].(map[string]any)
	if r["url"] != "https://example.org/product/brass-pen" || r["name"] != "Brass pen" {
		t.Fatalf("NLWeb result: %v", r)
	}
}

// Nothing a visitor cannot open reaches a chatbot or search: a record the
// listing keeps out, one only in the draft, one behind a page for members,
// one behind a page not open yet, an event that is over, one whose address
// redirects or is another route's, a field the listing never hands out,
// one the layout does not show and one it only puts inside a tag; nor a
// page not open yet at a product's address.
func TestNoIndexHoldsARecordAVisitorCannotOpen(t *testing.T) {
	st, _ := recordsShop(t)
	bot := assistant.Assistant{Name: "help", Public: true}
	idx, err := st.assistantIndex(bot)
	if err != nil {
		t.Fatal(err)
	}
	var said strings.Builder
	for _, p := range idx.Passages {
		said.WriteString(strings.ToLower(p.Page + " " + p.Header() + " " + p.Text + "\n"))
	}
	terms := map[string]bool{}
	for term := range st.searchIndex().Terms {
		terms[term] = true
	}
	for _, never := range []string{"copper", "steel", "gold", "silver", "rye", "acme", "b7731", "brs",
		"embargoed", "oak", "book/"} {
		if strings.Contains(said.String(), never) {
			t.Errorf("the chatbot reads %q:\n%s", never, said.String())
		}
		if terms[never] {
			t.Errorf("search holds %q", never)
		}
	}
	// What a visitor can open is there, and what is around every page's
	// content is not.
	for _, want := range []string{"brass", "ink"} {
		if !strings.Contains(said.String(), want) || !terms[want] {
			t.Errorf("%q is missing: the index holds %d passages", want, len(idx.Passages))
		}
	}
	if strings.Contains(said.String(), "every page says this") {
		t.Errorf("a footer was read as a record:\n%s", said.String())
	}
	// And the routes agree: each of those records is not a page anybody
	// opens.
	for _, path := range []string{"/product/copper-pen", "/product/steel-pen", "/club/gold-nib",
		"/sale/silver-pen", "/event/rye-night", "/book/brass-pen"} {
		if w := get(st, path, nil); w.Code != http.StatusNotFound {
			t.Errorf("%s answered %d", path, w.Code)
		}
	}
	if w := get(st, "/product/oak-ruler", nil); w.Code != http.StatusPermanentRedirect &&
		w.Code != http.StatusTemporaryRedirect {
		t.Errorf("the moved ruler answered %d", w.Code)
	}
	if w := get(st, "/product/brass-pen", nil); w.Code != 200 {
		t.Errorf("the brass pen's page answered %d", w.Code)
	}
}

// A changed record is a changed answer: the chatbot is not answered from
// the index of what the record used to say.
func TestAChangedRecordChangesTheChatbotsAnswer(t *testing.T) {
	st, s := recordsShop(t)
	bot := assistant.Assistant{Name: "help", Public: true}
	before, err := st.assistantIndex(bot)
	if err != nil {
		t.Fatal(err)
	}
	putRecords(t, s, "products", []collection.Record{
		{ID: "0123456789abcdef0123456789abcdef", Fields: map[string]any{
			"slug": "brass-pen", "name": "Brass pen", "price_display": "£26.00",
			"description": "Turned from solid brass, and heavier than it looks.",
			"status":      "live"}},
	})
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	after, err := st.assistantIndex(bot)
	if err != nil {
		t.Fatal(err)
	}
	if after == before {
		t.Fatal("a changed record was answered from the index built before it changed")
	}
	if body := askPost(st, "help", "How much is the brass pen?").Body.String(); !strings.Contains(body, "£26.00") ||
		strings.Contains(body, "£24.00") {
		t.Fatalf("the answer is not the new price:\n%s", body)
	}
}

// A page is read as a visitor reads it: what is inside <main>, a term with
// what it means, and nothing from inside a tag or an element nobody sees.
func TestAPageIsReadAsAVisitorReadsIt(t *testing.T) {
	title, text := readPage(`<html><head><title>Brass pen — Marginalia</title><style>p{}</style></head><body>
<header><h1>Marginalia</h1></header><nav>Home</nav>
<main><h1>Brass pen</h1><dl><dt>Price</dt><dd>&pound;24.00</dd></dl>
<p data-sku="MG-PN-BRS">Turned <a href="/brass">from brass</a></p>
<p hidden>A note for later.</p><div aria-hidden="true">Decoration</div>
<script>var secret = "<p>no</p>";</script><form><label>Email <input name="e"></label></form>
<h2>Care</h2><table><tr><td>Size</td><td>A5</td></tr></table></main>
<footer>Copyright</footer></body></html>`)
	if title != "Brass pen" {
		t.Errorf("title %q", title)
	}
	want := "Price: £24.00.\n\nTurned from brass.\n\n## Care\n\nSize · A5."
	if text != want {
		t.Errorf("read\n%q\nwant\n%q", text, want)
	}

	// With no <main>, the body less what is around its content, and the
	// document's title when it has no heading.
	title, text = readPage(`<html><head><title>A &amp; B</title></head><body><header>Site</header>` +
		`<p>Words.</p><aside>Elsewhere</aside><footer>Foot</footer></body></html>`)
	if title != "A & B" || text != "Words." {
		t.Errorf("without main: %q %q", title, text)
	}

	// Letters whose lower case is a different length leave the tags where
	// they are: a Kelvin sign is three bytes and its lower case one.
	title, text = readPage("<MAIN><H1>\u212a\u212a\u212a pen</H1><P>\u0130stanbul, 4\u212a.</P></MAIN>")
	if title != "\u212a\u212a\u212a pen" || text != "\u0130stanbul, 4\u212a." {
		t.Errorf("read %q %q", title, text)
	}
}

// Whatever a layout and a record make between them, reading it is an
// answer and never a failure.
func FuzzReadPage(f *testing.F) {
	for _, seed := range []string{
		"<main><h1>A</h1><dl><dt>Price<dd>£4</dl></main>", "<p hidden>x", "<script>", "<MAIN>\u212a<",
		`<a title="x>y">z</a>`, "<nav><nav></nav>", "<!-- <main>", "<td>a</td><td>b",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, page string) {
		readPage(page)
	})
}
