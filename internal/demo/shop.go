package demo

import (
	"fmt"

	"github.com/quilzo/quilzo/internal/brand"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/menu"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/taxonomy"
)

// Marginalia is the demonstration application: a shop that sells paper.
//
// # Why a shop, and why this one
//
// It replaced a photo-sharing site. That demonstration was honest and it
// showed the wrong things: a feed, a filter and a profile exercise querying
// and typing, and nothing about them needs a claim to be substantiated, a
// price to be a number, a stock state to be a closed set, or a machine to be
// able to read the catalogue. Those are the questions a real customer arrives
// with, and a demonstration that never raises them answers none of them.
//
// A stationer's was chosen because it is small enough to hold in the head and
// still has every hard case: products with variants in material and size, some
// made to order and some sold out, a sale with a start and an end, claims a
// regulator would ask about, wholesale enquiries that are personal data, and
// stockists who are not products at all.
//
// # The shape, and why it is that shape
//
// Products are records, not pages. A record lives in a collection, a
// collection is what a listing can query, and a listing is what the catalogue
// feed serves — so "an agent can read what this shop sells" is the same
// mechanism as "the shop page has a filter", rather than a second system that
// has to be kept in step with the first.
//
// Stockists and policies are pages with content types, so a stockist missing
// a city or a policy missing its updated date is refused before it is stored.
//
// The sale is a page carrying a publish window. It is not on the site yet and
// no scheduled job is responsible for that — the check happens when the page
// is asked for, so it cannot be late.
//
// # What it does not pretend to do
//
// There is no cart, no checkout, no payment and no stock reservation. The 2026
// shopping agents discover products and hand the purchase back to the
// merchant, and what a shop needs from a CMS is a catalogue that says what is
// for sale and where a person completes the purchase. The moment this took an
// order it would need credentials it does not have, and a demonstration
// implying otherwise would be selling something this is not.
func Marginalia() *Site {
	s := &Site{
		Name: "Marginalia",
		Summary: "A paper shop: products as structured records, a catalogue " +
			"a machine can read, claims that have to be substantiated before " +
			"they publish, a sale that starts on its own, and a wholesale " +
			"enquiry form the public server cannot read back.",
		Template:  templateHTML(),
		CSS:       styleSheet(),
		Bind:      map[string]string{},
		Pages:     map[string]any{},
		Records:   map[string][]collection.Record{},
		Catalogue: "catalogue",
	}
	s.addMedia()
	s.addTypes()
	s.addTaxonomy()
	s.addProducts()
	s.addStockists()
	s.addSale()
	s.addScreens()
	s.addListings()
	s.addMenu()
	s.addForms()
	s.addClaimRules()
	return s
}

func (s *Site) addMedia() {
	for _, a := range []struct{ name, alt string }{
		{"notebook-linen", "An illustration of a tall linen-bound notebook, " +
			"warm brown, two ruled lines showing"},
		{"notebook-pocket", "An illustration of a small teal pocket notebook"},
		{"pen-brass", "An illustration of a slim brass pen lying on the diagonal"},
		{"pen-copper", "An illustration of a slim copper pen lying on the diagonal"},
		{"cards-correspondence", "An illustration of a bordered green " +
			"correspondence card with two ruled lines"},
		{"cards-plain", "An illustration of a bordered blue plain card"},
		{"box-archive", "An illustration of a green archive box with a lid " +
			"and a label slot"},
		{"box-desk", "An illustration of a violet desk box with a lid"},
		{"tape-gummed", "An illustration of a deep red roll of gummed tape, " +
			"seen face on"},
		{"ink-walnut", "An illustration of a squat walnut-brown ink bottle"},
		{"ink-indigo", "An illustration of a squat indigo ink bottle"},
		{"blotter-desk", "An illustration of a bordered olive desk blotter"},
	} {
		s.Media = append(s.Media, Asset{
			Name: a.name, Alt: a.alt, Bytes: image(a.name)})
	}
}

// num is a pointer to a float, which is how schema expresses "this bound is
// set" as distinct from "this bound is zero".
func num(v float64) *float64 { return &v }

func (s *Site) addTypes() {
	// "expires", "publish_from" and "publish_until" are absent from every type
	// here. They are reserved — any page may carry them whatever its type — and
	// a type declaring one would be describing something it does not own.
	s.Types = []schema.Type{
		{
			Name: "product",
			Description: "Something this shop sells. The price is a number " +
				"because a price that is text cannot be sorted, compared or " +
				"served to a machine that has to decide anything with it.",
			Fields: []schema.Field{
				{Name: "slug", Kind: schema.Slug, Label: "Slug", Required: true},
				{Name: "name", Kind: schema.Text, Label: "Name", Required: true,
					MaxLen: 80},
				{Name: "image", Kind: schema.Text, Label: "Photograph", Required: true},
				{Name: "alt", Kind: schema.Text, Label: "Alt text",
					AltFor: "image", Required: true},
				{Name: "summary", Kind: schema.Text, Label: "One line", MaxLen: 140},
				{Name: "description", Kind: schema.LongText, Label: "Description",
					MaxLen: 1200},
				// Pence, and bounded. Stored as a number so it can be
				// compared and served to something that has to decide with
				// it; bounded so a slipped decimal point is refused at the
				// type rather than discovered on an invoice.
				{Name: "price", Kind: schema.Number, Label: "Price (pence)",
					Required: true, Min: num(1), Max: num(500000)},
				{Name: "currency", Kind: schema.Choice, Label: "Currency",
					Required: true, Choices: []string{"GBP", "EUR", "USD"}},
				// The same price, written for a person.
				//
				// This is the bill for a template language that cannot
				// execute: it has no arithmetic, so £24.00 cannot be computed
				// from 2400 at render time, and anything a reader sees that is
				// not literally stored has to be stored. The alternative is a
				// language with expressions in it, which is the class of
				// feature server-side template injection lives in.
				//
				// Paying it here rather than hiding it. Two fields, one
				// authoritative for machines and one for people, is a cost
				// worth naming in a demonstration rather than papering over.
				{Name: "price_display", Kind: schema.Text, Label: "Price, written out",
					Required: true, MaxLen: 20},
				{Name: "sku", Kind: schema.Text, Label: "SKU", Required: true},
				{Name: "range", Kind: schema.Choice, Label: "Range", Required: true,
					Choices: []string{"desk", "correspondence", "archive"}},
				{Name: "material", Kind: schema.Choice, Label: "Material",
					Required: true,
					Choices:  []string{"paper", "brass", "copper", "linen", "glass"}},
				// A closed set, so "out of stock", "Out Of Stock" and "sold
				// out" cannot be three states that mean one thing and split
				// every listing that filters on it.
				{Name: "availability", Kind: schema.Choice, Label: "Availability",
					Required: true,
					Choices: []string{"in_stock", "low_stock", "made_to_order",
						"sold_out"}},
				// And the same for availability: the stored value is a
				// closed machine token that listings filter on, so the
				// readable version is its own field.
				{Name: "availability_label", Kind: schema.Text,
					Label: "Availability, written out", Required: true, MaxLen: 40},
				{Name: "lead_time", Kind: schema.Text, Label: "Lead time",
					MaxLen: 60},
				{Name: "dimensions", Kind: schema.Text, Label: "Dimensions",
					MaxLen: 60},
				{Name: "care", Kind: schema.LongText, Label: "Care", MaxLen: 400},
				// The substantiation fields. Nothing requires them — they are
				// required by the claim, not by the type, which is the whole
				// argument in internal/brand: a product that does not claim a
				// guarantee does not need to carry its terms.
				{Name: "guarantee_terms", Kind: schema.URL,
					Label: "Guarantee terms"},
				{Name: "materials_evidence", Kind: schema.URL,
					Label: "Materials certification"},
				{Name: "launched", Kind: schema.Date, Label: "First sold",
					Required: true},
			},
		},
		{
			Name: "stockist",
			Description: "A shop that carries this. A record rather than a " +
				"page, because a screen showing a set reads a listing, and a " +
				"listing reads a collection.",
			Fields: []schema.Field{
				{Name: "slug", Kind: schema.Slug, Label: "Slug", Required: true},
				{Name: "shop", Kind: schema.Text, Label: "Shop", Required: true},
				{Name: "city", Kind: schema.Text, Label: "City", Required: true},
				{Name: "country", Kind: schema.Text, Label: "Country", Required: true},
				{Name: "address", Kind: schema.LongText, Label: "Address", MaxLen: 200},
				{Name: "url", Kind: schema.URL, Label: "Their site"},
				{Name: "since", Kind: schema.Date, Label: "Stocked since"},
			},
		},
		{
			Name: "policy",
			Description: "Returns, delivery, and the rest of what a customer " +
				"is entitled to ask about.",
			Fields: []schema.Field{
				{Name: "title", Kind: schema.Text, Label: "Title", Required: true},
				{Name: "body", Kind: schema.LongText, Label: "Body", Required: true,
					MaxLen: 6000},
				{Name: "updated", Kind: schema.Date, Label: "Last updated",
					Required: true},
			},
		},
	}
	// The two policy pages are bound, and so they may carry only what the type
	// declares. That is why neither has a "screen" hint: every other page here
	// carries one, the type does not declare it, and the gate refused the
	// install until it was taken off. A presentation hint is not content, and
	// the type saying so is the type working.
	s.Bind["returns"] = "policy"
	s.Bind["delivery"] = "policy"

	// Collections are bound to types too, so a record missing a city is
	// refused at the same gate a page is.
	s.BindCollection = map[string]string{
		"products":  "product",
		"stockists": "stockist",
	}
}

func (s *Site) addTaxonomy() {
	set := &taxonomy.Set{}
	// Closed, which is the default and the point: a misspelled range cannot
	// quietly invent a new one and split the shop page in two.
	ranges := taxonomy.Vocabulary{Name: "ranges", Label: "Ranges"}
	for _, t := range []struct {
		id, label, desc string
		syn             []string
	}{
		{"desk", "Desk", "What sits on the desk and stays there.",
			[]string{"office", "workspace"}},
		{"correspondence", "Correspondence",
			"What gets written on and sent away.", []string{"letters", "post"}},
		{"archive", "Archive", "What holds the rest of it afterwards.",
			[]string{"storage", "filing"}},
	} {
		ranges.Terms = append(ranges.Terms, taxonomy.Term{
			ID: t.id, Label: t.label, Description: t.desc, Synonyms: t.syn})
	}
	_ = set.Add(ranges)

	materials := taxonomy.Vocabulary{Name: "materials", Label: "Materials"}
	for _, t := range []struct{ id, label, desc string }{
		{"paper", "Paper", "Milled in Cumbria unless a product says otherwise."},
		{"brass", "Brass", "Unlacquered, so it darkens with handling."},
		{"copper", "Copper", "Unlacquered, and darkens faster than the brass."},
		{"linen", "Linen", "Woven cover cloth over board."},
		{"glass", "Glass", "Bottles, and nothing else so far."},
	} {
		materials.Terms = append(materials.Terms, taxonomy.Term{
			ID: t.id, Label: t.label, Description: t.desc})
	}
	_ = set.Add(materials)
	s.Vocabularies = set
}

// pounds writes a price in pence the way a customer reads it.
//
// In Go, because the template language has no arithmetic — see the note on
// price_display. Integer division and a two-digit remainder, so 2400 is
// "£24.00" and 850 is "£8.50" rather than "£8.5".
func pounds(pence int) string {
	return fmt.Sprintf("£%d.%02d", pence/100, pence%100)
}

// availabilityLabel writes the closed machine token for a person.
func availabilityLabel(v string) string {
	switch v {
	case "in_stock":
		return "In stock"
	case "low_stock":
		return "Low stock"
	case "made_to_order":
		return "Made to order"
	case "sold_out":
		return "Sold out"
	}
	// Unreachable while the type's choices and this switch agree, and a
	// visible token rather than an empty label if they ever stop agreeing.
	return v
}

func (s *Site) addProducts() {
	type p struct {
		slug, name, img, alt, summary, desc      string
		price                                    int
		sku, rng, material, avail, lead, dims    string
		care, guarantee, materialsCert, launched string
	}
	for _, x := range []p{
		{"linen-notebook-a5", "Linen notebook, A5", "notebook-linen",
			"An illustration of a tall linen-bound notebook, warm brown, two ruled lines showing",
			"Sewn, lies flat, 192 pages of 100gsm.",
			"Section-sewn so it opens flat at any page and stays there. The " +
				"cover is linen over 2mm board; the paper is 100gsm, milled " +
				"in Cumbria, and takes fountain ink without showing through. " +
				"Guaranteed for two years against the binding failing.",
			2800, "MG-NB-A5-LIN", "desk", "linen", "in_stock", "",
			"210 × 148 × 18mm",
			"Keep it dry. The linen marks and the marks stay; people seem to like that.",
			"https://marginalia.example/guarantee", "", "2024-03-04"},

		{"pocket-notebook", "Pocket notebook", "notebook-pocket",
			"An illustration of a small teal pocket notebook",
			"Fits a coat pocket. 64 pages, stapled.",
			"Stapled rather than sewn, because at this size a sewn spine adds " +
				"bulk and nothing else. 90gsm, ruled at 6mm.",
			850, "MG-NB-PKT", "desk", "paper", "in_stock", "", "105 × 74 × 5mm",
			"", "", "", "2024-03-04"},

		{"brass-pen", "Brass pen", "pen-brass",
			"An illustration of a slim brass pen lying on the diagonal",
			"Machined brass, unlacquered, takes a standard refill.",
			"Turned from solid brass on a manual lathe in Sheffield. " +
				"Unlacquered, so it darkens where it is held and stays bright " +
				"where it is not. Takes any standard G2 refill. Guaranteed " +
				"for five years against the mechanism.",
			4200, "MG-PN-BRS", "desk", "brass", "low_stock", "",
			"135 × 9mm, 42g",
			"Do not polish it unless you want to start again.",
			"https://marginalia.example/guarantee", "", "2024-09-12"},

		{"copper-pen", "Copper pen", "pen-copper",
			"An illustration of a slim copper pen lying on the diagonal",
			"The brass pen, in copper. Darkens faster.",
			"Identical to the brass pen except for the material, which " +
				"patinates in weeks rather than months.",
			4600, "MG-PN-CPR", "desk", "copper", "made_to_order",
			"Made in batches; about three weeks.", "135 × 9mm, 47g",
			"Do not polish it unless you want to start again.",
			"https://marginalia.example/guarantee", "", "2025-02-20"},

		{"correspondence-cards", "Correspondence cards, boxed", "cards-correspondence",
			"An illustration of a bordered green correspondence card with two ruled lines",
			"Fifty cards and fifty envelopes, 300gsm.",
			"Fifty flat cards at 300gsm with fifty gummed envelopes. " +
				"Letterpressed border. The paper is 100% recycled and the " +
				"certification is linked below.",
			3200, "MG-CD-CORR", "correspondence", "paper", "in_stock", "",
			"A6, 105 × 148mm", "", "",
			"https://marginalia.example/recycled-certification", "2024-06-01"},

		{"plain-cards", "Plain cards, boxed", "cards-plain",
			"An illustration of a bordered blue plain card",
			"The same card without the border.",
			"Fifty flat cards at 300gsm with fifty gummed envelopes, and no " +
				"printing at all.",
			2600, "MG-CD-PLN", "correspondence", "paper", "in_stock", "",
			"A6, 105 × 148mm", "", "", "", "2024-06-01"},

		{"archive-box", "Archive box", "box-archive",
			"An illustration of a green archive box with a lid and a label slot",
			"Acid-free, holds a year of A4.",
			"Acid-free board with a lidded top and a label slot on the front. " +
				"Flat-packed; folds without glue.",
			1900, "MG-BX-ARC", "archive", "paper", "in_stock", "",
			"320 × 240 × 100mm", "", "", "", "2024-11-08"},

		{"desk-box", "Desk box", "box-desk",
			"An illustration of a violet desk box with a lid",
			"For the things that end up loose.",
			"The archive box at desk scale, in a heavier board.",
			1400, "MG-BX-DSK", "desk", "paper", "sold_out", "",
			"200 × 150 × 70mm", "", "", "", "2025-01-15"},

		{"gummed-tape", "Gummed paper tape", "tape-gummed",
			"An illustration of a deep red roll of gummed tape, seen face on",
			"Water-activated. No plastic anywhere in it.",
			"Fifty metres of water-activated kraft tape. Recyclable with the " +
				"box it is on, which plastic tape is not.",
			700, "MG-TP-GUM", "archive", "paper", "in_stock", "", "50m × 48mm",
			"", "", "", "2024-11-08"},

		{"walnut-ink", "Walnut ink", "ink-walnut",
			"An illustration of a squat walnut-brown ink bottle",
			"30ml, made from walnut husks.",
			"Cooked from walnut husks and bottled in Devon. Not waterproof " +
				"and not lightfast; it is for writing, not for archiving.",
			1200, "MG-IN-WAL", "correspondence", "glass", "in_stock", "",
			"30ml", "Keep the lid on and it keeps for years.", "", "",
			"2025-04-02"},

		{"indigo-ink", "Indigo ink", "ink-indigo",
			"An illustration of a squat indigo ink bottle",
			"30ml, a blue that is nearly black.",
			"A dense blue-black that dries matte. Same bottle, same caveats " +
				"as the walnut.",
			1200, "MG-IN-IND", "correspondence", "glass", "low_stock", "",
			"30ml", "Keep the lid on and it keeps for years.", "", "",
			"2025-04-02"},

		{"desk-blotter", "Desk blotter", "blotter-desk",
			"An illustration of a bordered olive desk blotter",
			"Twenty-five replaceable sheets on board.",
			"A board base with twenty-five blotting sheets that tear off one " +
				"at a time. The base outlasts the pad; refills are the same " +
				"price without it.",
			2400, "MG-BL-DSK", "desk", "paper", "made_to_order",
			"Cut to order; about ten days.", "600 × 400mm", "", "", "",
			"2025-06-18"},
	} {
		fields := map[string]any{
			"slug": x.slug, "name": x.name, "image": Ref + x.img, "alt": x.alt,
			"summary": x.summary, "description": x.desc,
			"price": x.price, "currency": "GBP", "sku": x.sku,
			"range": x.rng, "material": x.material, "availability": x.avail,
			"dimensions": x.dims, "launched": x.launched,
			// The two written-out fields, derived here because the template
			// language has no arithmetic and no mapping — see the note on
			// price_display in the type.
			"price_display":      pounds(x.price),
			"availability_label": availabilityLabel(x.avail),
		}
		// Written only when there is one. An empty string in a URL field is a
		// field somebody filled in with nothing, and the claim gate reads
		// present-but-empty as absent anyway — but a record that carries the
		// key implies somebody made a decision about it.
		for k, v := range map[string]string{
			"lead_time": x.lead, "care": x.care,
			"guarantee_terms": x.guarantee, "materials_evidence": x.materialsCert,
		} {
			if v != "" {
				fields[k] = v
			}
		}
		s.Records["products"] = append(s.Records["products"],
			collection.Record{Fields: fields})
	}
}

// addStockists writes the shops that carry this, as records.
//
// They were typed pages first, which was the wrong shape and the template
// language said so: there is no `pages` in a template's scope, deliberately —
// a page that could walk every other page is a page that can leak one. A
// listing is how a template reads many things, and a listing reads a
// collection.
//
// So the rule falls out rather than being decreed: if a screen has to show a
// set, the set is records. Pages are screens.
func (s *Site) addStockists() {
	for _, x := range []struct {
		slug, shop, city, country, addr, url, since string
	}{
		{"choosing-keeping", "Choosing Keeping", "London",
			"United Kingdom", "21 Tower Street, London WC2H 9NS",
			"https://example.com/choosing-keeping", "2024-05-02"},
		{"papier-tigre", "Papier Tigre", "Paris", "France",
			"5 Rue des Filles du Calvaire, 75003 Paris",
			"https://example.com/papier-tigre", "2024-09-19"},
		{"analogue-life", "Analogue Life", "Nagoya", "Japan",
			"Aichi, Nagoya", "https://example.com/analogue-life", "2025-03-11"},
	} {
		s.Records["stockists"] = append(s.Records["stockists"],
			collection.Record{Fields: map[string]any{
				"slug": x.slug, "shop": x.shop, "city": x.city,
				"country": x.country, "address": x.addr, "url": x.url,
				"since": x.since,
			}})
	}
}

// addSale is the page that is not on the site yet.
//
// It carries a publish window opening in the future. Nothing schedules it and
// nothing has to: the window is checked when the page is asked for, so it
// cannot be late, and it cannot be early either — which is the property a shop
// actually needs from a sale, because a price that appears an hour early is a
// price somebody pays.
func (s *Site) addSale() {
	s.Pages["sale"] = map[string]any{
		"title":  "Winter sale",
		"intro":  "Fifteen per cent off the archive range.",
		"screen": "sale",
		"body": "<p>Fifteen per cent comes off everything in the archive " +
			"range, which is the boxes and the tape. It is not a clearance: " +
			"nothing here is being discontinued.</p>",
		// Reserved fields, so any page may carry them whatever its type.
		// RFC 3339 with a zone: a date with no timezone means something
		// different to the person who typed it and the server that reads it,
		// and for a sale that difference is priced in hours.
		"starts":  "2026-11-24T09:00:00Z",
		"expires": "2026-12-02T23:59:59Z",
	}
}

func (s *Site) addScreens() {
	s.Pages["index"] = map[string]any{
		"title": "Marginalia",
		"intro": "Paper, and the few things that go with it. Twelve products, " +
			"made in small runs.",
		"listings": "new_in",
		"screen":   "home",
	}
	s.Pages["shop"] = map[string]any{
		"title":    "Everything",
		"intro":    "The whole catalogue, newest first.",
		"listings": "catalogue",
		"screen":   "shop",
	}
	s.Pages["ranges"] = map[string]any{
		"title": "By range",
		"intro": "Desk, correspondence or archive. The list is closed, so a " +
			"range nobody agreed on cannot appear here.",
		"listings": "by_range",
		"screen":   "ranges",
	}
	s.Pages["available"] = map[string]any{
		"title": "In stock now",
		"intro": "What ships today. Made-to-order and sold-out items are not " +
			"on this page, because the filter is on the data rather than on " +
			"a person remembering.",
		"listings": "in_stock",
		"screen":   "shop",
	}
	s.Pages["stockists"] = map[string]any{
		"title": "Stockists",
		"intro": "Three shops carry this. A second collection, with a type " +
			"of its own, read by a listing exactly as the products are.",
		"listings": "stockists",
		"screen":   "stockists",
	}
	s.Pages["wholesale"] = map[string]any{
		"title":  "Wholesale",
		"intro":  "If you run a shop and want to carry this, say so here.",
		"screen": "wholesale",
		"form":   "wholesale",
		"privacy": "Wholesale enquiries reach the two people who run " +
			"Marginalia and nobody else. We keep them for a year so we can " +
			"pick up a conversation that paused, then they are deleted.",
	}
	s.Pages["returns"] = map[string]any{
		"title": "Returns",
		"body": "<p>Thirty days, unused, and we pay the postage back. Ink is " +
			"the exception: once a bottle is opened we cannot resell it, so " +
			"we cannot take it back.</p><p>Made-to-order items can be " +
			"cancelled until they are cut. After that they are yours.</p>",
		"updated": "2026-06-01",
	}
	s.Pages["delivery"] = map[string]any{
		"title": "Delivery",
		"body": "<p>UK orders go second class unless you ask otherwise. " +
			"Europe and the rest of the world go tracked, and the tracking " +
			"number is in the dispatch email.</p><p>We do not ship ink by " +
			"air, so bottles going outside Europe travel by surface and take " +
			"about six weeks.</p>",
		"updated": "2026-06-01",
	}
	s.Pages["about"] = map[string]any{
		"title":  "About Marginalia",
		"intro":  "What this is, and how it is put together.",
		"screen": "about",
		"body":   aboutBody,
	}
}

const aboutBody = `<h2>What this is</h2>
<p>Marginalia is a demonstration shop. Twelve products, three stockists, a
catalogue a machine can read, two policies, a wholesale enquiry form and a sale
that has not started yet. Everything here was built through the Quilzo admin
interface — no configuration files were edited, and no code was written for it
beyond one HTML template and one stylesheet.</p>

<h2>How it is put together</h2>
<p>The products are <strong>records</strong> in a collection, which is what
makes the shop page sortable, the range page filterable, and the catalogue feed
possible — all three are the same query mechanism, not three systems kept in
step. The price is a <strong>number</strong>, because a price stored as text
cannot be compared by anything. Availability is a <strong>closed choice</strong>,
so &ldquo;sold out&rdquo;, &ldquo;Sold Out&rdquo; and &ldquo;out of stock&rdquo;
cannot become three states that mean one thing.</p>
<p>The stockists are <strong>pages with a content type</strong>, so one missing
a city is refused before it is stored. The sale is a page carrying a
<strong>publish window</strong>: it is not on this site yet, and no scheduled
job is responsible for that — the window is checked when the page is asked for,
so it cannot be late, and it cannot be early either.</p>
<p>The claims are gated. The brass pen promises a five-year warranty and
publishes, because the product carries a link to the terms; take that link away
and publishing stops, naming the sentence and the field that would make it
sayable. The correspondence cards make a recycled-content claim and publish,
because the certification is linked. That check runs over the records and not
only the pages, because in a shop the copy that matters is a record.</p>
<p>This page is subject to the same rules, which is why it describes those
sentences rather than quoting them: the first draft quoted both, and the gate
refused to publish the page explaining the gate. That is the control working on
its author, and it seemed worth leaving in.</p>

<h2>What is deliberately missing</h2>
<p>There is no cart, no checkout, no payment and no stock reservation. Shopping
agents in 2026 discover products and hand the purchase back to the merchant, so
what a shop needs from a CMS is a catalogue that says what is for sale and where
to complete the purchase. The moment this took an order it would need
credentials it does not have, and implying otherwise would make this
demonstration dishonest.</p>`

func (s *Site) addListings() {
	// The allowlist. Cost, care and the substantiation links are on it; the
	// SKU is not, because a catalogue an agent reads is not the place to
	// publish internal identifiers.
	fields := []string{"slug", "name", "image", "alt", "summary", "description",
		"price", "price_display", "currency", "range", "material",
		"availability", "availability_label", "lead_time", "dimensions",
		"guarantee_terms", "materials_evidence", "launched"}

	base := func(name, label, desc, sort string, rows int) listing.Listing {
		return listing.Listing{
			Name: name, Label: label, Description: desc,
			Collection: "products", Fields: fields,
			Sort: sort, Descending: true, Rows: rows,
		}
	}

	// The one served as the catalogue feed. Everything, so an agent that reads
	// it is not being shown a curated subset somebody forgot to update.
	catalogue := base("catalogue", "Everything for sale",
		"The whole catalogue, which is what the machine-readable feed serves.",
		"launched", 100)

	newIn := base("new_in", "New in", "The six most recent.", "launched", 6)

	byRange := base("by_range", "A range",
		"Products in one range, chosen by the reader.", "launched", 50)
	byRange.Params = []listing.Param{{
		Name: "range", Kind: listing.Slug, Help: "Which range to show"}}
	byRange.Where = []listing.Condition{{
		Field: "range", Match: listing.Is, Param: "range"}}

	byMaterial := base("by_material", "A material",
		"Products made of one thing.", "launched", 50)
	byMaterial.Params = []listing.Param{{
		Name: "material", Kind: listing.Slug, Help: "Which material"}}
	byMaterial.Where = []listing.Condition{{
		Field: "material", Match: listing.Is, Param: "material"}}

	// The filter is on the data. A page that says "in stock" and is kept
	// truthful by somebody remembering to edit it is a page that is wrong.
	inStock := base("in_stock", "In stock now",
		"Only what ships today.", "launched", 50)
	inStock.Where = []listing.Condition{{
		Field: "availability", Match: listing.Is, Value: "in_stock"}}

	search := base("search", "Search",
		"Substring search over names and descriptions.", "launched", 50)
	search.Params = []listing.Param{{
		Name: "q", Kind: listing.Text, Help: "What to look for"}}
	search.Where = []listing.Condition{{
		Field: "name", Match: listing.Has, Param: "q"}}

	stockists := listing.Listing{
		Name: "stockists", Label: "Stockists",
		Description: "Shops that carry this.",
		Collection:  "stockists",
		Fields: []string{"slug", "shop", "city", "country", "address", "url",
			"since"},
		Sort: "shop", Rows: 50,
	}

	s.Listings = []listing.Listing{
		catalogue, newIn, byRange, byMaterial, inStock, search, stockists}
}

func (s *Site) addMenu() {
	set := &menu.Set{}
	m := menu.Menu{Name: "main", Label: "Marginalia"}
	for i, x := range []struct{ id, label, target string }{
		{"i1", "Shop", "index"},
		{"i2", "Everything", "shop"},
		{"i3", "Ranges", "ranges"},
		{"i4", "In stock", "available"},
		{"i5", "Stockists", "stockists"},
		{"i6", "Wholesale", "wholesale"},
		{"i7", "About", "about"},
	} {
		m.Items = append(m.Items, menu.Item{
			ID: x.id, Label: x.label, Kind: menu.Page, Target: x.target,
			Order: (i + 1) * 10,
		})
	}
	_ = set.Add(m)

	foot := menu.Menu{Name: "foot", Label: "The small print"}
	for i, x := range []struct{ id, label, target string }{
		{"f1", "Returns", "returns"},
		{"f2", "Delivery", "delivery"},
	} {
		foot.Items = append(foot.Items, menu.Item{
			ID: x.id, Label: x.label, Kind: menu.Page, Target: x.target,
			Order: (i + 1) * 10,
		})
	}
	_ = set.Add(foot)
	s.Menus = set
}

func (s *Site) addForms() {
	s.Forms = []form.Form{
		{
			Name: "wholesale", Label: "Wholesale enquiry",
			Notice: "Wholesale enquiries reach the two people who run " +
				"Marginalia and nobody else. We keep them for a year so we " +
				"can pick up a conversation that paused, then they are " +
				"deleted automatically.",
			RetentionDays: 365,
			Fields: []form.Field{
				{Name: "shop", Label: "Shop name", Kind: form.Line, Required: true},
				{Name: "contact", Label: "Your name", Kind: form.Line, Required: true},
				{Name: "email", Label: "Email", Kind: form.Email, Required: true},
				{Name: "city", Label: "Where you are", Kind: form.Line, Required: true},
				{Name: "ranges", Label: "Which ranges interest you",
					Kind:    form.Choice,
					Choices: []string{"desk", "correspondence", "archive", "all of them"}},
				{Name: "detail", Label: "Anything else", Kind: form.Para},
			},
		},
		{
			Name: "restock", Label: "Tell me when it is back",
			Notice: "We use this address once, to tell you the thing you " +
				"asked about is available, and then we delete it. It is not " +
				"a mailing list and you are not subscribed to anything.",
			RetentionDays: 180,
			Fields: []form.Field{
				{Name: "sku", Label: "Which product", Kind: form.Line, Required: true},
				{Name: "email", Label: "Email", Kind: form.Email, Required: true},
			},
		},
	}
}

// addClaimRules is what this shop will not say without backing it up.
//
// Shipped with the demonstration because the gate is only demonstrable if
// there is something for it to gate — and because the rules are the part an
// operator argues about, so seeing a real six is more useful than being told
// the feature exists.
//
// Every product here passes. The demonstration of the refusal is to edit one
// and try: take the guarantee link off the brass pen and `quilzo publish`
// stops, naming the sentence and the field that would make it sayable.
func (s *Site) addClaimRules() {
	s.ClaimRules = brand.Starter()
}
