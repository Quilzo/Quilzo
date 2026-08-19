package demo

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/tmpl"
)

// The demonstration has to satisfy the product it demonstrates.
//
// It is the first thing anybody runs, and a demo that trips its own gates is
// worse than none: it teaches that the gates are noise. So it is held to every
// rule the tool enforces on a customer's site — its content satisfies its own
// types, its menu points only at pages that exist, its images are described,
// and its template renders.

func TestTheDemonstrationSatisfiesItsOwnTypes(t *testing.T) {
	d := Marginalia()
	types := &schema.Store{
		Registry: schema.NewRegistry(), Bound: map[string]string{}}
	for _, ty := range d.Types {
		if err := types.Registry.Add(ty); err != nil {
			t.Fatalf("content type %s does not compile: %v", ty.Name, err)
		}
	}
	for page, name := range d.Bind {
		if err := types.Bind(page, name); err != nil {
			t.Fatalf("binding %s to %s: %v", page, name, err)
		}
		if _, there := d.Pages[page]; !there {
			t.Errorf("%s is bound to a type and is not a page", page)
		}
	}
	// Resolved first, because an unresolved "@name" is a string like any other
	// and would pass a check the real content has to pass with a real address.
	if err := d.Resolve(fakeAddresses(d)); err != nil {
		t.Fatal(err)
	}
	for _, f := range types.Gate(d.Pages) {
		t.Errorf("the demonstration fails its own type gate: %s", f)
	}
}

// Every image reference names an image that ships.
func TestEveryImageReferenceResolves(t *testing.T) {
	d := Marginalia()
	if err := d.Resolve(fakeAddresses(d)); err != nil {
		t.Fatalf("the demonstration refers to images it does not carry: %v", err)
	}
	// And nothing still looks like a reference.
	for name, body := range d.Pages {
		m, ok := body.(map[string]any)
		if !ok {
			continue
		}
		for k, v := range m {
			if s, is := v.(string); is && strings.HasPrefix(s, Ref) {
				t.Errorf("%s.%s is still %q after resolving", name, k, s)
			}
		}
	}
}

// Every image is described, which is the rule the tool refuses to publish
// without.
func TestEveryImageHasAlternativeText(t *testing.T) {
	d := Marginalia()
	if len(d.Media) == 0 {
		t.Fatal("no images at all; this test is checking nothing")
	}
	for _, a := range d.Media {
		if strings.TrimSpace(a.Alt) == "" {
			t.Errorf("%s ships with no alt text", a.Name)
		}
		if _, err := media.Accept(a.Name+".png", a.Bytes, time.Now()); err != nil {
			t.Errorf("%s is not a file this tool accepts: %v", a.Name, err)
		}
	}
}

// The menu points only at pages that exist, which is the rule the publish gate
// enforces — so a demo failing it could not be published by the tool that
// ships it.
func TestTheMenuPointsOnlyAtPagesThatExist(t *testing.T) {
	d := Marginalia()
	if d.Menus == nil {
		t.Fatal("the demonstration has no navigation")
	}
	for _, p := range d.Menus.Broken(d.Pages) {
		t.Errorf("the demonstration's own menu is broken: %s", p)
	}
	for _, name := range d.Menus.Names() {
		m, _ := d.Menus.Get(name)
		if err := m.Validate(d.Pages); err != nil {
			t.Errorf("menu %s: %v", name, err)
		}
	}
}

// Every listing a page names is a listing that exists, and every listing
// compiles.
func TestEveryListingAPageNamesExists(t *testing.T) {
	d := Marginalia()
	set := &listing.Set{}
	for _, l := range d.Listings {
		if err := set.Add(l); err != nil {
			t.Fatalf("listing %s does not compile: %v", l.Name, err)
		}
	}
	used := 0
	for page, body := range d.Pages {
		for _, want := range listing.On(body) {
			used++
			if _, ok := set.Get(want); !ok {
				t.Errorf("%s names a listing %q that does not exist", page, want)
			}
		}
	}
	if used == 0 {
		t.Error("no page embeds a listing, so the demonstration does not " +
			"demonstrate the feature it exists to show")
	}
}

// The template renders every page without a template error.
func TestTheTemplateRendersEveryPage(t *testing.T) {
	d := Marginalia()
	if err := d.Resolve(fakeAddresses(d)); err != nil {
		t.Fatal(err)
	}
	for name, body := range d.Pages {
		out, err := tmpl.Render(d.Template, map[string]any{
			"page": body,
			"site": map[string]any{"name": d.Name},
			// No listings and no menus: this is the harshest context, and a
			// template that needs them to produce valid HTML would break on
			// any page that has neither.
			"menus": map[string]any{},
		})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !strings.Contains(out, "</html>") {
			t.Errorf("%s stopped rendering part-way through", name)
		}
	}
}

// The sale is embargoed, and the About page's claim about it is true.
//
// The feature is that a page can be committed, live and not yet visible. The
// demonstration says so in prose, so the prose and the data have to agree —
// the failure this catches is somebody moving the date and leaving the
// sentence, which turns the demonstration into a lie about the product.
func TestTheSaleIsEmbargoedUntilItsWindowOpens(t *testing.T) {
	d := Marginalia()
	// Before the window opens.
	before := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	// Inside it.
	during := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	// After it closes.
	after := time.Date(2026, 12, 20, 12, 0, 0, 0, time.UTC)

	sale, ok := d.Pages["sale"].(map[string]any)
	if !ok {
		t.Fatal("there is no sale page, so nothing here demonstrates a window")
	}
	w, err := site.WindowOf(sale)
	if err != nil {
		t.Fatalf("the sale has an unreadable window: %v", err)
	}
	if w.Starts.IsZero() || w.Expires.IsZero() {
		t.Fatal("the sale carries no window, so every assertion below would " +
			"pass against a page that is simply always public")
	}

	for _, c := range []struct {
		when time.Time
		want bool
		why  string
	}{
		{before, false, "before it starts, a sale price is a price somebody pays early"},
		{during, true, "inside its window it has to be served"},
		{after, false, "after it closes it has to stop, with nothing scheduled to do that"},
	} {
		if got := w.Public(c.when); got != c.want {
			t.Errorf("at %s the sale is public=%v, want %v — %s",
				c.when.Format("2 Jan"), got, c.want, c.why)
		}
	}

	// And nothing ships already expired, which the tool refuses to publish.
	if stale := site.AlreadyExpired(d.Pages, before); len(stale) > 0 {
		t.Errorf("the demonstration ships content that is already expired, so "+
			"the tool would refuse to publish its own demo: %v", stale)
	}
}

// Every product's written-out price agrees with the number beside it.
//
// Two fields carry one fact, because the template language has no arithmetic.
// That is a deliberate cost, and the risk it buys is exactly this: the two
// drift, and the shop shows a price nobody is charging.
func TestTheWrittenPriceAgreesWithTheStoredOne(t *testing.T) {
	d := Marginalia()
	products := d.Records["products"]
	if len(products) < 5 {
		t.Fatalf("%d product(s); this test would pass by checking almost "+
			"nothing", len(products))
	}
	for _, r := range products {
		pence, ok := r.Fields["price"].(int)
		if !ok {
			t.Errorf("%v has a price that is not a number, so nothing can "+
				"compare it", r.Fields["name"])
			continue
		}
		want := pounds(pence)
		if got, _ := r.Fields["price_display"].(string); got != want {
			t.Errorf("%v is stored at %d pence and shown as %q, want %q",
				r.Fields["name"], pence, got, want)
		}
	}
}

// The availability labels say what the tokens mean.
//
// Written out here rather than compared against availabilityLabel, which is
// the function that produced them: checking a value against the function that
// made it is a tautology that passes however wrong the function is. A sabotage
// relabelling low_stock as "In stock" went through the earlier version of this
// test untouched, which is how it was found.
func TestEveryAvailabilityTokenIsLabelledHonestly(t *testing.T) {
	want := map[string]string{
		"in_stock":      "In stock",
		"low_stock":     "Low stock",
		"made_to_order": "Made to order",
		"sold_out":      "Sold out",
	}
	d := Marginalia()
	seen := map[string]bool{}
	for _, r := range d.Records["products"] {
		avail, _ := r.Fields["availability"].(string)
		label, _ := r.Fields["availability_label"].(string)
		expect, known := want[avail]
		if !known {
			t.Errorf("%v is %q, which is not one of the four states",
				r.Fields["name"], avail)
			continue
		}
		if label != expect {
			t.Errorf("%v is %q and labelled %q, want %q",
				r.Fields["name"], avail, label, expect)
		}
		seen[avail] = true
	}
	// And the demonstration shows all four, or it is not demonstrating a
	// closed set — three of four states is a list.
	for token := range want {
		if !seen[token] {
			t.Errorf("no product is %q, so the demonstration never shows that "+
				"state", token)
		}
	}
}

// pounds is the function under test above, so it is worth one direct case.
func TestPoundsWritesPenceTheWayAPersonReadsThem(t *testing.T) {
	for pence, want := range map[int]string{
		2400: "£24.00", 850: "£8.50", 700: "£7.00", 1205: "£12.05", 5: "£0.05",
	} {
		if got := pounds(pence); got != want {
			t.Errorf("pounds(%d) = %q, want %q", pence, got, want)
		}
	}
}

// fakeAddresses stands in for the media library, which the installer supplies.
func fakeAddresses(d *Site) map[string]string {
	out := make(map[string]string, len(d.Media))
	for _, a := range d.Media {
		out[a.Name] = strings.Repeat("a", 64)
	}
	return out
}
