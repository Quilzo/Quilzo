package demo

import (
	"strings"
	"testing"
	"time"

	"github.com/lithoform/lithoform/internal/listing"
	"github.com/lithoform/lithoform/internal/media"
	"github.com/lithoform/lithoform/internal/schema"
	"github.com/lithoform/lithoform/internal/site"
	"github.com/lithoform/lithoform/internal/tmpl"
)

// The demonstration has to satisfy the product it demonstrates.
//
// It is the first thing anybody runs, and a demo that trips its own gates is
// worse than none: it teaches that the gates are noise. So it is held to every
// rule the tool enforces on a customer's site — its content satisfies its own
// types, its menu points only at pages that exist, its images are described,
// and its template renders.

func TestTheDemonstrationSatisfiesItsOwnTypes(t *testing.T) {
	d := Gram()
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
	d := Gram()
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
	d := Gram()
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
	d := Gram()
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
	d := Gram()
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
	d := Gram()
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

// The publish windows say what the demonstration claims they say: two stories
// visible and one not yet started, because that is the feature being shown.
func TestOneStoryIsEmbargoedAndTheOthersAreNot(t *testing.T) {
	d := Gram()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	states := map[string]int{}
	for name, body := range d.Pages {
		if !strings.HasPrefix(name, "stories/") {
			continue
		}
		w, err := site.WindowOf(body)
		if err != nil {
			t.Fatalf("%s has an unreadable window: %v", name, err)
		}
		states[w.State(now)]++
	}
	if states["embargoed"] != 1 {
		t.Errorf("want exactly one embargoed story, got %d — the About page "+
			"tells the reader to expect one", states["embargoed"])
	}
	if states["expiring"] < 2 {
		t.Errorf("want at least two stories with an expiry that has not passed, "+
			"got %d", states["expiring"])
	}
	// And nothing already expired, which would refuse to publish.
	if stale := site.AlreadyExpired(d.Pages, now); len(stale) > 0 {
		t.Errorf("the demonstration ships content that is already expired, so "+
			"the tool would refuse to publish its own demo: %v", stale)
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
