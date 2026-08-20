// Package demo is a complete application, shipped so somebody can see one.
//
// # Why a whole site rather than a starter template
//
// The starters in internal/starter are single pages: markup and some sample
// content, enough to show what a template looks like. They cannot show what
// this tool is for, because what it is for only appears when several features
// are working at once — a query over structured records, a page that embeds it,
// a navigation that refuses to point at nothing, content with a window outside
// which it is not served, a gate that refuses a claim nobody can back up, and a
// form the internet-facing process can write to and cannot read back.
//
// So this installs an application. Marginalia is a shop that sells paper:
// twelve products, three stockists, a catalogue a machine can read, two
// policies, a wholesale enquiry form and a sale that has not started yet.
//
// # Why a shop, and why it replaced a photo-sharing site
//
// The previous demonstration was a photo feed. It was honest and it exercised
// the wrong half: a feed, a filter and a profile show querying and typing, and
// none of them raise a question a paying customer actually arrives with. A
// shop raises all of them at once — a price that has to be a number, an
// availability that has to be a closed set, copy that has to be substantiated
// before it publishes, and a catalogue something other than a browser has to
// be able to read.
//
// A stationer's specifically, because it is small enough to hold in the head
// and still has every hard case: products made to order and products sold out,
// a sale with a start and an end, claims a regulator would ask about, wholesale
// enquiries that are personal data, and stockists who are not products at all.
//
// # What it is honest about
//
// There is no cart, no checkout, no payment and no stock reservation. The 2026
// shopping agents discover products and hand the purchase back to the merchant,
// so what a shop needs from a CMS is a catalogue saying what is for sale and
// where a person completes the purchase — not a transaction. The moment this
// took an order it would need credentials it does not have.
//
// Every part of it was built through the admin interface before it was written
// down here, which is the only way to be sure it can be. Four bugs were found
// on the way the first time; installing the shop found three more, including a
// gate the installer had been bypassing since it was written.
//
// # Images
//
// Twelve generated plates, drawn by scripts/gendemoassets. Not photographs of
// anything and not trying to be: a demo shipping stock imagery ships a licence
// question with it, and convincing fake product photography would be a
// demonstration that lies about what it is — with alt text that has to lie
// along with it.
//
// The generator is committed. It was not, for the previous demonstration,
// which meant the claim that the images were generated was unverifiable and
// they could not be reproduced.
//
// They are referenced by name rather than by identifier. A media file is
// addressed by the hash of its bytes, which is not known until it is stored, so
// the content below says "@notebook-linen" and the installer substitutes the
// real address once the library has it.
package demo

import (
	"embed"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/brand"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/menu"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/taxonomy"
)

//go:embed assets/*
var assets embed.FS

// Ref is how content names an image before the image has an address.
const Ref = "@"

// Asset is one file for the media library.
type Asset struct {
	// Name is what content refers to it by, as "@name".
	Name string
	// Alt is the description stored with it. Written here rather than left to
	// the installer because an asset library full of undescribed images is the
	// thing this product refuses to publish.
	Alt string
	// Rights is what permits publishing it. Declared for every asset here,
	// because a demonstration that ships twelve undeclared images teaches that
	// the field is optional — and one of them lapses, because the feature
	// worth showing is the warning rather than the refusal.
	Rights media.Rights
	Bytes  []byte
}

// Site is everything an installer has to create.
type Site struct {
	Name    string
	Summary string
	Types   []schema.Type
	Bind    map[string]string
	// BindCollection is the type each collection's records must satisfy.
	BindCollection map[string]string
	Vocabularies   *taxonomy.Set
	Menus          *menu.Set
	Listings       []listing.Listing
	Forms          []form.Form
	Records        map[string][]collection.Record
	Pages          map[string]any
	Media          []Asset
	Template, CSS  string

	// Catalogue names the listing served as the machine-readable feed, if
	// any. Named rather than derived: a feed that serves whichever listing a
	// request selects would expose the ones a page embeds behind a filter
	// somebody assumed was private.
	Catalogue string

	// ClaimRules is what this site refuses to say without substantiation.
	// Empty for a demonstration that has no claims to make.
	ClaimRules brand.Rules
}

// Template and CSS, read from the embedded copies.
func templateHTML() string { b, _ := assets.ReadFile("assets/page.html"); return string(b) }
func styleSheet() string   { b, _ := assets.ReadFile("assets/site.css"); return string(b) }

func image(name string) []byte {
	b, err := assets.ReadFile("assets/" + name + ".png")
	if err != nil {
		// Impossible unless the embed directive and this list disagree, which
		// the test in this package checks.
		panic("demo: missing asset " + name)
	}
	return b
}

// Resolve replaces every "@name" with the address the installer stored that
// asset at.
//
// Walks pages and records rather than a list of known fields, because a demo
// that quietly stopped substituting when somebody added an image field would
// ship pages linking to "@harbour-dawn".
func (s *Site) Resolve(addresses map[string]string) error {
	var missing []string
	fix := func(v any) any {
		str, ok := v.(string)
		if !ok || !strings.HasPrefix(str, Ref) {
			return v
		}
		id, known := addresses[strings.TrimPrefix(str, Ref)]
		if !known {
			missing = append(missing, str)
			return v
		}
		return id
	}
	for _, body := range s.Pages {
		if m, ok := body.(map[string]any); ok {
			for k, v := range m {
				m[k] = fix(v)
			}
		}
	}
	for _, recs := range s.Records {
		for i := range recs {
			for k, v := range recs[i].Fields {
				recs[i].Fields[k] = fix(v)
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("nothing was stored for %s",
			strings.Join(missing, ", "))
	}
	return nil
}

// Rename changes what this demonstration calls itself, everywhere it says so.
//
// # Why a walk rather than a field
//
// The name is not only configuration. It is the index page's title, the
// wordmark in the header, and a sentence or two of prose that names the shop.
// Setting Site.Name alone renamed the configuration and left every page saying
// the old thing — so `demo --name "Paper & Post"` produced a site whose title
// bar read "Marginalia — Paper & Post", which is worse than not offering the
// flag at all.
//
// So this walks the content the same way Resolve does, for the same reason: a
// demonstration that quietly stopped substituting when somebody added a field
// would ship pages naming a shop that does not exist.
//
// Word-boundary matching, so a name that happens to be a substring of another
// word does not rewrite the middle of it.
func (s *Site) Rename(to string) {
	from := s.Name
	if from == "" || to == "" || from == to {
		return
	}
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(from) + `\b`)
	fix := func(v any) any {
		str, ok := v.(string)
		if !ok || !re.MatchString(str) {
			return v
		}
		return re.ReplaceAllString(str, to)
	}
	for _, body := range s.Pages {
		if m, ok := body.(map[string]any); ok {
			for k, v := range m {
				m[k] = fix(v)
			}
		}
	}
	for _, recs := range s.Records {
		for i := range recs {
			for k, v := range recs[i].Fields {
				recs[i].Fields[k] = fix(v)
			}
		}
	}
	if s.Menus != nil {
		for i := range s.Menus.Menus {
			if s.Menus.Menus[i].Label == from {
				s.Menus.Menus[i].Label = to
			}
		}
	}
	s.Summary, _ = fix(s.Summary).(string)
	s.Name = to
}
