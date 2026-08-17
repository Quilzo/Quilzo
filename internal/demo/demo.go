// Package demo is a complete application, shipped so somebody can see one.
//
// # Why a whole site rather than a starter template
//
// The starters in internal/starter are single pages: markup and some sample
// content, enough to show what a template looks like. They cannot show what
// this tool is for, because what it is for only appears when several features
// are working at once — a query over structured records, a page that embeds it,
// a navigation that refuses to point at nothing, content with a date after
// which it stops being served, and a form that the internet-facing process can
// write to and cannot read back.
//
// So this installs an application. Gram is a photo-sharing site: a feed, an
// explore page with a real filter, profiles, stories that take themselves down,
// and a message box. Every part of it was built through the admin interface
// before it was written down here, which is the only way to be sure it can be.
//
// # What it is honest about
//
// There is no comment thread, no follower graph and no messaging between
// visitors, because none of those are content management. A demonstration that
// implied otherwise would be selling something this is not. What it shows is
// the part a CMS is actually responsible for: structured content, a query over
// it, a gate before publication, and a record of who changed what.
//
// # Images
//
// Twelve generated gradients, about 450K. Not photographs of anything: a demo
// that ships stock imagery is a demo with a licence question attached, and
// these are drawn by the code that made them.
//
// They are referenced by name rather than by identifier. A media file is
// addressed by the hash of its bytes, which is not known until it is stored, so
// the content below says "@harbour-dawn" and the installer substitutes the real
// address once the library has it.
package demo

import (
	"embed"
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/listing"
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
	Alt   string
	Bytes []byte
}

// Site is everything an installer has to create.
type Site struct {
	Name          string
	Summary       string
	Types         []schema.Type
	Bind          map[string]string
	Vocabularies  *taxonomy.Set
	Menus         *menu.Set
	Listings      []listing.Listing
	Forms         []form.Form
	Records       map[string][]collection.Record
	Pages         map[string]any
	Media         []Asset
	Template, CSS string
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
