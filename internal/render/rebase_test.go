package render

import (
	"regexp"
	"strings"
	"testing"
)

// A bundle can be served from a subdirectory.
//
// Every link a page carries is rooted, which is right for a site at the root of
// a host and wrong for one at /demo2 — a project page, a demo, anything behind
// a proxy that mounts the site at a path. Copied into a subdirectory as
// rendered, the navigation, the pictures and the whole stylesheet resolve one
// level too high, so the pages are all present and the site does not work.
func TestABundleCanBeMovedUnderAPrefix(t *testing.T) {
	files := map[string][]byte{
		"index.html": []byte(`<link rel="stylesheet" href="/site.css">` +
			`<a href="/shop">Shop</a><a href="/">Home</a>` +
			`<img src="/media/abc" alt="x">` +
			`<img src="/media/big" srcset="/media/small 480w, /media/big 1200w" ` +
			`sizes="50vw" alt="y">` +
			`<form action="/form/wholesale"></form>` +
			`<meta property="og:image" content="/media/abc">` +
			`<video poster="/media/poster"></video>` +
			`<a href="https://example.com/x">Away</a>` +
			`<a href="//cdn.example.com/y">Protocol</a>` +
			`<a href="#main">Skip</a><a href="cloth/indigo">Relative</a>`),
		"site.css": []byte(`@font-face{src:url(/fonts/Inter.woff2)}` +
			`.x{background:url("/media/abc")}`),
		"manifest.webmanifest": []byte(`{"start_url":"/","scope":"/",` +
			`"shortcuts":[{"url":"/shop"}]}`),
		"media/abc": []byte{0x89, 'P', 'N', 'G'},
	}

	out := Rebase(files, "demo2")
	html := string(out["index.html"])

	for _, want := range []string{
		`href="/demo2/site.css"`,
		`href="/demo2/shop"`,
		`src="/demo2/media/abc"`,
		`action="/demo2/form/wholesale"`,
		`content="/demo2/media/abc"`,
		`srcset="/demo2/media/small 480w, /demo2/media/big 1200w"`,
		`poster="/demo2/media/poster"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the markup does not carry %s:\n%s", want, html)
		}
	}
	// Somebody else's URL, a protocol-relative one, a fragment and a relative
	// path are all left as they are.
	for _, keep := range []string{
		`href="https://example.com/x"`,
		`href="//cdn.example.com/y"`,
		`href="#main"`,
		`href="cloth/indigo"`,
	} {
		if !strings.Contains(html, keep) {
			t.Errorf("%s was rewritten and should not have been:\n%s", keep, html)
		}
	}

	css := string(out["site.css"])
	for _, want := range []string{`url(/demo2/fonts/Inter.woff2)`,
		`url("/demo2/media/abc")`} {
		if !strings.Contains(css, want) {
			t.Errorf("the stylesheet does not carry %s:\n%s", want, css)
		}
	}

	man := string(out["manifest.webmanifest"])
	for _, want := range []string{`"start_url":"/demo2/"`, `"scope":"/demo2/"`,
		`"url":"/demo2/shop"`} {
		if !strings.Contains(man, want) {
			t.Errorf("the manifest does not carry %s:\n%s", want, man)
		}
	}

	// A picture is bytes, not text.
	if got := out["media/abc"]; string(got) != string(files["media/abc"]) {
		t.Error("a binary file was rewritten as if it were markup")
	}

	// And no prefix is a no-op, so the ordinary case cannot be broken by this.
	same := Rebase(files, "")
	if string(same["index.html"]) != string(files["index.html"]) {
		t.Error("an empty prefix changed the bundle")
	}
}

// The prefix is written one way however it is given.
func TestThePrefixIsNormalised(t *testing.T) {
	for _, given := range []string{"demo2", "/demo2", "demo2/", "/demo2/",
		"  /demo2/  "} {
		out := Rebase(map[string][]byte{
			"index.html": []byte(`<a href="/shop">Shop</a>`),
		}, given)
		if got := string(out["index.html"]); got != `<a href="/demo2/shop">Shop</a>` {
			t.Errorf("prefix %q produced %s", given, got)
		}
	}
}

// A static copy names its assets, or a host will not render them.
//
// A file stored under a bare hash is served as application/octet-stream, and a
// static host that sends X-Content-Type-Options: nosniff — GitHub Pages, and
// most of the others — turns that into a picture the browser refuses to draw
// and a video it refuses to play. The served site is fine: it has the format
// table and sets the type itself, which is why nothing caught this until a
// bundle was put on a static host.
func TestABundlesAssetsCarryTheirFormat(t *testing.T) {
	id := "f73de9907689ddb5d33abd37d1465927ad02dae1a6151e23559a714b33f3fc0d"
	film := "3a2ca8bef9b8724da4994fafaf370fc784c87c32c9d704cf5dd8aad652b95803"
	files := map[string][]byte{
		"index.html": []byte(`<img src="/media/` + id + `" alt="x">` +
			`<video><source src="/media/` + film + `" type="video/mp4"></video>`),
		"media/" + id:   {0x89, 'P', 'N', 'G'},
		"media/" + film: {0, 0, 0, 0x18, 'f', 't', 'y', 'p'},
	}
	out := Named(files, map[string]string{id: ".png", film: ".mp4"})

	if _, ok := out["media/"+id+".png"]; !ok {
		t.Error("the picture was not renamed, so a static host serves it as " +
			"octet-stream and nosniff blocks it")
	}
	if _, ok := out["media/"+film+".mp4"]; !ok {
		t.Error("the film was not renamed")
	}
	html := string(out["index.html"])
	if !strings.Contains(html, `src="/media/`+id+`.png"`) {
		t.Errorf("the markup still points at the unnamed file:\n%s", html)
	}
	if !strings.Contains(html, `src="/media/`+film+`.mp4"`) {
		t.Errorf("the film reference was not moved with the file:\n%s", html)
	}
	// The file and every reference move together, or the bundle 404s.
	if _, stale := out["media/"+id]; stale {
		t.Error("the unnamed file is still in the bundle")
	}

	// And the two passes compose: named, then moved under a prefix.
	moved := Rebase(out, "/demo2")
	if !strings.Contains(string(moved["index.html"]),
		`src="/demo2/media/`+id+`.png"`) {
		t.Errorf("naming and rebasing do not compose:\n%s",
			string(moved["index.html"]))
	}
}

// A picture's narrower copies reach the template as a srcset.
//
// The language cannot call a function, so a layout cannot ask the library which
// renditions exist — and a layout that guessed would emit a candidate the
// browser may choose and then fail to fetch. So it is derived, like every other
// companion, and it is derived for any field holding an asset path rather than
// for a list of field names somebody has to keep up to date.
func TestAnAssetFieldGetsItsSrcSet(t *testing.T) {
	id := "f73de9907689ddb5d33abd37d1465927ad02dae1a6151e23559a714b33f3fc0d"
	other := "3a2ca8bef9b8724da4994fafaf370fc784c87c32c9d704cf5dd8aad652b95803"
	src := Sources{
		SrcSet: func(asked string) string {
			if asked == id {
				return "/media/small 480w, /media/" + id + " 1200w"
			}
			return ""
		},
	}
	ctx, err := src.For("index", map[string]any{
		"title": "Aster & Alum",
		"hero":  map[string]any{"image": "/media/" + id, "alt": "cloth"},
		"sections": []any{
			map[string]any{"gallery": map[string]any{"items": []any{
				// One with renditions, one without, and a field that is not an
				// asset at all.
				map[string]any{"image": "/media/" + id},
				map[string]any{"image": "/media/" + other},
				map[string]any{"image": "https://example.com/elsewhere.jpg"},
			}}},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	page := ctx["page"].(map[string]any)
	hero := page["hero"].(map[string]any)
	if hero["image_srcset"] == nil {
		t.Error("the hero picture has renditions and no srcset companion, so " +
			"every reader gets the widest file")
	}
	items := page["sections"].([]any)[0].(map[string]any)["gallery"].(map[string]any)["items"].([]any)
	if items[0].(map[string]any)["image_srcset"] == nil {
		t.Error("a gallery item with renditions got no srcset")
	}
	if _, present := items[1].(map[string]any)["image_srcset"]; present {
		t.Error("a picture with no renditions got a srcset, which would offer " +
			"the browser a candidate that does not exist")
	}
	if _, present := items[2].(map[string]any)["image_srcset"]; present {
		t.Error("somebody else's URL was treated as an asset in this library")
	}

	// And a record on a detail page, which is where the picture is largest and
	// which used to get no companions at all.
	rctx := map[string]any{}
	src.WithRecord(rctx, map[string]any{"image": id, "name": "Indigo linen"})
	rec := rctx["record"].(map[string]any)
	if rec["image_srcset"] == nil {
		t.Error("a record's picture got no srcset; a bare id is how a record " +
			"names one, and the layout puts /media/ in front of it")
	}
}

// Every candidate a page offers has to be a file the bundle holds.
//
// This is the check that found the srcset gap: the generic attribute pass
// rewrote one URL per attribute, so in a subdirectory a picture's first
// candidate moved and the rest did not — and a browser that picked one of the
// rest got a 404 where a photograph should be. It is a property of the whole
// bundle rather than of one rewrite, so it is asserted over the whole bundle.
func TestEverySrcSetCandidateNamesAFileInTheBundle(t *testing.T) {
	id := "f73de9907689ddb5d33abd37d1465927ad02dae1a6151e23559a714b33f3fc0d"
	small := "3a2ca8bef9b8724da4994fafaf370fc784c87c32c9d704cf5dd8aad652b95803"
	files := map[string][]byte{
		"index.html": []byte(`<img src="/media/` + id + `" srcset="/media/` +
			small + ` 480w, /media/` + id + ` 1200w" sizes="50vw" alt="x">`),
		"media/" + id:    {0x89, 'P', 'N', 'G'},
		"media/" + small: {0x89, 'P', 'N', 'G'},
	}
	out := Rebase(Named(files, map[string]string{id: ".jpg", small: ".jpg"}),
		"/demo2")

	html := string(out["index.html"])
	for _, m := range regexp.MustCompile(`srcset="([^"]+)"`).
		FindAllStringSubmatch(html, -1) {
		for _, candidate := range strings.Split(m[1], ",") {
			url := strings.Fields(strings.TrimSpace(candidate))[0]
			path := strings.TrimPrefix(url, "/demo2/")
			if path == url {
				t.Errorf("the candidate %s was not moved under the prefix, so "+
					"a browser choosing it gets a 404", url)
				continue
			}
			if _, ok := out[path]; !ok {
				t.Errorf("the candidate %s names no file in the bundle", url)
			}
		}
	}
}
