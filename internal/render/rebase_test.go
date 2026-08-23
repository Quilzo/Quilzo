package render

import (
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
