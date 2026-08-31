package render

import (
	"path"
	"regexp"
	"strings"
)

// Rebase moves a rendered bundle under a path prefix.
//
// # Why this exists
//
// Every link a Quilzo page carries is rooted: href="/shop", src="/media/…",
// the stylesheet at /site.css, the faces under /fonts/. That is correct for a
// site served at the root of a host and wrong for one served from a
// subdirectory — a project page on GitHub Pages, a demo under /demo2, a site
// behind a reverse proxy that mounts it at a path. Rendered as-is and copied
// into a subdirectory, every navigation link, every picture and the whole
// design resolve one level too high: the pages are there and the site is
// broken.
//
// There was no way to do it. `ipfs write` produced a bundle for the root and
// nothing else, so the only route was a hand-written sed over the output, which
// is how a site ends up with its stylesheet rewritten and its manifest missed.
//
// # What is rewritten, and what is not
//
// Root-relative references only, in the files that carry references: markup,
// the stylesheet, the manifest, the service worker. A reference beginning "//"
// is protocol-relative and belongs to another host; one with a scheme is
// somebody else's URL; a fragment or a relative path already resolves against
// the page. None of those are touched.
//
// Absolute URLs built from --base-url — the sitemap's <loc>, og:url — are not
// touched either, because the base URL is the operator's statement of where the
// site lives and it already carries whatever path it should.
func Rebase(files map[string][]byte, prefix string) map[string][]byte {
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	if prefix == "" {
		return files
	}
	at := "/" + prefix

	out := make(map[string][]byte, len(files))
	for name, body := range files {
		if !rewritable(name) {
			out[name] = body
			continue
		}
		out[name] = []byte(rebaseText(string(body), at))
	}
	return out
}

// rewritable reports whether a file in the bundle can carry a reference.
//
// By extension, and the list is short on purpose: a picture rewritten as if it
// were text is a corrupted picture. The extensionless case does not arise —
// pages are written as index.html — but it is answered as "no" anyway, because
// the alternative is guessing at bytes.
func rewritable(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".html", ".css", ".js", ".json", ".webmanifest", ".xml", ".txt":
		return true
	}
	return false
}

// The forms a root-relative reference takes. Each one stops at "/" followed by
// anything that is not another slash, so a protocol-relative "//host/x" is left
// alone.
var (
	// href="/x", src="/x", action="/x", content="/x", poster="/x"
	reAttr = regexp.MustCompile(`\b(href|src|action|content|poster|data-src)=("|')/(?:([^/"'])|("|'))`)
	// url(/x) in a stylesheet, quoted or not
	reCSSURL = regexp.MustCompile(`url\((\s*)("|'|)/(?:([^/"')])|("|'|\)))`)
	// "start_url": "/", "scope": "/", "url": "/x" in a manifest or JSON-LD
	reJSON = regexp.MustCompile(`("(?:start_url|scope|url|src|image|@id)"\s*:\s*")/(?:([^/"])|("))`)
	// A service worker naming a page to keep offline.
	reCacheAdd = regexp.MustCompile(`(caches\.[A-Za-z]+\([^)]*)("|')/(?:([^/"'])|("|'))`)
	// srcset carries a list of candidates, so it needs its own pass: the
	// attribute forms above rewrite one URL each and would leave every
	// candidate but the first alone — which, in a subdirectory, is a browser
	// choosing a picture that 404s. Found by checking that every candidate in
	// a rendered bundle names a file the bundle holds.
	reSrcSet    = regexp.MustCompile(`\b(imagesrcset|srcset)=("|')([^"']*)("|')`)
	reCandidate = regexp.MustCompile(`(^|,\s*)/(?:([^/,\s])|($))`)
)

func rebaseText(s, at string) string {
	s = reSrcSet.ReplaceAllStringFunc(s, func(match string) string {
		parts := reSrcSet.FindStringSubmatch(match)
		value := reCandidate.ReplaceAllString(parts[3], `${1}`+at+`/$2$3`)
		return parts[1] + "=" + parts[2] + value + parts[4]
	})
	s = reAttr.ReplaceAllString(s, `$1=$2`+at+`/$3$4`)
	s = reCSSURL.ReplaceAllString(s, `url($1$2`+at+`/$3$4`)
	s = reJSON.ReplaceAllString(s, `$1`+at+`/$2$3`)
	s = reCacheAdd.ReplaceAllString(s, `$1$2`+at+`/$3$4`)
	return s
}

// Named is a bundle whose assets carry the extension for their format.
//
// A static host reads a file's type from its name. An asset stored under a bare
// hash is served as application/octet-stream, and a host that also sends
// X-Content-Type-Options: nosniff — GitHub Pages does, and so does most of the
// rest — turns that into a picture the browser will not render and a video it
// will not play. The served site does not have this problem, because it has the
// format table and sets the type itself.
//
// exts maps an asset id to its extension, dot included. Both the file and every
// reference to it move together, so a bundle is either wholly renamed or
// untouched.
func Named(files map[string][]byte, exts map[string]string) map[string][]byte {
	if len(exts) == 0 {
		return files
	}
	out := make(map[string][]byte, len(files))
	for name, body := range files {
		renamed := name
		if id, ok := strings.CutPrefix(name, "media/"); ok {
			if ext := exts[id]; ext != "" && !strings.HasSuffix(name, ext) {
				renamed = name + ext
			}
		}
		if !rewritable(name) {
			out[renamed] = body
			continue
		}
		text := string(body)
		for id, ext := range exts {
			if ext == "" {
				continue
			}
			// Exact: an id is 64 hex characters, so "/media/<id>" cannot be a
			// prefix of another asset's path.
			text = strings.ReplaceAll(text, "/media/"+id, "/media/"+id+ext)
		}
		out[renamed] = []byte(text)
	}
	return out
}
