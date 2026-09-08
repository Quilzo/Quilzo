// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/render"
)

// A static copy of this site, made by asking this site for it.
//
// # Why the bundle is a crawl of the handler
//
// There used to be two renderers. The server assembled a page and then added,
// before the closing head tag, the things a layout must not be trusted to
// remember: the manifest link, the catalogue pointer, the page's structured
// data, and the provenance marking that internal/provenance exists to attach.
// It also answered six generated routes — the sitemap, robots.txt, the RSL
// licence, the TDMRep policy, the web manifest and the service worker.
//
// The bundle used render.Bundle, which renders pages and nothing else. So every
// static copy — `ipfs write`, the deposit somebody archives, the demo on a
// static host — was the site with its discovery, its machine-readable prices
// and its AI-disclosure marking removed. Measured on a deployed copy: six 404s
// and not one structured-data block on any page.
//
// Adding those pieces to the second renderer would have left two renderers, and
// the next thing the server learns to emit would be missing again. So there is
// one: this walks its own routes through its own handler and keeps what comes
// back. A page in the bundle is the bytes a reader would have been served,
// because they were served — to a recorder instead of a socket.
//
// # What it cannot carry
//
// Anything that only exists per request. The search endpoint, the form POST
// handler and the API are routes, not files, and a static host has no answer
// for them; they are absent rather than captured as one frozen response. A form
// on a static copy still renders, still says where it posts, and posts to
// nothing — which is a property of static hosting, not of this function.

// Bundle is the published site as files: every page, every generated document,
// and the stylesheet.
//
// Assets — the fonts and the asset library — are added by the caller, which is
// the layer holding those directories. Paths are relative with no leading
// slash, and a page is written as its directory's index.html so a static host
// serves it at the same address this server does.
func (st *Site) Bundle() (map[string][]byte, error) {
	routes, err := st.Routes()
	if err != nil {
		return nil, err
	}

	handler := st.Handler()
	out := map[string][]byte{}
	for _, route := range routes {
		body, status, err := fetchSelf(handler, route.path)
		if err != nil {
			return nil, err
		}
		if status == http.StatusNotFound && !route.required {
			// A route this deployment has not configured. robots.txt without a
			// base URL, the licence without terms, the catalogue without a
			// feed: absent is the honest answer, and a bundle carrying a
			// 404 page under those names would be worse than not carrying
			// them.
			continue
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf(
				"%s answered %d while building a static copy, so the copy "+
					"would be missing it", route.path, status)
		}
		out[route.file] = body
	}
	if st.Stylesheet != "" {
		out["site.css"] = []byte(st.Stylesheet)
	}
	return out, nil
}

// route is one address in the bundle and the file it becomes.
type route struct {
	path string
	file string
	// required marks a route whose absence is a bug rather than a
	// configuration choice. A page that 404s means the bundle would ship a
	// site with a hole in it.
	required bool
}

// Routes is every address a static copy of this site has.
//
// The pages, the detail page per record, and the documents the server generates.
// Sorted, so a bundle is built in the same order twice and a diff between two
// builds is a diff in the content.
func (st *Site) Routes() ([]route, error) {
	pages, _, err := st.pages()
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(pages))
	for name := range pages {
		names = append(names, name)
	}
	sort.Strings(names)

	src := st.sources()
	out := make([]route, 0, len(names)+8)
	for _, name := range names {
		body := pages[name]
		if d, declared := render.DetailOf(body); declared {
			if !d.Declared() {
				return nil, fmt.Errorf(
					"%s declares a detail route with half of it missing, so "+
						"no record can be addressed through it", name)
			}
			keys, _, derr := render.DetailRows(src, name, body, d)
			if derr != nil {
				return nil, derr
			}
			for _, key := range keys {
				out = append(out, route{
					path:     "/" + name + "/" + key,
					file:     name + "/" + key + "/index.html",
					required: true,
				})
			}
			// A detail page has no page of its own: it stands for whichever
			// record is being looked at, and its own address renders a
			// heading with no record under it.
			continue
		}
		path, file := "/"+name, name+"/index.html"
		if name == st.indexName() {
			path, file = "/", "index.html"
		}
		out = append(out, route{path: path, file: file, required: true})
	}

	// The documents the server generates. Each one is optional because each
	// depends on configuration the operator may not have supplied — and each
	// one was missing from every static copy this program had ever made.
	for _, r := range []route{
		{path: "/sitemap.xml", file: "sitemap.xml"},
		{path: "/robots.txt", file: "robots.txt"},
		{path: "/license.xml", file: "license.xml"},
		{path: "/.well-known/tdmrep.json", file: ".well-known/tdmrep.json"},
		{path: SecurityTxtPath, file: strings.TrimPrefix(SecurityTxtPath, "/")},
		// The speculation rules, which a static host cannot switch on by
		// itself: the API is reached through a Speculation-Rules header and a
		// bucket does not send one. Included anyway, because a host that can
		// add a header — Netlify, Cloudflare Pages, a reverse proxy — then
		// has something to point at, and a file nobody references costs a
		// kilobyte. See speculation.go.
		{path: SpeculationPath, file: strings.TrimPrefix(SpeculationPath, "/")},
		{path: "/manifest.webmanifest", file: "manifest.webmanifest"},
		{path: "/sw.js", file: "sw.js"},
		{path: "/offline", file: "offline/index.html"},
		{path: "/llms.txt", file: "llms.txt"},
		{path: "/catalogue.json", file: "catalogue.json"},
		{path: atomPath, file: strings.TrimPrefix(atomPath, "/")},
		{path: jsonPath, file: strings.TrimPrefix(jsonPath, "/")},
		{path: "/.well-known/agent-card.json", file: ".well-known/agent-card.json"},
	} {
		out = append(out, r)
	}
	return out, nil
}

// indexName is the page served at the root.
func (st *Site) indexName() string {
	if n := strings.TrimSpace(st.Index); n != "" {
		return n
	}
	return "index"
}

// fetchSelf asks this site's own handler for one address.
//
// httptest rather than a hand-rolled recorder: it is standard library, it is
// what every test in this package already uses, and a second implementation of
// ResponseWriter would be a second place for the bundle to differ from what is
// served — which is the whole thing this file exists to prevent.
func fetchSelf(h http.Handler, path string) ([]byte, int, error) {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	body := rec.Body.Bytes()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return nil, res.StatusCode, fmt.Errorf(
			"%s redirects, and a static copy cannot follow it", path)
	}
	body = carryCSP(body, res.Header.Get("Content-Security-Policy"),
		res.Header.Get("Content-Type"))
	return bytes.Clone(body), res.StatusCode, nil
}

// carryCSP writes the response's policy into the document as a meta element.
//
// The served site sends Content-Security-Policy as a header and a static copy
// has no way to send a header at all: the files go to IPFS, or to a bucket, or
// to whatever the person who ran `quilzo export` is using, and none of those
// reads Go. So the policy was computed correctly for every one of these
// responses and then dropped on the floor, and every static copy this program
// has ever produced was served with no policy.
//
// That matters most in exactly the case the policy is load-bearing for. The
// template engine escapes for context now, but `{% raw %}` still exists and is
// still the documented opt-out — and `script-src 'none'` is what stands behind
// it. On a static copy nothing did.
//
// A meta element is not as good as a header and is not meant to be. It is
// what a file can carry, browsers honour it for everything that matters here,
// and the alternative on the table was nothing.
func carryCSP(body []byte, policy, ctype string) []byte {
	if policy == "" || !strings.Contains(ctype, "text/html") {
		return body
	}
	// frame-ancestors, report-uri and sandbox are ignored when they arrive in
	// a meta element — the standard says so — and a browser prints a console
	// warning for each. Dropping them keeps the policy honest about what it is
	// actually enforcing rather than shipping directives that do nothing.
	var keep []string
	for _, d := range strings.Split(policy, ";") {
		switch name, _, _ := strings.Cut(strings.TrimSpace(d), " "); name {
		case "", "frame-ancestors", "report-uri", "report-to", "sandbox":
		default:
			keep = append(keep, strings.TrimSpace(d))
		}
	}
	if len(keep) == 0 {
		return body
	}
	// Only & and " need escaping inside a double-quoted attribute, and a
	// policy contains neither in practice. Escaping the apostrophes as well
	// would be equally correct and would render 'none' as &#39;none&#39; in
	// the one header an auditor is most likely to read by eye.
	attr := strings.NewReplacer("&", "&amp;", `"`, "&quot;").
		Replace(strings.Join(keep, "; "))
	meta := []byte(`<meta http-equiv="Content-Security-Policy" content="` +
		attr + `">`)

	// Immediately after <head>, so it is in force before anything the document
	// goes on to declare.
	//
	// A document with no <head> gets it before any content instead, rather
	// than not at all. The parser opens an implicit head for a meta that
	// arrives before body content, so it still applies -- and the first
	// version of this returned the body untouched in that case, which meant a
	// template written without a head element exported with no policy and
	// nothing said so. Every template this program ships has one, which is
	// exactly why that hole would have stayed open: it takes a hand-written
	// template to find, and `template adopt` accepts fragments.
	i := bytes.Index(body, []byte("<head>"))
	switch {
	case i >= 0:
		i += len("<head>")
	default:
		i = afterOpeningHTML(body)
	}
	out := make([]byte, 0, len(body)+len(meta)+1)
	out = append(out, body[:i]...)
	out = append(out, '\n')
	out = append(out, meta...)
	return append(out, body[i:]...)
}

// afterOpeningHTML finds the offset just past <html ...>, or past the doctype,
// or the start of the document.
//
// In each case the position is before any body content, which is what makes a
// meta element land in the head the parser opens for it.
func afterOpeningHTML(body []byte) int {
	lower := bytes.ToLower(body)
	if i := bytes.Index(lower, []byte("<html")); i >= 0 {
		if j := bytes.IndexByte(body[i:], '>'); j >= 0 {
			return i + j + 1
		}
	}
	if i := bytes.Index(lower, []byte("<!doctype")); i >= 0 {
		if j := bytes.IndexByte(body[i:], '>'); j >= 0 {
			return i + j + 1
		}
	}
	return 0
}
