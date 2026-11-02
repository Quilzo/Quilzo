// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package seo

import (
	"net/url"
	"strings"
)

// What a page tells search engines about itself, from two reserved fields:
//
//	"noindex": true                       not in results, not in the sitemap
//	"canonical": "https://elsewhere/x"    the address this page copies
//
// Every page says where it lives (rel=canonical) without being asked,
// once the site has an address: the same page reached with a query string,
// a trailing slash or through a redirect is one page, not several competing
// with each other. A page published elsewhere first names that address
// instead, and is left out of the sitemap, which lists what this site is
// the source of.

// NoIndexField and CanonicalField are the reserved page fields.
const (
	NoIndexField   = "noindex"
	CanonicalField = "canonical"
)

// NoIndex reports whether a page asks to be left out of search results.
func NoIndex(body any) bool {
	m, ok := body.(map[string]any)
	if !ok {
		return false
	}
	v, _ := m[NoIndexField].(bool)
	return v
}

// CanonicalOf is the address a page names as the one it copies, when it
// names a usable one: absolute, http or https, with a host. Anything else
// is ignored, so a typo cannot point a page at nowhere.
func CanonicalOf(body any) (string, bool) {
	m, ok := body.(map[string]any)
	if !ok {
		return "", false
	}
	raw, _ := m[CanonicalField].(string)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return "", false
	}
	return u.String(), true
}

// PageURL is a page's own address on a site at base: the index at the
// root.
func PageURL(base, name, index string) string {
	base = strings.TrimSuffix(base, "/")
	if name == index {
		return base + "/"
	}
	return base + "/" + name
}

// Canonical is the address a page's canonical link names: the one it
// copies, or its own; "" when the site has no address and it copies none.
func Canonical(base, name, index string, body any) string {
	if c, ok := CanonicalOf(body); ok {
		return c
	}
	if strings.TrimSpace(base) == "" {
		return ""
	}
	return PageURL(base, name, index)
}

// InSitemap reports whether a page belongs in this site's sitemap: not
// one that asks to be left out, nor one that is a copy of an address
// elsewhere.
func InSitemap(base, name, index string, body any) bool {
	if NoIndex(body) {
		return false
	}
	if c, ok := CanonicalOf(body); ok && c != PageURL(base, name, index) {
		return false
	}
	return true
}
