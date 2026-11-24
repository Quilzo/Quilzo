// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package sameorigin is the one answer to whether a request came from a
// site's own pages, for every door that asks: the admin's screens, the
// content API taking the admin's session cookie, the public site's member
// and board forms, its NLWeb tool, and the agent interface.
//
// Each door asked in its own way, and they disagreed about the same
// request. The admin compared only the host, exactly, so a page on another
// scheme was its own and its own host in capitals was not. The content API
// asked whether Origin ended in "//" and the host, so "http://evil.example
// //h" was its own. The public site compared the whole string. The NLWeb
// tool compared scheme and host without case, and the agent interface
// compared exactly. And two doors' comments gave opposite reasons for what
// they did with a request that said nothing.
//
// So the comparison is here, once, and what a door admits that its browser
// did not vouch for is a Policy each states where it asks.
package sameorigin

import (
	"net/http"
	"net/url"
	"strings"
)

// Policy is what a door admits beyond a request its own pages made.
type Policy struct {
	// None admits Sec-Fetch-Site: none, a request a person started by
	// typing the address or opening a bookmark, which no page made.
	None bool
	// Missing admits a request that names neither Sec-Fetch-Site nor
	// Origin. Such a request is not a browser's, so nothing attached a
	// cookie to it on somebody's behalf; a door that only ever answers its
	// own pages still refuses it.
	Missing bool
	// OriginOnly decides by Origin alone, and never asks Sec-Fetch-Site:
	// for a door that refuses DNS rebinding, where a page on a name pointed
	// at this machine is same-origin to its own browser, and only its
	// Origin says which site it is.
	OriginOnly bool
	// Also is other origins the door takes requests from, as the agent
	// interface takes its OAuth issuer's.
	Also []string
}

// Check reports whether r came from own's pages, or from what p admits.
// own is an origin, scheme://host[:port], or an address beginning with
// one.
//
// Sec-Fetch-Site decides when the browser sends it, unless the policy is
// OriginOnly: it is set by the browser and no page can forge it, and a
// privacy-hardened browser that says same-origin may send Origin: null,
// which a second check then refused. Otherwise Origin decides, compared as
// Same compares it.
func Check(r *http.Request, own string, p Policy) bool {
	if !p.OriginOnly {
		switch r.Header.Get("Sec-Fetch-Site") {
		case "same-origin":
			return true
		case "none":
			return p.None
		case "":
		default:
			return false
		}
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return p.Missing
	}
	if Same(origin, own) {
		return true
	}
	for _, o := range p.Also {
		if Same(origin, o) {
			return true
		}
	}
	return false
}

// Same reports whether origin, as a browser sends it in an Origin header,
// is own's origin: the same scheme, the same host in any case, and the
// same port, a scheme's default port written or not. An origin is only
// ever a scheme, a host and a port, so one with anything after them is
// nobody's, and so is "null".
func Same(origin, own string) bool {
	o, ok := parse(origin)
	if !ok || (o.Path != "" && o.Path != "/") || o.RawQuery != "" || o.Fragment != "" {
		return false
	}
	w, ok := parse(own)
	return ok && o.Scheme == w.Scheme && strings.EqualFold(o.Hostname(), w.Hostname()) &&
		port(o) == port(w)
}

func parse(s string) (*url.URL, bool) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.User != nil || u.Opaque != "" || u.Hostname() == "" {
		return nil, false
	}
	u.Scheme = strings.ToLower(u.Scheme)
	return u, u.Scheme == "http" || u.Scheme == "https"
}

// port is the port an address names, or its scheme's default.
func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}
