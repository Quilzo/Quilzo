// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package sitereport

import (
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Grade is how well one protection is set.
type Grade string

const (
	Good    Grade = "good"
	Weak    Grade = "weak"
	Missing Grade = "missing"
	// Elsewhere: not this program's to send, and a proxy in front may.
	Elsewhere Grade = "elsewhere"
	// Unchecked: what it depends on is not known.
	Unchecked Grade = "unchecked"
)

// Header is one protection, graded.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	Grade Grade  `json:"grade"`
	Why   string `json:"why"`
}

// Served is what is known about how the site reaches a browser.
type Served struct {
	// Address is the site's address (site.base_url), empty when unset.
	Address string
	// Proxied says a proxy is named in front of the site, which may add
	// or strip headers this program cannot see.
	Proxied bool
}

// scheme is the address's scheme, and whether it names this machine.
func (s Served) scheme() (scheme string, local bool) {
	u, err := url.Parse(strings.TrimSpace(s.Address))
	if err != nil || u.Host == "" {
		return "", false
	}
	host := u.Hostname()
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return u.Scheme, true
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		return u.Scheme, true
	}
	return u.Scheme, false
}

// GradeHeaders grades the protections in a response the site served.
func GradeHeaders(h http.Header, how Served) []Header {
	return []Header{csp(h), framing(h), hsts(h, how), nosniff(h), referrer(h), permissions(h), opener(h)}
}

// directives splits a policy into its directives, by name.
func directives(policy string) map[string][]string {
	out := map[string][]string{}
	for _, d := range strings.Split(policy, ";") {
		f := strings.Fields(strings.TrimSpace(d))
		if len(f) == 0 {
			continue
		}
		out[strings.ToLower(f[0])] = f[1:]
	}
	return out
}

func csp(h http.Header) Header {
	out := Header{Name: "Content-Security-Policy"}
	v := h.Get("Content-Security-Policy")
	if v == "" {
		if ro := h.Get("Content-Security-Policy-Report-Only"); ro != "" {
			out.Value, out.Grade = ro, Weak
			out.Why = "Only reported, so nothing is stopped. Set site.csp.mode to enforce once the reports are quiet."
			return out
		}
		out.Grade, out.Why = Missing, "Nothing limits what a page may load or run. Set site.csp.mode to enforce."
		return out
	}
	out.Value = v
	d := directives(v)
	script, ok := d["script-src"]
	if !ok {
		script, ok = d["default-src"]
	}
	if !ok {
		out.Grade, out.Why = Weak, "Neither script-src nor default-src is set, so scripts may come from anywhere."
		return out
	}
	for _, s := range script {
		switch strings.ToLower(s) {
		case "'unsafe-inline'", "'unsafe-eval'", "*", "https:", "http:", "data:":
			out.Grade, out.Why = Weak, "Scripts are allowed from "+s+", which lets injected markup run."
			return out
		}
	}
	out.Grade, out.Why = Good, "Scripts run only from the places the policy names."
	return out
}

func framing(h http.Header) Header {
	out := Header{Name: "Framing"}
	if fa, ok := directives(h.Get("Content-Security-Policy"))["frame-ancestors"]; ok {
		out.Value = "frame-ancestors " + strings.Join(fa, " ")
		if len(fa) == 1 && (fa[0] == "'none'" || fa[0] == "'self'") {
			out.Grade, out.Why = Good, "Other sites cannot put these pages in a frame to trick a click."
		} else {
			out.Grade, out.Why = Good, "Only the sites named may frame these pages."
		}
		return out
	}
	if x := h.Get("X-Frame-Options"); x != "" {
		out.Value = "X-Frame-Options: " + x
		out.Grade, out.Why = Good, "Other sites cannot put these pages in a frame."
		return out
	}
	out.Grade, out.Why = Missing, "Any site may put these pages in a frame and trick a click."
	return out
}

func hsts(h http.Header, how Served) Header {
	out := Header{Name: "Strict-Transport-Security"}
	v := h.Get("Strict-Transport-Security")
	scheme, local := how.scheme()
	if v == "" {
		switch {
		case scheme == "":
			out.Grade, out.Why = Unchecked, "No address is set (site.base_url), so whether the site is served over HTTPS is not known."
		case local:
			out.Grade, out.Why = Unchecked, "The address is this machine's, used while building the site; browsers ignore this header there."
		case scheme != "https":
			out.Grade, out.Why = Missing, "The address is not https, so visitors' connections are not encrypted. Serve the site over HTTPS, then set site.hsts."
		case how.Proxied:
			out.Grade, out.Why = Elsewhere, "Not sent here; the proxy in front of the site should send it. Or set site.hsts if this program is the edge."
		default:
			out.Grade, out.Why = Missing, "Browsers are not told to use HTTPS every time. Set site.hsts to a year once the site is only ever served over HTTPS."
		}
		return out
	}
	out.Value = v
	age := -1
	for _, part := range strings.Split(v, ";") {
		k, val, _ := strings.Cut(strings.TrimSpace(part), "=")
		if strings.EqualFold(k, "max-age") {
			if n, err := strconv.Atoi(strings.Trim(val, `"`)); err == nil {
				age = n
			}
		}
	}
	switch {
	case age >= 31536000:
		out.Grade, out.Why = Good, "Browsers use HTTPS for this site for at least a year."
	case age > 0:
		out.Grade, out.Why = Weak, "Remembered for under a year; a year (site.hsts 8760h) is the usual floor."
	default:
		out.Grade, out.Why = Weak, "The max-age is missing or zero, so browsers forget it at once."
	}
	return out
}

func nosniff(h http.Header) Header {
	out := Header{Name: "X-Content-Type-Options", Value: h.Get("X-Content-Type-Options")}
	if strings.EqualFold(out.Value, "nosniff") {
		out.Grade, out.Why = Good, "Browsers treat each file as the type it says it is."
	} else {
		out.Grade, out.Why = Missing, "A browser may guess a file is a script and run it."
	}
	return out
}

func referrer(h http.Header) Header {
	out := Header{Name: "Referrer-Policy", Value: h.Get("Referrer-Policy")}
	switch strings.ToLower(out.Value) {
	case "no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin":
		out.Grade, out.Why = Good, "Other sites see at most this site's address, never the page a visitor was on."
	case "":
		out.Grade, out.Why = Missing, "Not set; most browsers now default to strict-origin-when-cross-origin, older ones send the whole address."
	default:
		out.Grade, out.Why = Weak, "Other sites may see the full address of the page a visitor came from."
	}
	return out
}

func permissions(h http.Header) Header {
	out := Header{Name: "Permissions-Policy", Value: h.Get("Permissions-Policy")}
	if out.Value != "" {
		out.Grade, out.Why = Good, "Features no page here uses, like the camera and location, are switched off."
	} else {
		out.Grade, out.Why = Missing, "Anything injected into a page could ask for the camera or location."
	}
	return out
}

func opener(h http.Header) Header {
	out := Header{Name: "Cross-Origin-Opener-Policy", Value: h.Get("Cross-Origin-Opener-Policy")}
	switch strings.ToLower(out.Value) {
	case "same-origin":
		out.Grade, out.Why = Good, "A window from another site cannot reach into these pages."
	case "":
		out.Grade, out.Why = Missing, "A window this site opens, or that opens it, keeps a handle on the other."
	default:
		out.Grade, out.Why = Weak, "Popups opened from these pages keep a handle on them."
	}
	return out
}
