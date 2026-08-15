// Package csp builds a Content-Security-Policy from what the content actually
// references.
//
// The policy this program shipped with had `img-src 'self' data: https:`. That
// last token permits images from every host on the internet, which is not a
// policy so much as a note that nobody wanted to break anything. It is also the
// normal state of a hand-written CSP: the directive is widened once, during an
// incident, by somebody who needs the page to render, and it is never narrowed
// again because narrowing it means knowing what the content references — and
// nobody knows that.
//
// This knows that. The content is structured, so the hosts it points at can be
// read out of it rather than guessed: a URL field holding a YouTube link needs
// frame-src for that host and nothing else. The output is a policy naming the
// hosts in use, which is the version somebody would write by hand if they had
// the time to audit every page.
//
// What it cannot see is stated rather than papered over. A host referenced from
// inside a rich text field — an <img> somebody pasted — is markup this does not
// parse, and widening the whole directive to cover the possibility would undo
// the point. Those go in site.csp.extra_img and site.csp.extra_frame, named one
// at a time, which is a worse experience and a better policy.
//
// Script handling follows the current advice — a nonce-based strict policy, per
// the OWASP cheat sheet and CSP Level 3 — but the honest note is that this
// program's templates cannot execute anything, so `script-src 'none'` is
// achievable for most sites and is what they get. The nonce path exists for the
// search page, which is the one place a published site legitimately needs a
// script.
package csp

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Mode is how the policy is served.
type Mode string

const (
	// Enforce sends Content-Security-Policy. The destination.
	Enforce Mode = "enforce"
	// ReportOnly sends Content-Security-Policy-Report-Only, which reports
	// violations and blocks nothing. A migration state, not somewhere to live:
	// an injected script still runs.
	ReportOnly Mode = "report-only"
	// Off sends nothing, for when something in front sets the header.
	Off Mode = "off"
)

// Sources is what the content was found to reference, by directive.
type Sources struct {
	Img     []string
	Media   []string
	Frame   []string
	Connect []string
	// Fonts and stylesheets are not collected. This program serves its own
	// stylesheet from its own origin and has nowhere to put a font reference,
	// so a directive for them would be permitting something the content cannot
	// express — which is how a policy widens without anybody deciding to.
}

// Policy is a built policy.
type Policy struct {
	Mode    Mode
	Sources Sources
	// Nonce, when set, is placed in script-src. Empty means script-src 'none',
	// which is what a site with no scripts should have and what most get.
	Nonce string
	// ReportTo is a URI violations are posted to. Empty means violations are
	// visible in the browser console and nowhere else, which is honest for a
	// program with no collector rather than pretending to have one.
	ReportURI string
}

// Collect walks pages and returns the external hosts they reference.
//
// Values are examined for URLs regardless of which field they are in, because a
// content type does not say "this field is an image" in a way that can be
// relied on across every type somebody defines. What decides the directive is
// the URL, not the field name: a YouTube or Vimeo link is an embed, a media
// file extension is media, and everything else that is an http(s) URL is
// treated as an image — the conservative guess, because being wrong about an
// image means a broken picture and being wrong about a frame means permitting
// an iframe from somewhere.
func Collect(pages map[string]any) Sources {
	var s Sources
	seen := map[string]bool{}
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			if host, kind, ok := classify(t); ok {
				key := string(kind) + " " + host
				if seen[key] {
					return
				}
				seen[key] = true
				switch kind {
				case kindFrame:
					s.Frame = append(s.Frame, host)
				case kindMedia:
					s.Media = append(s.Media, host)
				default:
					s.Img = append(s.Img, host)
				}
			}
		case map[string]any:
			for _, vv := range t {
				walk(vv)
			}
		case []any:
			for _, vv := range t {
				walk(vv)
			}
		}
	}
	walk(pages)
	sort.Strings(s.Img)
	sort.Strings(s.Media)
	sort.Strings(s.Frame)
	return s
}

type kind string

const (
	kindImg   kind = "img"
	kindMedia kind = "media"
	kindFrame kind = "frame"
)

// embedHosts are the hosts whose URLs mean an iframe.
//
// A list rather than a heuristic, and a short one. Guessing that a URL is an
// embed because it looks like a video would put hosts into frame-src on the
// strength of a filename, and frame-src is the directive where being wrong
// permits somebody else's page inside yours.
var embedHosts = map[string]string{
	"youtube.com":              "www.youtube-nocookie.com",
	"www.youtube.com":          "www.youtube-nocookie.com",
	"youtu.be":                 "www.youtube-nocookie.com",
	"youtube-nocookie.com":     "www.youtube-nocookie.com",
	"www.youtube-nocookie.com": "www.youtube-nocookie.com",
	"vimeo.com":                "player.vimeo.com",
	"player.vimeo.com":         "player.vimeo.com",
}

var mediaExt = []string{".mp4", ".webm", ".ogg", ".mp3", ".wav", ".m4a", ".mov"}

func classify(raw string) (host string, k kind, ok bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "https://") && !strings.HasPrefix(raw, "http://") {
		return "", "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", "", false
	}
	h := strings.ToLower(u.Hostname())
	if h == "" {
		return "", "", false
	}
	if canonical, isEmbed := embedHosts[h]; isEmbed {
		// Rewritten to the host the embed is actually served from, which for
		// YouTube is the no-cookie domain. A policy naming youtube.com does
		// not permit the iframe, because the iframe is not served from there —
		// and the failure looks like the policy being broken rather than the
		// host being wrong.
		return canonical, kindFrame, true
	}
	lower := strings.ToLower(u.Path)
	for _, ext := range mediaExt {
		if strings.HasSuffix(lower, ext) {
			return h, kindMedia, true
		}
	}
	return h, kindImg, true
}

// Build assembles the header value.
func (p Policy) Build() string {
	var d []string

	// Nothing is permitted that is not named. Starting from 'none' rather than
	// from 'self' means a directive nobody thought about denies rather than
	// quietly permitting same-origin loads of a kind the site does not use.
	d = append(d, "default-src 'none'")

	script := "'none'"
	if p.Nonce != "" {
		// strict-dynamic alongside the nonce, per CSP Level 3: a script the
		// nonced one loads is trusted, which is what makes a nonce policy
		// survive contact with a real page. The host allow-list is deliberately
		// absent — with strict-dynamic browsers ignore it anyway, and leaving
		// it in produces a policy that reads as though hosts matter.
		script = fmt.Sprintf("'nonce-%s' 'strict-dynamic'", p.Nonce)
	}
	d = append(d, "script-src "+script)

	// 'unsafe-inline' for styles and not for scripts, stated because the
	// asymmetry looks like an oversight. An inline style can restyle a page;
	// an inline script can do anything. Removing it needs a nonce on every
	// style attribute the templates emit, which is a real change and worth
	// making, and until then the honest thing is that this is the weakest
	// directive here.
	d = append(d, "style-src 'self' 'unsafe-inline'")

	d = append(d, directive("img-src", []string{"'self'", "data:"}, p.Sources.Img))
	d = append(d, directive("media-src", []string{"'self'"}, p.Sources.Media))
	d = append(d, directive("font-src", []string{"'self'"}, nil))
	d = append(d, directive("connect-src", []string{"'self'"}, p.Sources.Connect))

	if len(p.Sources.Frame) > 0 {
		d = append(d, directive("frame-src", nil, p.Sources.Frame))
	} else {
		d = append(d, "frame-src 'none'")
	}

	d = append(d, "manifest-src 'self'")
	// frame-ancestors stops this site being framed by somebody else, which is
	// clickjacking. base-uri stops an injected <base> retargeting every
	// relative URL on the page — a bypass that survives a good script-src.
	d = append(d, "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'")

	if p.ReportURI != "" {
		d = append(d, "report-uri "+p.ReportURI)
	}
	return strings.Join(d, "; ")
}

func directive(name string, fixed, hosts []string) string {
	parts := append([]string(nil), fixed...)
	for _, h := range hosts {
		parts = append(parts, h)
	}
	if len(parts) == 0 {
		return name + " 'none'"
	}
	return name + " " + strings.Join(parts, " ")
}

// Header returns the header name for the mode, and whether to send one.
func (p Policy) Header() (string, bool) {
	switch p.Mode {
	case Off:
		return "", false
	case ReportOnly:
		return "Content-Security-Policy-Report-Only", true
	default:
		return "Content-Security-Policy", true
	}
}

// Widened reports directives that permit more than the content needs, for the
// posture scan.
//
// The check that matters is the schemeless wildcard — `https:` in a directive
// permits every host that speaks TLS, which is every host. It is the state a
// hand-written policy decays into, and it is invisible unless something says
// so, because the page renders perfectly.
func Widened(header string) []string {
	var out []string
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		name, rest, ok := strings.Cut(part, " ")
		if !ok {
			continue
		}
		for _, src := range strings.Fields(rest) {
			switch src {
			case "https:", "http:", "*":
				out = append(out, fmt.Sprintf(
					"%s permits %s, which is every host on the internet", name, src))
			case "'unsafe-eval'":
				out = append(out, name+" permits 'unsafe-eval'")
			case "'unsafe-inline'":
				if strings.HasPrefix(name, "script") {
					out = append(out, name+" permits 'unsafe-inline', which "+
						"defeats the directive entirely: an injected inline "+
						"script is exactly what this is meant to stop")
				}
			}
		}
	}
	return out
}
