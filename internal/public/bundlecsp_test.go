// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"net/http"
	"strings"
	"testing"
)

// A static copy carries the policy the served site sends as a header.
//
// The bundle is built by asking this site's own handler for each address and
// keeping the body. The response headers were computed correctly and then
// dropped, and a file cannot send a header — so every static copy this program
// produced, every `ipfs write` and every archived deposit, was served with no
// Content-Security-Policy at all.
//
// That is the case where the policy matters most rather than least. Templates
// escape for context, but {% raw %} is still the documented opt-out and
// script-src 'none' is what stands behind it. On a static copy nothing did.
func TestAStaticCopyCarriesThePolicy(t *testing.T) {
	const policy = "default-src 'none'; script-src 'none'; frame-ancestors 'none'"
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", policy)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("<!doctype html><html><head><title>t</title></head><body>b</body></html>"))
	})
	body, _, err := fetchSelf(h, "/")
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	if !strings.Contains(got, `<meta http-equiv="Content-Security-Policy"`) {
		t.Fatalf("no policy in the static copy:\n%s", got)
	}
	if !strings.Contains(got, "script-src 'none'") {
		t.Errorf("the directive that matters did not survive:\n%s", got)
	}
	// Directives a meta element cannot enforce are dropped rather than shipped
	// as decoration; the browser ignores them and warns about each one.
	if strings.Contains(got, "frame-ancestors") {
		t.Errorf("frame-ancestors is ignored in a meta element and should not "+
			"be written into one:\n%s", got)
	}
	// In force before anything the document goes on to declare.
	if strings.Index(got, "http-equiv") > strings.Index(got, "<title>") {
		t.Error("the policy should come directly after <head>")
	}
}

// Only HTML gets it. A meta element in JSON is corruption, not hardening.
func TestOnlyHTMLCarriesThePolicy(t *testing.T) {
	for _, ctype := range []string{"application/json", "application/xml", "text/css"} {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Security-Policy", "default-src 'none'")
			w.Header().Set("Content-Type", ctype)
			w.Write([]byte(`{"head":"<head>"}`))
		})
		body, _, err := fetchSelf(h, "/x")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "http-equiv") {
			t.Errorf("%s was rewritten: %s", ctype, body)
		}
	}
}

// A response with no policy, or no head, is left exactly as it was.
func TestNothingIsInventedWhenThereIsNoPolicy(t *testing.T) {
	const doc = "<!doctype html><html><head><title>t</title></head><body>b</body></html>"
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(doc))
	})
	body, _, err := fetchSelf(h, "/")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != doc {
		t.Errorf("a document with no policy was changed:\n%s", body)
	}
}

// A document without a <head> still gets the policy.
//
// The first version of carryCSP returned the body untouched when it found no
// <head>, which meant a template written without one exported with no policy
// and nothing said so. Every template this program ships has a head, which is
// exactly why that hole would have stayed open — it took a hand-written
// template to find it, and `quilzo template adopt` accepts fragments.
//
// A meta element that arrives before any body content lands in the head the
// parser opens for it, so placing it there is not a guess.
func TestADocumentWithNoHeadStillGetsThePolicy(t *testing.T) {
	cases := map[string]string{
		"doctype and html": `<!doctype html><html><body>b</body></html>`,
		"html only":        `<html><body>b</body></html>`,
		"bare fragment":    `<p>b</p>`,
		"uppercase":        `<!DOCTYPE HTML><HTML><BODY>b</BODY></HTML>`,
	}
	for name, doc := range cases {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Security-Policy", "script-src 'none'")
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(doc))
		})
		body, _, err := fetchSelf(h, "/")
		if err != nil {
			t.Fatal(err)
		}
		got := string(body)
		if !strings.Contains(got, "http-equiv") {
			t.Errorf("%s: no policy:\n  %s", name, got)
			continue
		}
		// Before any body content, or the parser will not put it in the head.
		if i, j := strings.Index(strings.ToLower(got), "<body"),
			strings.Index(got, "http-equiv"); i >= 0 && j > i {
			t.Errorf("%s: the policy landed after <body>, where it is "+
				"ignored:\n  %s", name, got)
		}
	}
}
