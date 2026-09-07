// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package foreign

import (
	"strings"
	"testing"
)

// Whatever Adopt strips, ExecutableMarkup finds.
//
// This is the test the pair exists for. Two callers ask the same question about
// a template — one wants the file cleaned, one wants to refuse it — and the
// failure mode is not that either is wrong today. It is that somebody adds a
// construct to the stripper six months from now, does not know a detector
// exists, and the assistant starts accepting the one thing the adopter takes
// out.
//
// So the assertion is about agreement rather than about any particular pattern:
// if a construct is removed on the way in, it must also be reportable.
func TestAnythingAdoptStripsIsAlsoDetectable(t *testing.T) {
	for name, src := range map[string]string{
		"a script element":     `<p>hello</p><script>alert(1)</script>`,
		"a script reference":   `<script src="https://evil.example/x.js"></script>`,
		"a self-closing one":   `<script src="/x.js"/>`,
		"an inline handler":    `<button onclick="alert(1)">go</button>`,
		"a handler with quote": `<img src="/a.png" onerror='alert(1)'>`,
		"a javascript url":     `<a href="javascript:alert(1)">click</a>`,
		"a vbscript url":       `<a href="vbscript:msgbox">click</a>`,
		"a data url":           `<a href="data:text/html,<b>x">click</a>`,
	} {
		t.Run(name, func(t *testing.T) {
			found := ExecutableMarkup(src)
			r := Adopt(src)
			stripped := r.Template != src

			switch {
			case len(found) == 0 && stripped:
				t.Errorf("Adopt changed this and ExecutableMarkup reports "+
					"nothing.\n  in:   %s\n  out:  %s\nA caller that refuses "+
					"instead of stripping would accept it", src, r.Template)
			case len(found) > 0 && !stripped:
				t.Errorf("ExecutableMarkup reports %v and Adopt left the "+
					"source alone. One of the two is describing markup the "+
					"other thinks is fine", found)
			case len(found) == 0 && !stripped:
				t.Errorf("neither end sees anything in %q. This case is in "+
					"the table because it can execute", src)
			}
		})
	}
}

// An ordinary template is not accused of anything.
//
// A detector that fires on the templates people actually write is a detector
// that gets taken out again, so the negative case is worth as much as the
// positive ones. Every string here is markup this renderer is expected to
// carry.
func TestOrdinaryMarkupIsNotExecutable(t *testing.T) {
	for name, src := range map[string]string{
		"a page":              `<h1>{{ page.title }}</h1><p>{{ page.body }}</p>`,
		"a loop":              `{% for p in pages %}<a href="/{{ p.name }}">{{ p.title }}</a>{% end %}`,
		"an ordinary link":    `<a href="https://example.com/reading">a link out</a>`,
		"a relative link":     `<a href="/shop">the shop</a>`,
		"an image":            `<img src="/media/cloth.avif" alt="indigo cloth">`,
		"a stylesheet":        `<link rel="stylesheet" href="/site.css">`,
		"a word with on":      `<p>the online workshop is on Monday</p>`,
		"an element named on": `<p data-one="1" data-only="2">x</p>`,
		"noscript":            `<noscript><p>no script needed</p></noscript>`,
		"a description":       `<p>Use onclick handlers? This site does not.</p>`,
	} {
		t.Run(name, func(t *testing.T) {
			if found := ExecutableMarkup(src); len(found) > 0 {
				t.Errorf("ordinary markup reported as executable: %v\n  in: %s",
					found, src)
			}
		})
	}
}

// One script element is one finding.
//
// A complete <script>...</script> matches both the paired pattern and the
// looser open-tag one. Reporting it twice would name a second construct the
// caller does not have, and the message a reviewer reads is the whole value of
// refusing rather than stripping.
func TestACompleteScriptElementIsReportedOnce(t *testing.T) {
	found := ExecutableMarkup(`<script>alert(1)</script>`)
	if len(found) != 1 {
		t.Fatalf("want 1 finding, got %d: %v", len(found), found)
	}
	if !strings.Contains(found[0], "<script> element") {
		t.Errorf("the finding does not name a script element: %q", found[0])
	}
}
