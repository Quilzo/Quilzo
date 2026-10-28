// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package webimport

import (
	"net/url"
	"strings"
	"testing"
)

// Whatever a page is made of, reading it ends, and nothing it says becomes
// an address that is not a web page's.
func FuzzRead(f *testing.F) {
	for _, s := range []string{
		bakery().pages["/"], "<", "<a href='", "<!--", "<script>", "<img srcset=', ,'>",
		`<a href="javascript:alert(1)">x</a><a href="data:text/html,x">y</a>`,
		"<nav><nav><a href=/a>a</a></nav>", "<base href='https://evil.example/'><a href=x>x</a>",
	} {
		f.Add(s)
	}
	base, _ := url.Parse("https://hartsbakery.example/")
	f.Fuzz(func(t *testing.T, s string) {
		p := Read([]byte(s), base)
		for _, u := range p.Links {
			if u.Scheme != "http" && u.Scheme != "https" {
				t.Fatalf("a %s: address came out", u.Scheme)
			}
		}
		for _, b := range p.Blocks {
			if b.Src != nil && b.Src.Scheme != "http" && b.Src.Scheme != "https" {
				t.Fatalf("a picture at %s", b.Src)
			}
			if strings.ContainsAny(b.Text, "\x00\n") {
				t.Fatalf("a block holds a control character: %q", b.Text)
			}
		}
	})
}
