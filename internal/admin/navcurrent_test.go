// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Opening a navigation entry marks that entry as the current one.
//
// Every screen passes a "Nav" value to its template and the layout marks the
// entry whose key matches it with aria-current="page". Nothing checked that
// the value a handler passes is the key of the entry that leads to it, and
// three of twenty-eight were wrong:
//
//	/sections   marked Design, because the list screens passed "design"
//	            while only the edit screens passed "sections"
//	/logs       passed no Nav at all, so nothing was marked
//	/passkeys   passed no Nav at all, so nothing was marked
//
// The one somebody noticed was /sections, and they noticed it as "the
// highlight does not work here like it does everywhere else" — which is what
// this costs. Navigation that lies about where you are is worse than
// navigation with no highlight at all, because the reader trusts it.
//
// aria-current is not decoration either. It is how a screen reader announces
// which item is the current page, so a wrong one is a wrong answer to
// somebody who cannot see the layout.
func TestOpeningANavEntryMarksIt(t *testing.T) {
	srv, token := fullyWired(t)

	// Screens that legitimately have no navigation to mark. Written down
	// rather than skipped silently, and each is asserted to be a real
	// destination below, so a stale exemption fails.
	standalone := map[string]string{
		"/playground": "its own document with its own Content-Security-Policy, " +
			"because it is the one screen permitted a script; it renders " +
			"neither the header nor the sidebar",
	}

	dests := destinations
	if len(dests) < 20 {
		t.Fatalf("found %d navigation entries; the parse is wrong and a test "+
			"that checks nothing passes", len(dests))
	}

	known := map[string]bool{}
	for _, d := range dests {
		known[d.Path] = true
	}
	for path := range standalone {
		if !known[path] {
			t.Errorf("%q is excused from this test and is not a navigation "+
				"entry; the exemption is stale", path)
		}
	}

	checked := 0
	for _, d := range dests {
		if _, excused := standalone[d.Path]; excused {
			continue
		}
		t.Run(d.Path, func(t *testing.T) {
			w := get(t, srv, d.Path, token)
			if w.Code != http.StatusOK {
				t.Skipf("%s answered %d, which another test is responsible for",
					d.Path, w.Code)
			}
			body := w.Body.String()
			want := fmt.Sprintf(`href=%q aria-current="page"`, d.Path)
			if strings.Contains(body, want) {
				return
			}
			// Say which one it marked instead, because "not marked" and
			// "marked the wrong one" are different bugs and the second is
			// the worse one.
			if got := markedEntry(body); got != "" {
				t.Errorf("opening %s (%s) marks %s as the current page",
					d.Path, d.Key, got)
				return
			}
			t.Errorf("opening %s (%s) marks nothing as the current page, so "+
				"the navigation does not say where you are", d.Path, d.Key)
		})
		checked++
	}
	if checked < 20 {
		t.Fatalf("only checked %d entries", checked)
	}
}

// markedEntry returns the path the layout marked, or "".
func markedEntry(body string) string {
	const tail = `" aria-current="page"`
	i := strings.Index(body, tail)
	if i < 0 {
		return ""
	}
	head := body[:i]
	j := strings.LastIndex(head, `href="`)
	if j < 0 {
		return ""
	}
	return head[j+len(`href="`):]
}
