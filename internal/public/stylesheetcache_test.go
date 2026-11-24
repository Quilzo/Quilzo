// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"net/http"
	"strings"
	"testing"
)

// The stylesheet is asked for again with every page, as the page is.
//
// It was kept for an hour, on the reasoning that it changed only when the
// operator restarted. The site now takes the design with each publish and
// on SIGHUP, so a reader who had opened a page in the hour before a publish
// was handed the published page over the stylesheet from before it: the
// palette, the style layer and the faces the publish brought arrived up to
// an hour late, and markup a new layer styles was drawn without it. Asking
// again costs a 304 when nothing changed, which is what a page already
// costs.
func TestTheStylesheetIsAskedForAgainAsThePageIs(t *testing.T) {
	st, _ := setup(t)
	st.Stylesheet = ":root { --x: 1 }"

	first := get(st, "/site.css", nil)
	cc := first.Header().Get("Cache-Control")
	if !strings.Contains(cc, "max-age=0") || !strings.Contains(cc, "must-revalidate") {
		t.Errorf("/site.css is kept without asking again (Cache-Control: %q), "+
			"so a publish's design reaches a returning reader late", cc)
	}
	tag := first.Header().Get("ETag")
	if tag == "" {
		t.Fatal("no ETag, so asking again would cost the whole stylesheet")
	}

	// Not modified carries the policy and the tag, so a browser holding a
	// copy stored under the hour it used to be given takes the new policy
	// with its next 304 rather than keeping the old one.
	again := get(st, "/site.css", map[string]string{"If-None-Match": tag})
	if again.Code != http.StatusNotModified {
		t.Fatalf("a matching ETag answered %d", again.Code)
	}
	if got := again.Header().Get("Cache-Control"); got != cc {
		t.Errorf("a 304 says Cache-Control %q, the stylesheet %q", got, cc)
	}
	if got := again.Header().Get("ETag"); got != tag {
		t.Errorf("a 304 says ETag %q, the stylesheet %q", got, tag)
	}

	// A publish that changes the design is a new stylesheet at the next ask.
	st.Stylesheet = ":root { --x: 2 }"
	if w := get(st, "/site.css", map[string]string{"If-None-Match": tag}); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), "--x: 2") {
		t.Errorf("a changed stylesheet answered %d to the old tag", w.Code)
	}
}
