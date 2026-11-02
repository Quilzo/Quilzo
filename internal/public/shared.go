// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"net/http"
	"strings"
)

// A draft shared for review, at /shared/ID: one page as it was when it was
// shared, for somebody with no account to look at before it is published.
//
// Never indexed, never stored by anybody between, never referred onward:
// the address is the only key to it, and a search engine, a cache or the
// next site visited should not be handed it. A note says what it is, so a
// screenshot of it is not mistaken for the site. A link that has ended is
// the site's own 404, the same as one that never was.

const sharedNote = `<p role="note" class="shared-draft"><strong>A draft shared for review.</strong> It is not ` +
	`published, and later changes do not show here.</p>`

func (st *Site) shared(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/shared/")
	if st.Shared == nil || r.Method != http.MethodGet && r.Method != http.MethodHead {
		st.notFound(w, r)
		return
	}
	out, ok := st.Shared(id)
	if !ok {
		st.notFound(w, r)
		return
	}
	h := w.Header()
	h.Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Type", "text/html; charset=utf-8")
	// After the body's own opening tag, where a reader looks first.
	if i := strings.Index(strings.ToLower(out), "<body"); i >= 0 {
		if j := strings.Index(out[i:], ">"); j >= 0 {
			at := i + j + 1
			out = out[:at] + sharedNote + out[at:]
		}
	}
	_, _ = w.Write([]byte(out))
}
