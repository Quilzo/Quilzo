package public

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// font serves one typeface from this site's own origin.
//
// # Why this route exists at all
//
// Because the alternative is a link to somebody else's server on every page.
// A remote font is a request that identifies every reader to a third party, a
// dependency that can stall the first paint, and — since the page asked for it
// — one the Content-Security-Policy will not stop. The policy this program
// builds says font-src 'self', which was a promise nothing could keep until
// there was a route to keep it with.
//
// # Why the name is looked up rather than joined to a path
//
// The obvious implementation reads the file the request names out of the fonts
// directory. That is path traversal waiting for a %2e%2e, and every fix is a
// cleaning function somebody has to get right forever.
//
// So there is no path here. The request's name is looked up in the set that was
// loaded and validated at startup, and a name that is not in it is a 404. There
// is nothing to escape, because nothing is joined.
func (st *Site) font(w http.ResponseWriter, r *http.Request) {
	if st.Fonts == nil || st.Fonts.Len() == 0 {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/fonts/")
	if name == "" || strings.Contains(name, "/") {
		http.NotFound(w, r)
		return
	}
	body, found := st.Fonts.File(name)
	if !found {
		http.NotFound(w, r)
		return
	}

	// Validated by ETag as well as cached, so a proxy that ignores max-age
	// still cannot serve a face the operator has replaced.
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	if match := r.Header.Get("If-None-Match"); match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "font/woff2")
	w.Header().Set("ETag", etag)
	// A font is immutable for as long as its filename is: the name carries the
	// family, the weight and the style, so a changed font is a changed name.
	// That is what makes a year of caching correct rather than optimistic.
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	// Fonts are subresources fetched with CORS in some engines, and a font that
	// fails a cross-origin check renders as nothing. Same-origin only, which is
	// the only origin this route serves.
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	_, _ = w.Write(body)
}
