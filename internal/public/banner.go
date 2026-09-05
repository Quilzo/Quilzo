package public

import (
	"bytes"
	"net/http"
	"strings"

	"github.com/quilzo/quilzo/internal/marking"
)

// Putting the banner where a template cannot forget it.
//
// # Why not in the templates
//
// Because a template can omit it, and the one that does is the one nobody
// checks. Marking is a control whose entire value is that it is never absent:
// a page without a banner does not look broken, it looks unclassified, and a
// reader treats it accordingly. Asking every template to include a variable
// makes the control depend on the least careful template in the deployment.
//
// So it is written into the response instead, after the page has rendered and
// before it is sent, on every HTML response this server produces -- pages,
// search results, the catalogue, an error. Templates cannot opt out because
// they are not consulted.
//
// # A page that cannot be marked is not served
//
// If the response has no body element to put the banner in, this refuses to
// send it. That is the correct direction for this particular failure: an
// unmarked page reaching a reader is the outcome the control exists to
// prevent, and a 500 that says so is recoverable in a way that a quietly
// unmarked page is not.

// bannerWriter buffers an HTML response so the banner can be added to it.
//
// Buffering is a real cost and is accepted here: a marking deployment is not
// optimising for throughput, and streaming a page whose banner is decided
// after the body would mean deciding it before the body, which is the
// arrangement that lets a template omit it.
type bannerWriter struct {
	http.ResponseWriter
	banner string
	buf    bytes.Buffer
	code   int
	// wroteHeader records that the handler set a status, so it is preserved
	// rather than replaced with 200 when the body is flushed.
	wroteHeader bool
}

func (b *bannerWriter) WriteHeader(code int) {
	if b.wroteHeader {
		return
	}
	b.code, b.wroteHeader = code, true
}

// Write buffers everything, whatever the content type appears to be.
//
// Deciding here would be deciding too early. A handler that writes HTML and
// sets no Content-Type is served as HTML anyway -- Go sniffs the first bytes
// and fills the header in -- so a wrapper that read the header at this point
// would see nothing, pass the page through unmarked, and the browser would
// still render it as a page. That is the exact failure this control exists to
// prevent, arrived at from the one direction nobody watches: not a template
// omitting the banner, but a handler omitting a header.
//
// So the type is decided at flush, from the header if the handler set one and
// from the bytes if it did not, which is the same question Go asks.
func (b *bannerWriter) Write(p []byte) (int, error) {
	if !b.wroteHeader {
		b.WriteHeader(http.StatusOK)
	}
	return b.buf.Write(p)
}

// isHTML reports whether this response will be rendered as a page.
func (b *bannerWriter) isHTML() bool {
	declared := b.ResponseWriter.Header().Get("Content-Type")
	if declared == "" {
		// What Go itself will put there.
		declared = http.DetectContentType(b.buf.Bytes())
	}
	return strings.HasPrefix(declared, "text/html")
}

// flush writes the marked body, or refuses.
func (b *bannerWriter) flush() {
	if !b.isHTML() {
		// Passed through exactly as the handler wrote it. Nothing is added,
		// removed or re-encoded: a stylesheet has nowhere to put a banner and
		// this wrapper is not the place to change what a response says.
		b.ResponseWriter.WriteHeader(b.code)
		_, _ = b.ResponseWriter.Write(b.buf.Bytes())
		return
	}
	marked, err := insertBanner(b.buf.Bytes(), b.banner)
	if err != nil {
		// Deliberately not the unmarked page. See the note above.
		b.ResponseWriter.Header().Set("Content-Type", "text/plain; charset=utf-8")
		b.ResponseWriter.Header().Set("Content-Length", "")
		b.ResponseWriter.WriteHeader(http.StatusInternalServerError)
		_, _ = b.ResponseWriter.Write([]byte(
			"this page could not be marked, so it has not been sent.\n\n" +
				err.Error() + "\n\nA page without its banner does not look " +
				"broken, it looks unclassified, and a reader treats it " +
				"accordingly.\n"))
		return
	}
	// Content-Length was computed for the unmarked body if the handler set
	// it, so it is dropped rather than corrected: Go writes the right one.
	b.ResponseWriter.Header().Del("Content-Length")
	b.ResponseWriter.WriteHeader(b.code)
	_, _ = b.ResponseWriter.Write(marked)
}

// insertBanner puts the marking immediately inside the body and immediately
// before it closes.
//
// Both ends, always: a banner at the top of a long page is one a reader has
// scrolled past by the time they reach the part that matters, which is why
// every marking standard asks for it twice.
func insertBanner(body []byte, banner string) ([]byte, error) {
	open := bytes.Index(body, []byte("<body"))
	if open < 0 {
		return nil, errNoBody
	}
	openEnd := bytes.IndexByte(body[open:], '>')
	if openEnd < 0 {
		return nil, errNoBody
	}
	openEnd += open + 1

	closeAt := bytes.LastIndex(body, []byte("</body>"))
	if closeAt < 0 || closeAt < openEnd {
		return nil, errNoBody
	}

	// role="note" rather than a heading: it is not part of the document's
	// outline, and a screen reader announcing it as a section every time
	// would be worse than useless. aria-label names what it is, because
	// "SECRET//NOFORN" read aloud with no context is a puzzle.
	top := []byte(`<div class="classification-banner classification-top" ` +
		`role="note" aria-label="Classification banner">` +
		escapeBanner(banner) + `</div>`)
	bottom := []byte(`<div class="classification-banner classification-bottom" ` +
		`role="note" aria-label="Classification banner">` +
		escapeBanner(banner) + `</div>`)

	out := make([]byte, 0, len(body)+len(top)+len(bottom))
	out = append(out, body[:openEnd]...)
	out = append(out, top...)
	out = append(out, body[openEnd:closeAt]...)
	out = append(out, bottom...)
	out = append(out, body[closeAt:]...)
	return out, nil
}

// escapeBanner escapes a marking for HTML.
//
// A marking is configuration and should never contain markup, so this is belt
// and braces — but it is configuration somebody types, and the one time it
// does contain a stray character is not the time to discover the banner is an
// injection point.
func escapeBanner(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

var errNoBody = errNoBodyError{}

type errNoBodyError struct{}

func (errNoBodyError) Error() string {
	return "this response has no body element for the banner to go in"
}

// marked wraps a handler so every HTML response carries the banner.
func (st *Site) marked(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policy := st.markingPolicy()
		if !policy.Enabled() {
			next.ServeHTTP(w, r)
			return
		}
		top, _ := policy.BannerHTML()
		bw := &bannerWriter{ResponseWriter: w, banner: top, code: http.StatusOK}
		next.ServeHTTP(bw, r)
		if !bw.wroteHeader {
			bw.WriteHeader(http.StatusOK)
		}
		bw.flush()
	})
}

// markingPolicy is the deployment's scheme, or the zero policy.
func (st *Site) markingPolicy() marking.Policy {
	if st.Marking == nil {
		return marking.Policy{}
	}
	return *st.Marking
}
