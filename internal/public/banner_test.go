package public

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/marking"
)

func scheme() *marking.Policy {
	return &marking.Policy{
		Levels:   []string{"UNCLASSIFIED", "CONFIDENTIAL", "SECRET"},
		Banner:   "SECRET//NOFORN",
		Controls: []string{"NOFORN"},
	}
}

// serve runs one HTML response through the marking middleware.
func serve(t *testing.T, st *Site, body string, code int) *httptest.ResponseRecorder {
	t.Helper()
	h := st.marked(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	return rec
}

const page = `<!doctype html><html><head><title>x</title></head>` +
	`<body><h1>Hello</h1></body></html>`

// The banner goes at both ends of every HTML response, and a template cannot
// leave it out because templates are not consulted.
func TestTheBannerIsOnEveryHTMLResponse(t *testing.T) {
	rec := serve(t, &Site{Marking: scheme()}, page, 200)

	body := rec.Body.String()
	if n := strings.Count(body, "SECRET//NOFORN"); n != 2 {
		t.Fatalf("the banner appears %d time(s); it belongs at both ends:\n%s",
			n, body)
	}
	// Top means immediately inside <body>, not merely somewhere above.
	after := body[strings.Index(body, "<body>")+len("<body>"):]
	if !strings.HasPrefix(after, `<div class="classification-banner`) {
		t.Error("the banner is not the first thing inside the body")
	}
	// Bottom means immediately before </body>, whatever attributes the
	// element carries — asserted structurally rather than as a literal
	// string, so adding an aria label does not fail the test.
	closeAt := strings.LastIndex(body, "</body>")
	tail := body[:closeAt]
	lastOpen := strings.LastIndex(tail, `<div class="classification-banner`)
	if lastOpen < 0 || !strings.HasSuffix(tail, "</div>") {
		t.Errorf("the banner is not the last thing before the body closes:\n%s",
			body)
	}
	if !strings.Contains(tail[lastOpen:], "classification-bottom") {
		t.Error("the element before </body> is not the bottom banner")
	}
}

// A page that cannot be marked is not sent.
//
// The correct direction for this failure. An unmarked page reaching a reader
// is what the control exists to prevent: it does not look broken, it looks
// unclassified, and a reader treats it accordingly.
func TestAPageThatCannotBeMarkedIsNotSent(t *testing.T) {
	rec := serve(t, &Site{Marking: scheme()}, "<p>no body element</p>", 200)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("an unmarkable page answered %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "no body element</p>") {
		t.Error("the unmarked page was sent anyway")
	}
	if !strings.Contains(rec.Body.String(), "looks unclassified") {
		t.Errorf("the refusal does not explain: %s", rec.Body.String())
	}
}

// A deployment that does not mark is untouched, which is every existing one.
func TestAnUnmarkedDeploymentIsUnchanged(t *testing.T) {
	rec := serve(t, &Site{}, page, 200)
	if rec.Body.String() != page {
		t.Errorf("an unmarked deployment's page was rewritten:\n%s",
			rec.Body.String())
	}
}

// Anything that is not HTML passes through: a stylesheet has nowhere to put a
// banner and does not need one.
func TestNonHTMLIsNotTouched(t *testing.T) {
	st := &Site{Marking: scheme()}
	h := st.marked(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write([]byte("body{color:red}"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/style.css", nil))

	if rec.Body.String() != "body{color:red}" {
		t.Errorf("a stylesheet was rewritten: %s", rec.Body.String())
	}
}

// The handler's own status survives. An error page is still marked, and is
// still an error.
func TestTheStatusIsPreserved(t *testing.T) {
	rec := serve(t, &Site{Marking: scheme()}, page, http.StatusNotFound)
	if rec.Code != http.StatusNotFound {
		t.Errorf("a 404 became %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "SECRET//NOFORN") {
		t.Error("an error page went out unmarked")
	}
}

// A marking is configuration somebody types, and the one time it contains a
// stray character is not the time to discover the banner is an injection
// point.
func TestAMarkingCannotCarryMarkup(t *testing.T) {
	st := &Site{Marking: &marking.Policy{
		Levels:   []string{`SECRET<script>alert(1)</script>`},
		Banner:   `SECRET<script>alert(1)</script>`,
		Controls: nil,
	}}
	rec := serve(t, st, page, 200)

	if strings.Contains(rec.Body.String(), "<script>") {
		t.Errorf("markup in a banner reached the page:\n%s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "&lt;script&gt;") {
		t.Error("the banner was not escaped")
	}
}

// A handler that writes HTML and sets no Content-Type is still marked.
//
// Go sniffs the first bytes and fills the header in, so the page is served as
// HTML either way. A wrapper that read the header before that happened would
// see nothing, pass the page through unmarked, and the browser would render it
// as a page regardless — the failure this control exists to prevent, arrived
// at from the direction nobody watches: not a template omitting the banner,
// but a handler omitting a header.
func TestAPageWithNoContentTypeIsStillMarked(t *testing.T) {
	st := &Site{Marking: scheme()}
	h := st.marked(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Content-Type set at all.
		_, _ = w.Write([]byte(page))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	if n := strings.Count(rec.Body.String(), "SECRET//NOFORN"); n != 2 {
		t.Fatalf("a page with no declared type carries the banner %d time(s); "+
			"it is served as HTML either way:\n%s", n, rec.Body.String())
	}
}

// And something that is not HTML still passes through untouched when nobody
// declared a type either.
func TestUndeclaredNonHTMLIsStillNotTouched(t *testing.T) {
	st := &Site{Marking: scheme()}
	h := st.marked(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("plain text, no markup at all"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x.txt", nil))

	if rec.Body.String() != "plain text, no markup at all" {
		t.Errorf("plain text was rewritten: %q", rec.Body.String())
	}
}
