package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rsh1k/scrivet/internal/provenance"
	"github.com/rsh1k/scrivet/internal/schema"
	"github.com/rsh1k/scrivet/internal/site"
)

// Which side of the workflow the type gate belongs on.
//
// It used to run on every save and not at all on publish, which is backwards in
// both directions and was found by building an application with this rather
// than by reading it.
//
// A page can be made invalid without being written to: give an existing page a
// type its stored content does not satisfy. From that moment the whole-draft
// check on save refused every write to every page, naming a page the author was
// not touching and, if they are scoped to their own posts, has no permission to
// fix. Meanwhile the same content published to the live site without complaint,
// because nothing checked on the way out.
//
// So saving checks the page being saved, and publishing checks all of them.

// typedServer is a server with one type, one page bound to it, and content that
// does not satisfy the binding — the state a mistaken bind leaves behind.
func typedServer(t *testing.T) (*Server, string) {
	t.Helper()
	srv, token := setup(t)

	types := &schema.Store{
		Registry: schema.NewRegistry(),
		Bound:    map[string]string{},
	}
	if err := types.Registry.Add(schema.Type{Name: "profile", Fields: []schema.Field{
		{Name: "title", Kind: schema.Text, Required: true},
		{Name: "link", Kind: schema.URL},
		// The fixture page arrives from setup with a body, and an undeclared
		// field is its own failure. Declaring it keeps this test about the one
		// thing it is testing.
		{Name: "body", Kind: schema.LongText},
	}}); err != nil {
		t.Fatal(err)
	}
	srv.Types = &Types{
		Load:  func() (*schema.Store, error) { return types, nil },
		Save:  func(*schema.Store) error { return nil },
		Pages: func() (map[string]any, error) { return srv.draftPages() },
	}
	srv.CheckTypes = func(pages map[string]any) []schema.Failure {
		return types.Gate(pages)
	}

	// "about" exists from setup with a body that has no link at all, so bind a
	// type it fails: give it a link that is not a URL first.
	postForm(t, srv, "/save", token,
		"__name=about&title=About&link=not-a-url")
	if err := types.Bind("about", "profile"); err != nil {
		t.Fatal(err)
	}
	if len(types.Gate(mustPages(t, srv))) == 0 {
		t.Fatal("the fixture is meant to have one invalid page and does not")
	}
	return srv, token
}

func mustPages(t *testing.T, srv *Server) map[string]any {
	t.Helper()
	p, err := srv.draftPages()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func postForm(t *testing.T, srv *Server, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// One broken page must not stop everybody else working.
func TestAnInvalidPageDoesNotBlockSavingAnotherOne(t *testing.T) {
	srv, token := typedServer(t)

	w := postForm(t, srv, "/save", token, "__name=index&title=Home&body=Edited")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("saving an unrelated page while another is invalid answered "+
			"%d, want a redirect\n%s", w.Code, firstLines(w.Body.String(), 8))
	}
	pages := mustPages(t, srv)
	if body, ok := pages["index"].(map[string]any); !ok || body["body"] != "Edited" {
		t.Fatal("the save reported success and did not store anything")
	}
}

// The page being saved is still checked.
func TestSavingAPageThatFailsItsOwnTypeIsStillRefused(t *testing.T) {
	srv, token := typedServer(t)

	w := postForm(t, srv, "/save", token, "__name=about&title=About&link=still-not-a-url")
	if w.Code == http.StatusSeeOther {
		t.Fatal("a page was saved with content that does not satisfy its type")
	}
}

// And the whole draft is checked on the way out.
func TestPublishingRefusesADraftWithAnInvalidPage(t *testing.T) {
	srv, token := typedServer(t)

	w := postForm(t, srv, "/publish", token, "reason=go")
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("publishing a draft containing an invalid page answered %d, "+
			"want 422\n%s", w.Code, firstLines(w.Body.String(), 8))
	}
	if !strings.Contains(w.Body.String(), "about") {
		t.Error("the refusal does not name the page that caused it")
	}
	// The reason field overrides accessibility and provenance. It must not
	// override this one.
	if live := srv.Store.GetRef(site.RefLive); live != "" {
		if pages, err := site.PagesAt(srv.Store, site.RefLive); err == nil {
			if _, there := pages["about"]; there {
				t.Fatal("the invalid page reached the live site anyway")
			}
		}
	}
}

// Fixing the page unblocks the publish, so this is a gate and not a wall.
func TestPublishingProceedsOnceTheInvalidPageIsFixed(t *testing.T) {
	srv, token := typedServer(t)

	if w := postForm(t, srv, "/save", token,
		"__name=about&title=About&link=https://example.org"); w.Code != http.StatusSeeOther {
		t.Fatalf("fixing the page answered %d\n%s", w.Code,
			firstLines(w.Body.String(), 8))
	}
	w := postForm(t, srv, "/publish", token, "reason=go")
	if w.Code == http.StatusUnprocessableEntity &&
		strings.Contains(w.Body.String(), "satisfy the type") {
		t.Fatalf("publishing still refused on types after the page was fixed\n%s",
			firstLines(w.Body.String(), 8))
	}
}

// Binding a type to a page that is not there is a rule about nothing.
func TestBindingRefusesAPageThatDoesNotExist(t *testing.T) {
	srv, token := typedServer(t)

	w := postForm(t, srv, "/types/bind", token, "page=no/such/page&type=profile")
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "e=") {
		t.Fatalf("binding a type to a nonexistent page was accepted: %q", loc)
	}
	if !strings.Contains(loc, "no+such+page") && !strings.Contains(loc, "no%2Fsuch%2Fpage") {
		t.Errorf("the refusal does not name the page: %q", loc)
	}
}

var _ = provenance.NewIndex
