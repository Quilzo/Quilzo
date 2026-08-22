package public

import (
	"github.com/quilzo/quilzo/internal/render"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

const tpl = `<!doctype html><html lang="en"><head><title>{{ page.title }}</title>
</head><body><h1>{{ page.title }}</h1></body></html>`

func published(t *testing.T, pages map[string]any) *Site {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, pages, "first", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	st := New(s, render.OneLayout(tpl))
	st.BaseURL = "https://example.org"
	return st
}

// Expiry is enforced by the server, not by a job.
//
// A scheduler that never runs cannot leave content public, because nothing
// about serving the page consults it.
func TestAnExpiredPageIsNotServed(t *testing.T) {
	st := published(t, map[string]any{
		"index":   map[string]any{"title": "Home"},
		"gone":    map[string]any{"title": "Gone", site.Expires: "2020-01-01"},
		"soon":    map[string]any{"title": "Soon", site.Starts: "2099-01-01"},
		"current": map[string]any{"title": "Current", site.Expires: "2099-01-01"},
	})
	h := st.Handler()

	for path, want := range map[string]int{
		"/":        http.StatusOK,
		"/current": http.StatusOK,
		"/gone":    http.StatusNotFound,
		"/soon":    http.StatusNotFound,
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != want {
			t.Errorf("%s answered %d, expected %d", path, w.Code, want)
		}
	}
}

// The sitemap cannot advertise a page the server refuses to serve.
//
// This is the bug that comes from filtering in one read path and not the
// others: a crawler follows a link the same server printed and gets a 404,
// which is worse than either the link or the 404 alone.
func TestNoReadPathAdvertisesAPageAnotherRefuses(t *testing.T) {
	st := published(t, map[string]any{
		"index": map[string]any{"title": "Home"},
		"gone":  map[string]any{"title": "Gone", site.Expires: "2020-01-01"},
		"soon":  map[string]any{"title": "Soon", site.Starts: "2099-01-01"},
	})
	h := st.Handler()

	for _, path := range []string{"/sitemap.xml", "/llms.txt", "/search.json"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			continue // not configured in this build, which is fine
		}
		body := w.Body.String()
		for _, hidden := range []string{"gone", "soon"} {
			if strings.Contains(body, hidden) {
				t.Errorf("%s lists %q, which the page handler 404s",
					path, hidden)
			}
		}
	}
}

// A page with an unreadable date is hidden rather than served.
func TestAMalformedDateHidesThePage(t *testing.T) {
	st := published(t, map[string]any{
		"index": map[string]any{"title": "Home"},
		"bad":   map[string]any{"title": "Bad", site.Expires: "whenever"},
	})
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/bad", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("a page with an unreadable date answered %d; a typo must not "+
			"silently lift an embargo", w.Code)
	}
}

// The window is evaluated per request, so time passing is enough.
func TestThePageDisappearsWhenItsMomentArrives(t *testing.T) {
	soon := time.Now().Add(1500 * time.Millisecond).UTC().Format(time.RFC3339)
	st := published(t, map[string]any{
		"index": map[string]any{"title": "Home", site.Expires: soon},
	})
	h := st.Handler()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("not served before it expires: %d", w.Code)
	}

	time.Sleep(2 * time.Second)

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("still served %d after expiring; nothing ran in between, "+
			"which is exactly the point", w.Code)
	}
}
