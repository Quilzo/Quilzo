package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rsh1k/scrivet/internal/auth"
	"github.com/rsh1k/scrivet/internal/provenance"
	"github.com/rsh1k/scrivet/internal/store"
)

// The state every installation is in for its first few minutes.
//
// Every other test in this package starts from setup, and setup saves a draft
// before it hands the server over. That is a reasonable thing for a test about
// editing to do, and it meant that nothing here had ever opened a store with
// nothing in it — so the first save through the browser, on a machine somebody
// had just run init on, panicked on a nil map and dropped the connection with
// no response at all. Two more screens answered 500 with "not an object id: """,
// which reads to a new user as a broken installation.
//
// The empty store is not an edge case. It is the state the product is in when
// somebody sees it for the first time, and it is the one state no test covered.

// emptyStore is setup without the draft: a real store, real policy, real token,
// and no content whatsoever.
func emptyStore(t *testing.T) (*Server, string) {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{
		Principal: "editor", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	ts := &auth.TokenStore{}
	secret, _, err := ts.Issue("test", "editor", auth.RoleAdmin, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(s, pol, ts, siteTemplate)
	if err != nil {
		t.Fatal(err)
	}
	idx := provenance.NewIndex()
	srv.LoadProvenance = func() (*provenance.Index, error) { return idx, nil }
	srv.SaveProvenance = func(i *provenance.Index) error { idx = i; return nil }
	return srv, secret
}

// Opening any screen on a store with no content must explain, not fail.
func TestEveryScreenSurvivesAnEmptyStore(t *testing.T) {
	srv, token := emptyStore(t)

	for r := range servedRoutes(t) {
		if strings.HasSuffix(r, "/") && r != "/" {
			continue
		}
		if _, excused := notAScreen[r]; excused {
			continue
		}
		path := r
		t.Run(path, func(t *testing.T) {
			w := get(t, srv, path, token)
			switch w.Code {
			case http.StatusOK, http.StatusMethodNotAllowed,
				http.StatusServiceUnavailable:
			default:
				t.Fatalf("%s answered %d on a store with nothing in it; a new "+
					"installation is the first thing anybody sees and it has "+
					"to say so rather than fail\n%s",
					path, w.Code, firstLines(w.Body.String(), 6))
			}
			if strings.Contains(w.Body.String(), "<!-- render error:") {
				t.Fatalf("%s rendered with a template error", path)
			}
		})
	}
}

// Posting to any route on an empty store must not panic and must not 500.
//
// The body below is deliberately one flat set of plausible field names rather
// than a correct body per route: the assertion is not that the write succeeds,
// it is that a handler reaching for content that does not exist answers instead
// of dying. A redirect, a 400, a 404, a 422 are all fine — they are the handler
// deciding something. A 500 is it giving up, and no response at all is a panic
// the http server caught and turned into a closed connection, which is what
// this was written after finding.
func TestEveryWriteRouteSurvivesAnEmptyStore(t *testing.T) {
	srv, token := emptyStore(t)

	body := strings.NewReader(strings.Join([]string{
		"__name=first", "__message=first+save", "title=Hello", "body=Some+text",
		"name=first", "label=First", "id=x", "slug=y", "page=first",
		"reason=because", "source=human", "order=nav", "who=editor",
	}, "&"))

	posted := 0
	for r := range servedRoutes(t) {
		if strings.HasSuffix(r, "/") && r != "/" {
			continue
		}
		path := r
		t.Run(path, func(t *testing.T) {
			body.Seek(0, 0)
			req := httptest.NewRequest(http.MethodPost, path, body)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			w := httptest.NewRecorder()

			// A panic here would otherwise be recovered by net/http in the real
			// server and seen only as an empty reply. In a test there is no
			// recovery, so it fails loudly, which is the point.
			srv.Handler().ServeHTTP(w, req)
			posted++

			// 503 is this build saying the capability was never wired in, which
			// is a decision and not a collapse — the same allowance the GET
			// sweep makes. Anything else in the 500s is the handler giving up.
			if w.Code >= 500 && w.Code != http.StatusServiceUnavailable {
				t.Fatalf("POST %s answered %d on an empty store\n%s",
					path, w.Code, firstLines(w.Body.String(), 6))
			}
		})
	}
	if posted < 25 {
		t.Errorf("only %d routes were posted to; this test is checking almost "+
			"nothing", posted)
	}
}

// The specific bug, kept as its own case.
//
// Named separately from the sweep above because this is the one a person does
// first: install the thing, open the browser, write a page, press save. It
// panicked, and the browser showed a connection error with nothing in the log
// that a user would ever see.
func TestFirstSaveOnAFreshStore(t *testing.T) {
	srv, token := emptyStore(t)

	form := strings.NewReader("__name=welcome&title=Welcome&body=First+page")
	req := httptest.NewRequest(http.MethodPost, "/save", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("saving the first page answered %d, want a redirect\n%s",
			w.Code, firstLines(w.Body.String(), 6))
	}
	// And it has to have actually stored it, not merely survived.
	got := get(t, srv, "/page/welcome", token)
	if !strings.Contains(got.Body.String(), "Welcome") {
		t.Fatal("the first page saved without error and is not in the draft")
	}
}
