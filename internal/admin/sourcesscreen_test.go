// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/sources"
)

// postForm posts a form as a same-origin page does.
func postSourceForm(t *testing.T, srv *Server, token, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// addSource adds a source as a person, made at the moment given.
func addSource(t *testing.T, srv *Server, src register.Source, at time.Time) {
	t.Helper()
	reg := register.Open(srv.Store)
	reg.Audit = func(audit.Record) error { return nil }
	reg.Now = func() time.Time { return at }
	by := register.Actor{Name: "editor", Kind: audit.KindHuman, Verified: true, May: func(auth.Action, string) error { return nil }}
	if _, err := sources.Open(reg).Add(by, src); err != nil {
		t.Fatal(err)
	}
}

// The Sources screen names every stale source with its age, first, in
// words and with a badge that is not colour alone; each screen passes the
// accessibility checks.
func TestTheSourcesScreenNamesStaleSources(t *testing.T) {
	srv, token := setup(t)
	recording(t)
	stale, err := sources.PipelineSource(sources.Pipeline{Name: "docs-ci", Title: "Docs pipeline", Repository: "octo/docs",
		Workflow: ".github/workflows/evidence.yml", Fresh: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	addSource(t, srv, stale, time.Now().Add(-3*time.Hour))
	entra, err := sources.ConnectorSource(sources.Connector{Name: "entra-prod", Recipe: "entra",
		Params: map[string]string{"tenant": "72f988bf-86f1-41af-91ab-2d7cd011db47"}})
	if err != nil {
		t.Fatal(err)
	}
	addSource(t, srv, entra, time.Now())

	w := get(t, srv, "/sources", token)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "Stale sources") ||
		!strings.Contains(body, "Docs pipeline: has never reported, added 3 hours ago, expected every 1 hour") {
		t.Fatalf("the Sources screen: %d\n%s", w.Code, body)
	}
	if !strings.Contains(body, `aria-label="Warning"`) && !strings.Contains(body, "kit-badge-word\">Stale") {
		t.Error("the stale badge has no word")
	}
	accessible(t, "/sources", body)
	for _, path := range []string{"/sources/item/docs-ci", "/sources/item/entra-prod", "/sources/add"} {
		w := get(t, srv, path, token)
		if w.Code != http.StatusOK {
			t.Errorf("%s: %d", path, w.Code)
		}
		accessible(t, path, w.Body.String())
	}
	item := get(t, srv, "/sources/item/entra-prod", token).Body.String()
	for _, want := range []string{"graph.microsoft.com", "User.Read.All", "entra-client-secret", "not kept yet",
		"verified against recorded responses"} {
		if !strings.Contains(item, want) {
			t.Errorf("the connector's screen does not say %q", want)
		}
	}
	if w := get(t, srv, "/sources/item/nobody", token); w.Code != http.StatusNotFound {
		t.Errorf("an unknown source: %d", w.Code)
	}
}

// A source is added from the screen, with every error named beside its
// field and summarised at the top; a credential is refused on a store that
// cannot seal it; a run with nothing in the vault writes nothing and says
// why.
func TestASourceIsAddedRunAndKeptFromTheScreens(t *testing.T) {
	srv, token := setup(t)
	recording(t)
	var acts []string
	srv.Audit = func(action, _ string, _ map[string]string) { acts = append(acts, action) }
	w := postSourceForm(t, srv, token, "/sources/add", url.Values{"kind": {"pipeline"}, "name": {"Not A Name"},
		"repository": {"octo"}, "workflow": {"x"}, "hours": {"0"}})
	body := w.Body.String()
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(body, "There are 2 problems") ||
		!strings.Contains(body, `id="source-name-error"`) || !strings.Contains(body, `id="source-hours-error"`) {
		t.Fatalf("a wrong form: %d\n%s", w.Code, body)
	}
	accessible(t, "/sources/add", body)
	w = postSourceForm(t, srv, token, "/sources/add", url.Values{"kind": {"connector"}, "name": {"okta-prod"},
		"recipe": {"okta"}, "org": {"northwind"}, "owner": {"priya@northwind.example"}, "hours": {"24"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/sources/item/okta-prod?said=added" {
		t.Fatalf("adding a connector: %d %s", w.Code, w.Body)
	}
	src, _, err := sources.Open(register.Open(srv.Store)).Source("okta-prod")
	if err != nil || src.Hosts[0] != "northwind.okta.com" || src.Owner == "" || src.By != "service" {
		t.Fatalf("the source: %+v %v", src, err)
	}
	if !strings.Contains(get(t, srv, "/sources/item/okta-prod?said=added", token).Body.String(), "The source was added.") {
		t.Error("the screen does not say the source was added")
	}
	w = postSourceForm(t, srv, token, "/sources/credential", url.Values{"name": {"okta-prod"}, "credential": {"okta-api-token"},
		"value": {"00abcdefghij"}})
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "keyring") {
		t.Errorf("a credential on a store with no keyring: %d", w.Code)
	}
	w = postSourceForm(t, srv, token, "/sources/credential", url.Values{"name": {"okta-prod"}, "credential": {"github-app-key"},
		"value": {"x"}})
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("a credential the recipe does not name: %d", w.Code)
	}
	w = postSourceForm(t, srv, token, "/sources/run", url.Values{"name": {"okta-prod"}})
	if w.Code != http.StatusSeeOther || !strings.HasSuffix(w.Header().Get("Location"), "said=failed") {
		t.Fatalf("a run with no credential: %d %s", w.Code, w.Header().Get("Location"))
	}
	page := get(t, srv, "/sources/item/okta-prod?said=failed", token).Body.String()
	if !strings.Contains(page, "Last run failed") || !strings.Contains(page, "vault") {
		t.Error("the failed run is not shown with why")
	}
	accessible(t, "/sources/item/okta-prod", page)
	if n, _, _ := register.Open(srv.Store).List(register.KindObservation, 0, 1); len(n) != 0 {
		t.Error("a failed run wrote facts")
	}
	if !strings.Contains(strings.Join(acts, " "), register.AuditAction) {
		t.Errorf("adding the source is not in the audit log: %v", acts)
	}
}
