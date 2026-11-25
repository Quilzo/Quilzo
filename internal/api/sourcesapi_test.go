// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/evidence"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/sources"
)

// withSource adds a pipeline's source to a test server's register.
func withSource(t *testing.T, s *Server) register.Source { return withSourceFresh(t, s, 0) }

func withSourceFresh(t *testing.T, s *Server, fresh time.Duration) register.Source {
	t.Helper()
	reg := register.Open(s.Store)
	reg.Audit = func(audit.Record) error { return nil }
	src, err := sources.PipelineSource(sources.Pipeline{Name: "docs-ci", Repository: "octo/docs",
		Workflow: ".github/workflows/evidence.yml", Fresh: fresh})
	if err != nil {
		t.Fatal(err)
	}
	by := register.Actor{Name: "olu", Kind: audit.KindHuman, Verified: true, May: func(auth.Action, string) error { return nil }}
	if _, err := sources.Open(reg).Add(by, src); err != nil {
		t.Fatal(err)
	}
	return src
}

func init() {
	moduleExamples["/api/v1/sources"] = func(t *testing.T, s *Server) (string, string) {
		withSource(t, s)
		return "/api/v1/sources", officer(t, s)
	}
	moduleExamples["/api/v1/sources/recipes"] = func(t *testing.T, s *Server) (string, string) {
		return "/api/v1/sources/recipes", officer(t, s)
	}
	moduleExamples["/api/v1/sources/{name}"] = func(t *testing.T, s *Server) (string, string) {
		withSource(t, s)
		return "/api/v1/sources/docs-ci", officer(t, s)
	}
	moduleExamples["/api/v1/evidence/import"] = func(t *testing.T, s *Server) (string, string) {
		return "/api/v1/evidence/import", officer(t, s)
	}
}

// post sends a file to a path as the token's holder.
func post(t *testing.T, s *Server, path, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// A file brought in through the API is held to what `quilzo ingest` holds
// it to: sealed and read as the caller, graded by how it came, written
// only for somebody the policy lets write the register, recorded in the
// audit log, and refused where the command line would refuse it.
func TestTheAPIImportsAsTheCommandLineDoes(t *testing.T) {
	s, readTok, _ := setup(t)
	var audited []audit.Record
	was := evidence.Recorder
	evidence.Recorder = func(reg *register.Register) {
		reg.Audit = func(r audit.Record) error { audited = append(audited, r); return nil }
	}
	defer func() { evidence.Recorder = was }()
	body, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "ocsf", "prowler-1.2.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	tok := officer(t, s)
	w := post(t, s, "/api/v1/evidence/import?format=ocsf", tok, body)
	var got struct {
		Grade  register.Grade `json:"grade"`
		Facts  int            `json:"facts"`
		Commit string         `json:"commit"`
	}
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Facts == 0 || got.Commit == "" {
		t.Fatalf("an officer's import: %d %s", w.Code, w.Body)
	}
	held, _ := s.Tokens.Authenticate(tok, time.Now())
	if want := evidence.GradeFor(evidence.FormatOCSF, map[bool]audit.Kind{true: audit.KindHuman, false: audit.KindService}[held.Person()], nil); got.Grade != want {
		t.Errorf("graded %s, and the command line grades %s", got.Grade, want)
	}
	if got.Grade == register.GradeCI || got.Grade == register.GradeConnector {
		t.Errorf("a file a caller sent was graded %s", got.Grade)
	}
	recorded := false
	for _, a := range audited {
		recorded = recorded || a.Action == register.AuditAction && a.Principal == "olu"
	}
	if !recorded {
		t.Error("the import is not in the audit log")
	}
	// The same file again writes nothing.
	again := post(t, s, "/api/v1/evidence/import?format=ocsf", tok, body)
	if again.Code != http.StatusCreated || bytes.Contains(again.Body.Bytes(), []byte(`"written":1`)) {
		t.Errorf("a second import: %d %s", again.Code, again.Body)
	}
	for name, c := range map[string]struct {
		path, token string
		want        int
	}{
		"a reader of the site":   {"/api/v1/evidence/import?format=ocsf", readTok, http.StatusForbidden},
		"no format":              {"/api/v1/evidence/import", tok, http.StatusBadRequest},
		"a run's format":         {"/api/v1/evidence/import?format=pull", tok, http.StatusBadRequest},
		"a table with no map":    {"/api/v1/evidence/import?format=csv", tok, http.StatusUnprocessableEntity},
		"a map nobody confirmed": {"/api/v1/evidence/import?format=csv&map=nobodys", tok, http.StatusNotFound},
	} {
		if w := post(t, s, c.path, c.token, body); w.Code != c.want {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	// A person's bearer token pushes nothing as a pipeline: it is graded
	// by how it came, under a source of its own.
	withSource(t, s)
	w = post(t, s, "/api/v1/evidence/import?format=ocsf&source=docs-ci", tok, body)
	if w.Code != http.StatusUnprocessableEntity && w.Code != http.StatusForbidden {
		t.Errorf("a person's file under a pipeline's source: %d %s", w.Code, w.Body)
	}
}

// The sources routes say how each source stands.
func TestTheSourcesRoutesSayHowEachStands(t *testing.T) {
	s, _, _ := setup(t)
	withSourceFresh(t, s, time.Second)
	tok := officer(t, s)
	var list struct {
		Sources []sources.Standing `json:"sources"`
		Stale   int                `json:"stale"`
	}
	s.Now = func() time.Time { return time.Now().Add(time.Minute) }
	w := req(t, s, "GET", "/api/v1/sources", tok, nil, nil)
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &list) != nil || len(list.Sources) != 1 ||
		!list.Sources[0].Stale || list.Stale != 1 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := req(t, s, "GET", "/api/v1/sources/nobody", tok, nil, nil); w.Code != http.StatusNotFound {
		t.Errorf("an unknown source: %d", w.Code)
	}
	var recipes struct {
		Recipes []sources.Recipe `json:"recipes"`
	}
	w = req(t, s, "GET", "/api/v1/sources/recipes", tok, nil, nil)
	if json.Unmarshal(w.Body.Bytes(), &recipes) != nil || len(recipes.Recipes) != 4 {
		t.Errorf("%s", w.Body)
	}
}
