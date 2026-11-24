// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
)

// withControls puts two controls in the register of a test server's store,
// and proposes a third, as a crew would.
func withControls(t *testing.T, s *Server) (put, proposed register.ID) {
	t.Helper()
	r := register.Open(s.Store)
	r.Audit = func(audit.Record) error { return nil }
	r.Now = func() time.Time { return time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC) }
	allow := func(auth.Action, string) error { return nil }
	owner := register.ID("0123456789abcdef0123456789abcdef")
	first := register.Control{Ref: "AC-01", Title: "Second factor for every account", Domain: "identity", Owner: owner}
	waits := register.Control{Ref: "AC-03", Title: "Quarterly access review", Domain: "identity", Owner: owner}
	if _, err := r.Put(register.Actor{Name: "olu", Subject: "d0000000000000000000000000000001", Kind: audit.KindHuman, May: allow},
		"two controls", first,
		register.Control{Ref: "AC-02", Title: "Encrypted disks", Domain: "endpoints", Owner: owner}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Propose(register.Actor{Name: "control-tester", Kind: audit.KindAI, May: allow}, "drafted", waits); err != nil {
		t.Fatal(err)
	}
	put, _ = register.IDOf(first)
	proposed, _ = register.IDOf(waits)
	return put, proposed
}

func init() {
	moduleExamples["/api/v1/register/kinds"] = func(t *testing.T, s *Server) (string, string) {
		return "/api/v1/register/kinds", officer(t, s)
	}
	moduleExamples["/api/v1/register/kinds/{kind}"] = func(t *testing.T, s *Server) (string, string) {
		withControls(t, s)
		return "/api/v1/register/kinds/control", officer(t, s)
	}
	moduleExamples["/api/v1/register/records/{id}"] = func(t *testing.T, s *Server) (string, string) {
		id, _ := withControls(t, s)
		return "/api/v1/register/records/" + string(id), officer(t, s)
	}
}

// The register's routes read the register and only the register: its
// kinds with how many of each, a kind's records a page at a time, and one
// record with the hash it is stored under; a proposal is none of them.
func TestTheRegisterRoutesReadTheRegister(t *testing.T) {
	s, _, _ := setup(t)
	put, proposed := withControls(t, s)
	tok := officer(t, s)

	var kinds struct {
		Kinds []struct {
			Kind    string `json:"kind"`
			Records int    `json:"records"`
		} `json:"kinds"`
		Head string `json:"head"`
	}
	w := req(t, s, "GET", "/api/v1/register/kinds", tok, nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &kinds); err != nil || len(kinds.Kinds) != len(register.Kinds()) ||
		kinds.Head != register.Open(s.Store).Head() {
		t.Fatalf("kinds: %d %v %s", w.Code, err, w.Body)
	}
	for _, k := range kinds.Kinds {
		if k.Kind == "Control" && k.Records != 2 {
			t.Errorf("the register holds %d controls by the API's count, not 2", k.Records)
		}
	}

	var list struct {
		Total   int `json:"total"`
		Records []struct {
			ID register.ID `json:"id"`
		} `json:"records"`
	}
	w = req(t, s, "GET", "/api/v1/register/kinds/control?limit=1", tok, nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || list.Total != 2 || len(list.Records) != 1 {
		t.Fatalf("list: %d %v %s", w.Code, err, w.Body)
	}
	for path, want := range map[string]int{
		"/api/v1/register/kinds/nonsense":                      http.StatusNotFound,
		"/api/v1/register/kinds/control?limit=0":               http.StatusBadRequest,
		"/api/v1/register/records/" + string(put):              http.StatusOK,
		"/api/v1/register/records/" + string(proposed):         http.StatusNotFound,
		"/api/v1/register/records/not-an-identifier":           http.StatusNotFound,
		"/api/v1/register/records/" + string(put) + "/further": http.StatusNotFound,
	} {
		if w := req(t, s, "GET", path, tok, nil, nil); w.Code != want {
			t.Errorf("GET %s answered %d, not %d: %s", path, w.Code, want, w.Body)
		}
	}
	var one struct {
		ID     register.ID    `json:"id"`
		Kind   string         `json:"kind"`
		Object string         `json:"object"`
		Record map[string]any `json:"record"`
	}
	w = req(t, s, "GET", "/api/v1/register/records/"+string(put), tok, nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &one); err != nil || one.ID != put || one.Kind != "Control" || len(one.Object) != 64 {
		t.Errorf("record: %v %s", err, w.Body)
	}
	if w.Header().Get("ETag") != `"`+one.Object+`"` {
		t.Errorf("a record's ETag is %q, not the hash it is stored under", w.Header().Get("ETag"))
	}
}
