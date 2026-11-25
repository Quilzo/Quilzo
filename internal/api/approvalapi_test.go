// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/approval"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
)

// withRisk proposes an accepted risk raised by dana, waiting for its
// approver.
func withRisk(t *testing.T, s *Server) register.ID {
	t.Helper()
	r := register.Open(s.Store)
	r.Audit = func(audit.Record) error { return nil }
	dana, err := approval.SubjectMap{Register: register.Open(s.Store)}.Pseudonym("dana")
	if err != nil {
		t.Fatal(err)
	}
	risk := register.Risk{Ref: "R-41", Title: "Payroll supplier outage", Owner: dana, Raised: dana, Likelihood: 3, Impact: 2, Status: "accepted"}
	if _, err := r.Propose(register.Actor{Name: "dana", Subject: dana, Kind: audit.KindHuman,
		May: func(auth.Action, string) error { return nil }}, "raised at the risk review", risk); err != nil {
		t.Fatal(err)
	}
	id, _ := register.IDOf(risk)
	return id
}

func init() {
	moduleExamples["/api/v1/approvals"] = func(t *testing.T, s *Server) (string, string) {
		withRisk(t, s)
		return "/api/v1/approvals", officer(t, s)
	}
	moduleExamples["/api/v1/approvals/policy"] = func(t *testing.T, s *Server) (string, string) {
		return "/api/v1/approvals/policy", officer(t, s)
	}
	moduleExamples["/api/v1/approvals/{id}"] = func(t *testing.T, s *Server) (string, string) {
		return "/api/v1/approvals/" + string(withRisk(t, s)), officer(t, s)
	}
}

// The API reads what waits for approval, with the hash of what it shows,
// and says where it is approved; approving through it is refused.
func TestApprovingOverTheAPIIsRefused(t *testing.T) {
	s, _, _ := setup(t)
	id := withRisk(t, s)
	tok := officer(t, s)
	var one struct {
		Surface register.Digest  `json:"surface"`
		Shown   approval.Surface `json:"shown"`
		Approve string           `json:"approve"`
	}
	w := req(t, s, "GET", "/api/v1/approvals/"+string(id), tok, nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &one); err != nil || w.Code != http.StatusOK || one.Shown.Digest() != one.Surface ||
		!strings.Contains(one.Approve, "passkey") {
		t.Fatalf("one decision: %d %v %s", w.Code, err, w.Body)
	}
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		w := req(t, s, method, "/api/v1/approvals/"+string(id), tok, nil, nil)
		if w.Code != http.StatusMethodNotAllowed || !strings.Contains(w.Header().Get("Allow"), "GET") {
			t.Errorf("%s answered %d, and approving over the API is refused", method, w.Code)
		}
	}
	if register.Open(s.Store).Head() != "" {
		t.Fatal("something was approved over the API")
	}
	if w := req(t, s, "GET", "/api/v1/approvals/00000000000000000000000000000000", tok, nil, nil); w.Code != http.StatusNotFound {
		t.Errorf("a decision that is not waiting answered %d", w.Code)
	}
	if w := req(t, s, "GET", "/api/v1/approvals", "", nil, nil); w.Code == http.StatusOK {
		t.Error("the approvals were read without a token")
	}
}
