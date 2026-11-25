// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/evidence"
	"github.com/quilzo/quilzo/internal/register"
)

// withEvidence brings one file in as evidence on a test server's store, as
// a person would on the command line.
func withEvidence(t *testing.T, s *Server) evidence.Result {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "ocsf", "prowler-1.2.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	reg := register.Open(s.Store)
	reg.Audit = func(audit.Record) error { return nil }
	by := register.Actor{Name: "olu", Kind: audit.KindHuman, Verified: true, May: func(auth.Action, string) error { return nil }}
	res, err := evidence.New(reg).Ingest(by, "", evidence.Input{Format: evidence.FormatOCSF, Body: b})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func init() {
	moduleExamples["/api/v1/evidence/formats"] = func(t *testing.T, s *Server) (string, string) {
		return "/api/v1/evidence/formats", officer(t, s)
	}
	moduleExamples["/api/v1/evidence/files"] = func(t *testing.T, s *Server) (string, string) {
		withEvidence(t, s)
		return "/api/v1/evidence/files", officer(t, s)
	}
	moduleExamples["/api/v1/evidence/files/{id}"] = func(t *testing.T, s *Server) (string, string) {
		res := withEvidence(t, s)
		return "/api/v1/evidence/files/" + string(res.Batch.RawID), officer(t, s)
	}
	moduleExamples["/api/v1/evidence/verify"] = func(t *testing.T, s *Server) (string, string) {
		withEvidence(t, s)
		return "/api/v1/evidence/verify", officer(t, s)
	}
}

// The evidence routes read what was brought in: the files with their
// grades, one file with its check and what was read from it, by its
// identifier or its digest, and a check of them all.
func TestTheEvidenceRoutesReadWhatWasBroughtIn(t *testing.T) {
	s, _, _ := setup(t)
	res := withEvidence(t, s)
	tok := officer(t, s)

	var files struct {
		Files []evidence.File `json:"files"`
		Total int             `json:"total"`
	}
	w := req(t, s, "GET", "/api/v1/evidence/files", tok, nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &files); err != nil || files.Total != 1 || files.Files[0].Record.Grade != register.GradeUploaded {
		t.Fatalf("the files are %s, %v", w.Body, err)
	}
	for _, name := range []string{string(res.Batch.RawID), string(res.Batch.Digest)} {
		var one struct {
			OK    bool           `json:"ok"`
			Check evidence.Check `json:"check"`
			Read  []string       `json:"read"`
		}
		w := req(t, s, "GET", "/api/v1/evidence/files/"+name, tok, nil, nil)
		if err := json.Unmarshal(w.Body.Bytes(), &one); err != nil || !one.OK || len(one.Read) != len(res.Batch.Facts) {
			t.Errorf("the file by %s is %d %s", name, w.Code, w.Body)
		}
	}
	if w := req(t, s, "GET", "/api/v1/evidence/files/sha256:"+string(make([]byte, 0))+"00", tok, nil, nil); w.Code != http.StatusNotFound {
		t.Errorf("a file that is not there answered %d", w.Code)
	}
	var all struct {
		Files, Problems int
	}
	w = req(t, s, "GET", "/api/v1/evidence/verify", tok, nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &all); err != nil || all.Files != 1 || all.Problems != 0 {
		t.Errorf("the check of every file is %s", w.Body)
	}
}
