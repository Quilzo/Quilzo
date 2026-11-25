// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/sheet"
)

func init() {
	moduleExamples["/api/v1/register/records/{id}/history"] = func(t *testing.T, s *Server) (string, string) {
		id, _ := withControls(t, s)
		return "/api/v1/register/records/" + string(id) + "/history", officer(t, s)
	}
	moduleExamples["/api/v1/register/export/{kind}"] = func(t *testing.T, s *Server) (string, string) {
		withControls(t, s)
		return "/api/v1/register/export/control", officer(t, s)
	}
	moduleExamples["/api/v1/register/inventory"] = func(t *testing.T, s *Server) (string, string) {
		return "/api/v1/register/inventory", officer(t, s)
	}
}

// PLAN themes 7 and 28: the register's routes filter a kind by a field's
// value, give a record's history, export a kind as a table or as CSV with
// every cell safe for a spreadsheet, give the top risks, say what a
// record names beside the register, and give the data inventory.
func TestTheRegisterRoutesFilterExportAndFollowHistory(t *testing.T) {
	s, _, _ := setup(t)
	put, _ := withControls(t, s)
	tok := officer(t, s)
	r := register.Open(s.Store)
	r.Audit = func(audit.Record) error { return nil }
	r.Now = func() time.Time { return time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC) }
	by := register.Actor{Name: "olu", Subject: "d0000000000000000000000000000001", Kind: audit.KindHuman,
		May: func(auth.Action, string) error { return nil }}
	renamed := register.Control{Ref: "AC-01", Title: "+cmd|' /C calc'!A0", Domain: "identity",
		Owner: "0123456789abcdef0123456789abcdef"}
	if _, err := r.Put(by, "renamed", renamed); err != nil {
		t.Fatal(err)
	}
	for i, li := range []int64{2, 5} {
		if _, err := r.Put(by, "a risk", register.Risk{Ref: "R-" + string(rune('1'+i)), Title: "A risk", Owner: by.Subject,
			Raised: by.Subject, Likelihood: li, Impact: 3, Status: "open"}); err != nil {
			t.Fatal(err)
		}
	}

	var list struct {
		Total int `json:"total"`
	}
	w := req(t, s, "GET", "/api/v1/register/kinds/control?filter="+url.QueryEscape("domain=endpoints"), tok, nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || w.Code != http.StatusOK || list.Total != 1 {
		t.Errorf("the filtered list: %d %s", w.Code, w.Body)
	}
	if w := req(t, s, "GET", "/api/v1/register/kinds/control?filter=colour%3Dred", tok, nil, nil); w.Code != http.StatusBadRequest {
		t.Errorf("a filter on a field the kind lacks answered %d", w.Code)
	}

	var h struct {
		Changes []register.Change `json:"changes"`
	}
	w = req(t, s, "GET", "/api/v1/register/records/"+string(put)+"/history", tok, nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &h); err != nil || len(h.Changes) != 2 || h.Changes[0].Why != "renamed" {
		t.Errorf("the history: %d %s", w.Code, w.Body)
	}
	if w := req(t, s, "GET", "/api/v1/register/records/ffffffffffffffffffffffffffffffff/history", tok, nil, nil); w.Code != http.StatusNotFound {
		t.Errorf("the history of nothing answered %d", w.Code)
	}

	var table struct {
		Columns []string   `json:"columns"`
		Rows    [][]string `json:"rows"`
	}
	w = req(t, s, "GET", "/api/v1/register/export/control", tok, nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &table); err != nil || len(table.Rows) != 2 || table.Columns[0] != "id" {
		t.Fatalf("the export: %d %s", w.Code, w.Body)
	}
	w = req(t, s, "GET", "/api/v1/register/export/control?format=csv", tok, nil, nil)
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/csv") || len(rows) != 3 {
		t.Fatalf("the CSV export: %d %v %s", w.Code, err, w.Body)
	}
	for _, row := range rows[1:] {
		for _, cell := range row {
			if sheet.IsFormula(cell) {
				t.Errorf("the cell %q would run as a formula", cell)
			}
		}
	}
	w = req(t, s, "GET", "/api/v1/register/export/risk?top=1", tok, nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &table); err != nil || len(table.Rows) != 1 ||
		table.Rows[0][len(table.Rows[0])-1] != "15" || table.Columns[len(table.Columns)-1] != "rating" {
		t.Errorf("the top risk: %d %s", w.Code, w.Body)
	}
	if w := req(t, s, "GET", "/api/v1/register/export/control?top=1", tok, nil, nil); w.Code != http.StatusBadRequest {
		t.Errorf("the top of controls answered %d", w.Code)
	}

	var one struct {
		Named []register.Named `json:"named"`
	}
	w = req(t, s, "GET", "/api/v1/register/records/"+string(put), tok, nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &one); err != nil || len(one.Named) != 1 || one.Named[0].Field != "owner" ||
		one.Named[0].Said != "subject not in the map" {
		t.Errorf("what the record names: %s", w.Body)
	}

	var inv register.DataInventory
	w = req(t, s, "GET", "/api/v1/register/inventory", tok, nil, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &inv); err != nil || len(inv.Kinds) != len(register.Kinds()) {
		t.Errorf("the inventory: %d %s", w.Code, w.Body)
	}
}
