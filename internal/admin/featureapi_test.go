// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/feature"
)

// A pull request's CI gets the card and the plan as a comment; the CI on
// merge installs, or is told it waits, or is refused as itself.
func TestAProgramChecksAndInstallsOverHTTP(t *testing.T) {
	srv, token := setup(t)
	var asked []string
	srv.FeatureProgram = &FeatureProgram{
		Check: func(body []byte, tok auth.Token) (*feature.Package, feature.Card, feature.Plan, error) {
			p, err := feature.Decode(bytes.NewReader(body))
			if err != nil {
				return nil, feature.Card{}, feature.Plan{}, err
			}
			return p, p.MakeCard(), p.MakePlan(feature.State{}, nil), nil
		},
		Install: func(body []byte, tok auth.Token) (string, []string, error) {
			asked = append(asked, tok.Principal)
			return "0123456789ab", nil, nil
		},
	}
	post := func(path, bearer string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}
	if w := post("/features/check", "", feature.Example()); w.Code != http.StatusUnauthorized {
		t.Errorf("an anonymous check answered %d", w.Code)
	}
	w := post("/features/check", token, feature.Example())
	var got featureAnswer
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if got.Name != "lab-samples" || !strings.Contains(got.Markdown, "| add | type | `sample` |") ||
		!strings.Contains(got.Markdown, "two different people approve it") || len(asked) != 0 {
		t.Errorf("the check is not the card and the plan, or it installed:\n%s", got.Markdown)
	}
	w = post("/features/install", token, feature.Example())
	json.Unmarshal(w.Body.Bytes(), &got)
	if w.Code != http.StatusOK || got.Waiting != "0123456789ab" || !strings.Contains(got.Markdown, "Waiting for a second person") {
		t.Errorf("%d %+v", w.Code, got)
	}
	bad := post("/features/install", token, []byte(`{"format":1,"name":"x","grants":["admin"]}`))
	if bad.Code != http.StatusBadRequest {
		t.Errorf("a package with a key nobody knows answered %d", bad.Code)
	}
}
