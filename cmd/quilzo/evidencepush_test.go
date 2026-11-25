// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/dpop"
)

// A pipeline's push asks the platform for the job's identity token for the
// server's audience, exchanges it with a proof by a key made in the
// process, and pushes the file with that key's fresh proof and the token it
// was given; it writes nothing to the job's disk.
func TestEvidencePushUsesTheJobsIdentityAndAKeyOfItsOwn(t *testing.T) {
	var server string
	var thumbs []string
	var pushed []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/idtoken":
			if r.Header.Get("Authorization") != "bearer the-request-token" || r.URL.Query().Get("audience") != server {
				t.Errorf("the identity token was asked for with %q for %q", r.Header.Get("Authorization"), r.URL.Query().Get("audience"))
			}
			io.WriteString(w, `{"value":"the-jobs-identity"}`)
		case "/token/exchange":
			p, err := dpop.Verify(r.Header.Get("DPoP"), "POST", server+"/token/exchange", "", time.Now())
			if err != nil {
				t.Errorf("the exchange's proof: %v", err)
			}
			thumbs = append(thumbs, p.Thumbprint)
			_ = r.ParseForm()
			if r.PostForm.Get("subject_token") != "the-jobs-identity" ||
				r.PostForm.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:id_token" {
				t.Errorf("exchanged %v", r.PostForm)
			}
			io.WriteString(w, `{"access_token":"qz_short","token_type":"DPoP","expires_in":600}`)
		case "/api/v1/evidence/import":
			if r.Header.Get("Authorization") != "DPoP qz_short" || r.URL.Query().Get("format") != "sarif" {
				t.Errorf("pushed with %q to %s", r.Header.Get("Authorization"), r.URL)
			}
			p, err := dpop.Verify(r.Header.Get("DPoP"), "POST", server+"/api/v1/evidence/import", "qz_short", time.Now())
			if err != nil {
				t.Errorf("the push's proof: %v", err)
			}
			thumbs = append(thumbs, p.Thumbprint)
			pushed, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, `{"grade":"ci","source":"docs-ci","facts":9,"written":9}`)
		default:
			t.Errorf("asked for %s", r.URL)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	server = srv.URL
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL+"/idtoken?api-version=2.0")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "the-request-token")
	dir := t.TempDir()
	file := filepath.Join(dir, "results.sarif")
	if err := os.WriteFile(file, []byte(`{"version":"2.1.0","runs":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := pushEvidence(context.Background(), srv.Client(), pushOptions{file: file, format: "sarif", to: srv.URL}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if res["grade"] != "ci" || string(pushed) != `{"version":"2.1.0","runs":[]}` {
		t.Errorf("the push answered %v and sent %s", res, pushed)
	}
	if len(thumbs) != 2 || thumbs[0] != thumbs[1] {
		t.Errorf("the exchange and the push were proved by %v, not one key", thumbs)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("the push left files beside the one it sent: %v", entries)
	}
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), "qz_short") {
		t.Error("the server's token is in what the push prints")
	}

	// The server's address is https: the job's identity token goes to it.
	for _, to := range []string{"http://admin.example", "https://admin.example/path", "https://user:pw@admin.example"} {
		if _, err := pushEvidence(context.Background(), srv.Client(), pushOptions{file: file, format: "sarif", to: to,
			idToken: "x"}, time.Now); err == nil {
			t.Errorf("a push to %s was attempted", to)
		}
	}
}
