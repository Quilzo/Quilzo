// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/api"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
)

// A store with one content type, one page bound to it, and a writable API.
func apiStore(t *testing.T) (string, http.Handler) {
	t.Helper()
	if w == nil {
		w = out.New(false)
		t.Cleanup(func() { w = nil })
	}
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"note": map[string]any{"title": "A note", "body": "words"},
	}, "first", "test"); err != nil {
		t.Fatal(err)
	}

	reg := schema.NewRegistry()
	if err := reg.Add(schema.Type{Name: "note", Fields: []schema.Field{
		{Name: "title", Kind: schema.Text, Required: true},
		{Name: "body", Kind: schema.LongText, Required: true},
	}}); err != nil {
		t.Fatal(err)
	}
	st := &schema.Store{Registry: reg, Bound: map[string]string{"note": "note"}}
	if err := saveJSON(filepath.Join(root, "types.json"), st); err != nil {
		t.Fatal(err)
	}

	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{
		Principal: "writer", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	ts := &auth.TokenStore{}
	tok, _, err := ts.Issue("w", "writer", auth.RoleAuthor, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	srv := &api.Server{
		Store: s, Policy: pol, Tokens: ts,
		Ref: site.RefDraft, Writable: true,
		Types: func() (*schema.Store, error) { return schema.Load(root) },
	}
	return root, authed{h: srv.Handler(), tok: tok}
}

// authed presents the write token on every request, so each test is about the
// thing it is testing rather than about authentication.
type authed struct {
	h   http.Handler
	tok string
}

func (a authed) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("Authorization", "Bearer "+a.tok)
	a.h.ServeHTTP(w, r)
}

// The API validated and wrote nothing down, so a page written through it was
// permanently indistinguishable from one nobody ever checked.
//
// Every other write path — the CLI, the admin, MCP, the importer, sections,
// Telegram — goes through gateWrite, which records. internal/admin's wiring
// states the invariant this broke: unrecorded reads as unvalidated, which is
// the safe way round. Safe, and wrong: schema.Validated exists to answer "did
// this exact content pass this exact type", and for the API the honest answer
// was no when the truth was yes.
func TestAWriteThroughTheAPIRecordsItsTypeBinding(t *testing.T) {
	root, h := apiStore(t)

	body, err := json.Marshal(map[string]any{
		"title": "A better note", "body": "more words"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/pages/note",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", "*")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code >= 400 {
		t.Fatalf("the write was refused (%d): %s", rec.Code, rec.Body.String())
	}

	types, err := schema.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	if !types.Validated("note", fields) {
		t.Error("the API stored content it had just validated and recorded " +
			"nothing, so the page is indistinguishable from one nobody checked")
	}
}

// Content that fails the gate is refused, and nothing is recorded for it.
func TestAnInvalidWriteIsRefusedAndNotRecorded(t *testing.T) {
	root, h := apiStore(t)

	// body is required by the type.
	body, err := json.Marshal(map[string]any{"title": "no body"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/pages/note",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", "*")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid content got %d: %s", rec.Code, rec.Body.String())
	}
	types, err := schema.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	if types.Validated("note", fields) {
		t.Error("content the gate refused was recorded as validated")
	}
}
