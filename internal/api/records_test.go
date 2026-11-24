// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/schema"
)

// Content that fails its type answers 422, not 500.
//
// It answered 500 until somebody looked: a record missing a required field
// paged an on-call engineer, spent an error budget on a typo, and told the
// client to retry something that could never succeed however many times it
// was sent. The distinction a caller needs is "your content is wrong" versus
// "this server is broken", and only the writer knows which.
func TestInvalidContentIsAClientErrorNotAServerError(t *testing.T) {
	if !schema.IsInvalid(&schema.Invalid{Where: "products"}) {
		t.Fatal("a schema.Invalid is not recognised as invalid content, so " +
			"every caller will keep reporting it as a server fault")
	}
	// And an ordinary error is not mistaken for one, or a real failure would
	// start being reported to clients as their own fault.
	if schema.IsInvalid(errors.New("the disk is full")) {
		t.Error("an unrelated error was classified as invalid content")
	}
	// Wrapped, because the write path returns it through several layers.
	wrapped := fmt.Errorf("writing records: %w", &schema.Invalid{Where: "x"})
	if !schema.IsInvalid(wrapped) {
		t.Error("a wrapped validation error was not recognised")
	}
}

// recordsServer is a server with two collections and somebody granted one
// of them, and somebody granted the section of pages that shares its name.
func recordsServer(t *testing.T) (*Server, map[string]string) {
	t.Helper()
	srv, readTok, _ := setup(t)
	tree := ""
	for _, c := range []string{"samples", "payroll"} {
		next, _, err := collection.Put(srv.Store, tree, c, collection.Record{ID: strings.Repeat("a", 32),
			Fields: map[string]any{"name": c}}, time.Now(), nil)
		if err != nil {
			t.Fatal(err)
		}
		tree = next
	}
	srv.Records = &Records{Tree: func() (string, error) { return tree, nil }}
	tokens := map[string]string{"reader": readTok}
	for who, b := range map[string]auth.Binding{
		"tech":  {Role: auth.RoleReader, Resource: auth.DataResource("samples")},
		"pages": {Role: auth.RoleReader, Resource: "/samples"},
	} {
		b.Principal = who
		if err := srv.Policy.Grant(b); err != nil {
			t.Fatal(err)
		}
		tok, _, err := srv.Tokens.Issue(who, who, auth.RoleReader, "/", time.Hour, auth.RoleAdmin)
		if err != nil {
			t.Fatal(err)
		}
		tokens[who] = tok
	}
	return srv, tokens
}

// A collection is asked about as itself: a grant on one collection reads
// it and nothing else, and a section of pages that shares its name reads
// none of it.
func TestARecordsGrantIsOnTheCollection(t *testing.T) {
	srv, tok := recordsServer(t)
	for _, c := range []struct {
		who, path string
		want      int
	}{
		{"tech", "/api/v1/records/samples", http.StatusOK},
		{"tech", "/api/v1/records/payroll", http.StatusForbidden},
		{"pages", "/api/v1/records/samples", http.StatusForbidden},
		{"reader", "/api/v1/records/payroll", http.StatusOK},
	} {
		if w := req(t, srv, "GET", c.path, tok[c.who], nil, nil); w.Code != c.want {
			t.Errorf("%s %s: %d, want %d: %s", c.who, c.path, w.Code, c.want, w.Body)
		}
	}
	w := req(t, srv, "GET", "/api/v1/collections", tok["tech"], nil, nil)
	if !strings.Contains(w.Body.String(), `"samples"`) || strings.Contains(w.Body.String(), `"payroll"`) {
		t.Errorf("tech was listed %s", w.Body)
	}
}

// A record id that can address no record is refused as the caller's to fix,
// as a page name the store cannot hold is, and not answered 500 as a write
// that failed.
func TestARecordIDThatAddressesNothingIsRefusedAs400(t *testing.T) {
	srv, _ := recordsServer(t)
	srv.Types = func() (*schema.Store, error) { return &schema.Store{}, nil }
	srv.Records.Writable = true
	srv.Records.Commit = func(string, string, string) error { return nil }
	if err := srv.Policy.Grant(auth.Binding{Principal: "writer", Role: auth.RoleAuthor,
		Resource: auth.DataResource("samples")}); err != nil {
		t.Fatal(err)
	}
	tok, _, err := srv.Tokens.Issue("w2", "writer", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"not-an-id", "%C3%9Cr%C3%BCn", strings.Repeat("a", 31)} {
		w := req(t, srv, "PUT", "/api/v1/records/samples/"+id, tok,
			map[string]any{"name": "x"}, map[string]string{"If-Match": "*"})
		if w.Code != http.StatusBadRequest {
			t.Errorf("PUT a record %s answered %d, not 400: %s", id, w.Code, w.Body)
		}
	}
	// A record id that can address one is still written, and made by the
	// write (RFC 9110 §9.3.4).
	w := req(t, srv, "PUT", "/api/v1/records/samples/"+strings.Repeat("b", 32), tok,
		map[string]any{"name": "x"}, map[string]string{"If-None-Match": "*"})
	if w.Code != http.StatusCreated {
		t.Errorf("a usable record id answered %d: %s", w.Code, w.Body)
	}
}

// An empty list is [] in the content API's answers, as on the command line
// and the machine interface, and not null.
//
// encoding/json writes a nil slice as null, and a nil slice is how Go
// spells an empty list: a collection nothing matched answered "records":
// null, and a page of the listing past the last page "pages": null, so a
// client iterating the answer failed where it had nothing to do.
func TestAnEmptyListIsAListInTheContentAPI(t *testing.T) {
	srv, tok := recordsServer(t)
	for _, path := range []string{
		"/api/v1/records/samples?where=name:nobody",
		"/api/v1/pages?offset=50",
	} {
		w := req(t, srv, "GET", path, tok["reader"], nil, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "null") {
			t.Errorf("%s answered a null where an empty list is: %s", path, w.Body.String())
		}
	}
}
