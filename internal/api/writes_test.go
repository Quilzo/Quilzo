// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// -- pages -------------------------------------------------------------------

// The read a write is based on can be made, whatever the draft holds.
//
// GET served the published page and its ETag, and PUT compared If-Match
// with the page as the draft holds it. The two are one page until the
// first write, and after it they are not: a client that wrote once, then
// read the page again to make a second edit, was given the published ETag,
// refused 412, told to read it again, and given the published ETag again,
// until somebody published. GET still serves what is published, which is
// what a read token is for; ?ref=draft reads what a write replaces, for a
// caller who may write it.
func TestAWriterCanReadWhatItIsWritingTo(t *testing.T) {
	s, readTok, writeTok := setup(t)
	s.Writable = true

	live := req(t, s, "GET", "/api/v1/pages/index", writeTok, nil, nil).Header().Get("ETag")
	if w := req(t, s, "PUT", "/api/v1/pages/index", writeTok,
		map[string]any{"title": "Home", "body": "First edit."},
		map[string]string{"If-Match": live}); w.Code != http.StatusOK {
		t.Fatalf("the first write answered %d: %s", w.Code, w.Body)
	}

	// The second edit, by a client that holds nothing from the first.
	w := req(t, s, "GET", "/api/v1/pages/index?ref=draft", writeTok, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("reading the draft answered %d: %s", w.Code, w.Body)
	}
	var p Page
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Fields["body"] != "First edit." {
		t.Errorf("the draft read is not the draft: %s", w.Body)
	}
	if w := req(t, s, "PUT", "/api/v1/pages/index", writeTok,
		map[string]any{"title": "Home", "body": "Second edit."},
		map[string]string{"If-Match": w.Header().Get("ETag")}); w.Code != http.StatusOK {
		t.Fatalf("a write based on the draft as read answered %d: %s", w.Code, w.Body)
	}

	// A stale write is still refused, and the refusal names the read that
	// would let it be made again.
	w = req(t, s, "PUT", "/api/v1/pages/index", writeTok,
		map[string]any{"title": "Home", "body": "Third."},
		map[string]string{"If-Match": live})
	if w.Code != http.StatusPreconditionFailed || !strings.Contains(w.Body.String(), "ref=draft") {
		t.Errorf("a write based on what is published answered %d: %s", w.Code, w.Body)
	}

	// What is published is unchanged, and is what GET serves.
	if got := req(t, s, "GET", "/api/v1/pages/index", writeTok, nil, nil).Header().Get("ETag"); got != live {
		t.Errorf("GET served %s, not the published %s", got, live)
	}
	// The draft is for whoever may write it, on a server that takes writes.
	if w := req(t, s, "GET", "/api/v1/pages/index?ref=draft", readTok, nil, nil); w.Code != http.StatusForbidden {
		t.Errorf("a read token read the draft: %d", w.Code)
	}
	s.Writable = false
	if w := req(t, s, "GET", "/api/v1/pages/index?ref=draft", writeTok, nil, nil); w.Code != http.StatusForbidden {
		t.Errorf("a read-only API served the draft: %d", w.Code)
	}
	if w := req(t, s, "GET", "/api/v1/pages/index?ref=staging", writeTok, nil, nil); w.Code != http.StatusBadRequest {
		t.Errorf("a ref this API does not read answered %d", w.Code)
	}
	// And the API's description says where the read is.
	b, _ := json.Marshal(OpenAPI()["paths"].(map[string]any)["/api/v1/pages/{name}"])
	if !strings.Contains(string(b), `"name":"ref"`) {
		t.Error("the description of a page does not offer the draft read")
	}
}

// If-Match and If-None-Match on a write mean what RFC 9110 §13 says.
//
// If-Match: * is true only of a page that exists, and it created one that
// did not: the one thing a client sending it asks not to happen, as a
// client updating a page somebody has just deleted. If-None-Match: * is how
// a client creates a page without overwriting one, and it was refused 428
// as though no precondition had been sent; beside an If-Match it was not
// looked at, and a write it should have stopped went through.
func TestWritePreconditionsMeanWhatRFC9110Says(t *testing.T) {
	s, _, tok := setup(t)
	s.Writable = true
	page := func(name string) bool {
		pages, _ := site.PagesAt(s.Store, site.RefDraft)
		_, ok := pages[name]
		return ok
	}
	body := map[string]any{"title": "New", "body": "x"}

	if w := req(t, s, "PUT", "/api/v1/pages/new", tok, body,
		map[string]string{"If-Match": "*"}); w.Code != http.StatusPreconditionFailed {
		t.Errorf("If-Match: * on a page that does not exist answered %d: %s", w.Code, w.Body)
	}
	if page("new") {
		t.Fatal("If-Match: * created a page")
	}
	if w := req(t, s, "PUT", "/api/v1/pages/new", tok, body,
		map[string]string{"If-None-Match": "*"}); w.Code != http.StatusCreated {
		t.Errorf("If-None-Match: * on a page that does not exist answered %d: %s", w.Code, w.Body)
	}
	if !page("new") {
		t.Fatal("If-None-Match: * did not create the page")
	}
	if w := req(t, s, "PUT", "/api/v1/pages/new", tok, map[string]any{"title": "Over"},
		map[string]string{"If-None-Match": "*"}); w.Code != http.StatusPreconditionFailed {
		t.Errorf("If-None-Match: * on a page that exists answered %d", w.Code)
	}
	etag := req(t, s, "GET", "/api/v1/pages/new?ref=draft", tok, nil, nil).Header().Get("ETag")
	if w := req(t, s, "PUT", "/api/v1/pages/new", tok, map[string]any{"title": "Over"},
		map[string]string{"If-Match": etag, "If-None-Match": etag}); w.Code != http.StatusPreconditionFailed {
		t.Errorf("an If-None-Match naming the page's ETag, beside an If-Match, answered %d", w.Code)
	}
	pages, _ := site.PagesAt(s.Store, site.RefDraft)
	if pages["new"].(map[string]any)["title"] != "New" {
		t.Error("a write a precondition refused landed anyway")
	}
	// And a page that exists is still written with If-Match: *.
	if w := req(t, s, "PUT", "/api/v1/pages/new", tok, map[string]any{"title": "Mine"},
		map[string]string{"If-Match": "*"}); w.Code != http.StatusOK {
		t.Errorf("If-Match: * on a page that exists answered %d: %s", w.Code, w.Body)
	}
	// With neither, the write is blind, and the refusal says how to create.
	w := req(t, s, "PUT", "/api/v1/pages/other", tok, body, nil)
	if w.Code != http.StatusPreconditionRequired || !strings.Contains(w.Body.String(), "If-None-Match: *") {
		t.Errorf("a write with no precondition answered %d: %s", w.Code, w.Body)
	}
}

// A PUT that creates answers 201 Created, which RFC 9110 §9.3.4 requires,
// and one that replaces answers 200. Both answered 200, so a client could
// not tell that its write made a page rather than changing one.
func TestAPutThatCreatesAnswers201(t *testing.T) {
	s, _, tok := setup(t)
	s.Writable = true
	w := req(t, s, "PUT", "/api/v1/pages/fresh", tok, map[string]any{"title": "Fresh"},
		map[string]string{"If-None-Match": "*"})
	if w.Code != http.StatusCreated || w.Header().Get("ETag") == "" {
		t.Errorf("creating a page answered %d with ETag %q", w.Code, w.Header().Get("ETag"))
	}
	w = req(t, s, "PUT", "/api/v1/pages/fresh", tok, map[string]any{"title": "Again"},
		map[string]string{"If-Match": w.Header().Get("ETag")})
	if w.Code != http.StatusOK {
		t.Errorf("replacing a page answered %d", w.Code)
	}

	srv, rtok := recordStore(t)
	id := strings.Repeat("c", 32)
	w = req(t, srv, "PUT", "/api/v1/records/samples/"+id, rtok, map[string]any{"name": "c"},
		map[string]string{"If-None-Match": "*"})
	if w.Code != http.StatusCreated {
		t.Errorf("creating a record by PUT answered %d: %s", w.Code, w.Body)
	}
	w = req(t, srv, "PUT", "/api/v1/records/samples/"+id, rtok, map[string]any{"name": "d"},
		map[string]string{"If-Match": w.Header().Get("ETag")})
	if w.Code != http.StatusOK {
		t.Errorf("replacing a record answered %d: %s", w.Code, w.Body)
	}

	// And the API's description says so, which listed 200 alone.
	paths := OpenAPI()["paths"].(map[string]any)
	for _, p := range []string{"/api/v1/pages/{name}", "/api/v1/records/{collection}/{id}"} {
		put := paths[p].(map[string]any)["put"].(map[string]any)
		if _, ok := put["responses"].(map[string]any)["201"]; !ok {
			t.Errorf("PUT %s is not described as answering 201", p)
		}
	}
}

// The body null is not an object, and is refused as every other body that
// is not one is. It was taken as a page whose fields were null, and as a
// record with none.
func TestANullBodyIsNotAnObject(t *testing.T) {
	s, _, tok := setup(t)
	s.Writable = true
	put := func(srv *Server, path, token string, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, path, strings.NewReader("null"))
		r.Header.Set("Authorization", "Bearer "+token)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		return w
	}
	if w := put(s, "/api/v1/pages/index", tok, map[string]string{"If-Match": "*"}); w.Code != http.StatusBadRequest {
		t.Errorf("PUT null on a page answered %d: %s", w.Code, w.Body)
	}
	pages, _ := site.PagesAt(s.Store, site.RefDraft)
	if pages["index"] == nil {
		t.Error("the page's fields are null")
	}
	srv, rtok := recordStore(t)
	if w := put(srv, "/api/v1/records/samples/"+strings.Repeat("e", 32), rtok, nil); w.Code != http.StatusBadRequest {
		t.Errorf("PUT null on a record answered %d: %s", w.Code, w.Body)
	}
}

// -- records -----------------------------------------------------------------

// recordStore is a server whose records are read from the draft and
// committed to it, as `quilzo serve` wires them, and a token for somebody
// who may write the samples collection.
func recordStore(t *testing.T) (*Server, string) {
	t.Helper()
	srv, _, _ := setup(t)
	srv.Types = func() (*schema.Store, error) { return &schema.Store{}, nil }
	srv.Records = &Records{
		Writable: true,
		Tree: func() (string, error) {
			c, err := srv.Store.GetCommit(srv.Store.GetRef(site.RefDraft))
			return c.Tree, err
		},
		Commit: func(tree, message, author string) error {
			cid, err := srv.Store.PutCommit(store.Commit{Tree: tree,
				Parents: []string{srv.Store.GetRef(site.RefDraft)},
				Message: message, Author: author, At: time.Now().Unix()})
			if err != nil {
				return err
			}
			return srv.Store.SetRef(site.RefDraft, cid)
		},
	}
	if err := srv.Policy.Grant(auth.Binding{Principal: "keeper", Role: auth.RoleAuthor,
		Resource: auth.DataResource("samples")}); err != nil {
		t.Fatal(err)
	}
	tok, _, err := srv.Tokens.Issue("k", "keeper", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return srv, tok
}

// added is a record POSTed to samples, and its ETag.
func added(t *testing.T, srv *Server, tok string, fields map[string]any) (collection.Record, string) {
	t.Helper()
	w := req(t, srv, "POST", "/api/v1/records/samples", tok, fields, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("adding a record answered %d: %s", w.Code, w.Body)
	}
	var rec collection.Record
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	return rec, w.Header().Get("ETag")
}

// Deleting a record takes If-Match, as every write does and as the API's
// own description says. It took none: with no If-Match, or with one that
// no longer matched, the record was deleted, so a client deleting what it
// read deleted whatever somebody had put there since.
func TestDeletingARecordNeedsACurrentIfMatch(t *testing.T) {
	srv, tok := recordStore(t)
	rec, etag := added(t, srv, tok, map[string]any{"name": "first"})
	path := "/api/v1/records/samples/" + rec.ID
	edited := req(t, srv, "PUT", path, tok, map[string]any{"name": "edited"},
		map[string]string{"If-Match": etag})
	if edited.Code != http.StatusOK {
		t.Fatalf("the edit answered %d: %s", edited.Code, edited.Body)
	}

	if w := req(t, srv, "DELETE", path, tok, nil, nil); w.Code != http.StatusPreconditionRequired {
		t.Errorf("a delete with no If-Match answered %d", w.Code)
	}
	if w := req(t, srv, "DELETE", path, tok, nil, map[string]string{"If-Match": etag}); w.Code != http.StatusPreconditionFailed {
		t.Errorf("a delete with a stale If-Match answered %d", w.Code)
	}
	if w := req(t, srv, "GET", path, tok, nil, nil); w.Code != http.StatusOK {
		t.Fatalf("a refused delete deleted the record: %d", w.Code)
	}
	if w := req(t, srv, "DELETE", path, tok, nil,
		map[string]string{"If-Match": edited.Header().Get("ETag")}); w.Code != http.StatusNoContent {
		t.Errorf("a delete with the current If-Match answered %d: %s", w.Code, w.Body)
	}
	if w := req(t, srv, "GET", path, tok, nil, nil); w.Code != http.StatusNotFound {
		t.Errorf("the deleted record answered %d", w.Code)
	}
	other, _ := added(t, srv, tok, map[string]any{"name": "other"})
	if w := req(t, srv, "DELETE", "/api/v1/records/samples/"+other.ID, tok, nil,
		map[string]string{"If-Match": "*"}); w.Code != http.StatusNoContent {
		t.Errorf("a delete with If-Match: * answered %d", w.Code)
	}
}

// A record's ETag is its content hash, so a second write in the same
// second is a different ETag.
//
// It was the id and the second the record was last written in. Two writes
// inside one second kept the first one's ETag, so a client holding it from
// before the second write passed If-Match and overwrote that write unseen:
// the lost update If-Match exists to prevent. Retried until both writes
// land in one second, which is the case that went wrong.
func TestARecordsETagChangesWithEveryWrite(t *testing.T) {
	srv, tok := recordStore(t)
	for try := 0; try < 5; try++ {
		rec, first := added(t, srv, tok, map[string]any{"n": 1.0})
		path := "/api/v1/records/samples/" + rec.ID
		w := req(t, srv, "PUT", path, tok, map[string]any{"n": 2.0},
			map[string]string{"If-Match": first})
		if w.Code != http.StatusOK {
			t.Fatalf("the second write answered %d: %s", w.Code, w.Body)
		}
		var second collection.Record
		if err := json.Unmarshal(w.Body.Bytes(), &second); err != nil {
			t.Fatal(err)
		}
		if second.Updated != rec.Updated {
			continue
		}
		if w.Header().Get("ETag") == first {
			t.Fatalf("a different record kept the ETag %s", first)
		}
		if w := req(t, srv, "PUT", path, tok, map[string]any{"n": 3.0},
			map[string]string{"If-Match": first}); w.Code != http.StatusPreconditionFailed {
			t.Errorf("a write based on the record before the last one answered %d", w.Code)
		}
		got := req(t, srv, "GET", path, tok, nil, nil)
		if !strings.Contains(got.Body.String(), `"n":2`) {
			t.Errorf("the record is now %s", got.Body)
		}
		// The ETag is the object id the store keeps the record under.
		tree, _ := srv.Records.Tree()
		ids, err := srv.Store.GetNested(tree)
		if err != nil {
			t.Fatal(err)
		}
		if want := quote(ids[collection.Path("samples", rec.ID)]); got.Header().Get("ETag") != want {
			t.Errorf("the ETag is %s and the record is stored as %s", got.Header().Get("ETag"), want)
		}
		return
	}
	t.Skip("no two writes landed in the same second in five tries")
}

// A record deleted over the API is recorded as a deletion, with the commit
// that made it.
//
// It was told to OnWrite, so the audit log held api.write for the record,
// with an empty commit, and nothing anywhere said it had been deleted. A
// write named no commit either: Records.Commit returns none, and the API
// passed "".
func TestADeletionIsRecordedAsOne(t *testing.T) {
	srv, tok := recordStore(t)
	type told struct{ who, what, commit string }
	var writes, deletes []told
	srv.OnWrite = func(who, what, commit string) { writes = append(writes, told{who, what, commit}) }
	srv.OnDelete = func(who, what, commit string) { deletes = append(deletes, told{who, what, commit}) }

	rec, etag := added(t, srv, tok, map[string]any{"name": "gone"})
	if len(writes) != 1 || writes[0].commit != srv.Store.GetRef(site.RefDraft) {
		t.Errorf("a write was told as %+v; the draft is %s", writes, srv.Store.GetRef(site.RefDraft))
	}
	if w := req(t, srv, "DELETE", "/api/v1/records/samples/"+rec.ID, tok, nil,
		map[string]string{"If-Match": etag}); w.Code != http.StatusNoContent {
		t.Fatalf("the delete answered %d: %s", w.Code, w.Body)
	}
	if len(writes) != 1 {
		t.Errorf("a deletion was told as a write: %+v", writes[1:])
	}
	if len(deletes) != 1 || deletes[0].who != "keeper" || deletes[0].what != "samples/"+rec.ID ||
		deletes[0].commit != srv.Store.GetRef(site.RefDraft) || deletes[0].commit == writes[0].commit {
		t.Errorf("the deletion was told as %+v; the draft is %s", deletes, srv.Store.GetRef(site.RefDraft))
	}

	// A host that is told of writes alone is still told of a deletion.
	srv.OnDelete = nil
	other, etag := added(t, srv, tok, map[string]any{"name": "also"})
	req(t, srv, "DELETE", "/api/v1/records/samples/"+other.ID, tok, nil, map[string]string{"If-Match": etag})
	if last := writes[len(writes)-1]; last.what != "samples/"+other.ID || last.commit != srv.Store.GetRef(site.RefDraft) {
		t.Errorf("with no OnDelete the deletion was told as %+v", last)
	}
}
