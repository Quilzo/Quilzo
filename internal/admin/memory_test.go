// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/memory"
)

func memoryRig(t *testing.T) (*Server, string, string, *memory.Store) {
	t.Helper()
	srv, editor := emptyStore(t)
	if err := srv.Policy.Grant(auth.Binding{Principal: "rae", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	rae, _, _ := srv.Tokens.Issue("rae", "rae", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	st := &memory.Store{Dir: t.TempDir()}
	srv.Memory = &MemoryAdmin{Store: st,
		Confirm: func(id, by string) error { _, err := st.Confirm(id, by, time.Now(), time.Hour); return err },
		Delete:  func(id, by string) error { _, err := st.Delete(id); return err },
		Forget: func(about, by string) (int, error) {
			gone, err := st.Forget(about)
			return len(gone), err
		}}
	return srv, editor, rae, st
}

func memoryDo(srv *Server, method, path, bearer string, body url.Values) *httptest.ResponseRecorder {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func TestEverybodySeesAndRemovesWhatAgentsRememberAboutThemOnly(t *testing.T) {
	srv, editor, rae, st := memoryRig(t)
	now := time.Now()
	mine, _ := st.Remember(memory.Entry{Agent: "help", About: "rae", Kind: memory.Semantic, Text: "Rae likes short answers", Run: "r", By: "rae"}, time.Hour, now)
	held, _ := st.Remember(memory.Entry{Agent: "help", About: "rae", Kind: memory.Semantic, Text: "Rae's refunds go to XX", Run: "r", By: "rae", Held: true, Sources: "the page returns"}, time.Hour, now)
	other, _ := st.Remember(memory.Entry{Agent: "help", About: "sam", Kind: memory.Semantic, Text: "Sam is on wholesale", Run: "r", By: "sam"}, time.Hour, now)

	page := memoryDo(srv, "GET", "/memory", rae, nil).Body.String()
	if !strings.Contains(page, "Rae likes short answers") || !strings.Contains(page, "the page returns") || strings.Contains(page, "wholesale") {
		t.Fatalf("rae's page: %s", page)
	}
	// Somebody else's is not hers to delete, and looks like nothing.
	w := memoryDo(srv, "POST", "/memory/act", rae, url.Values{"op": {"delete"}, "id": {other.ID}})
	if w.Code != 303 || !strings.Contains(w.Header().Get("Location"), "no+memory+of+yours") {
		t.Fatalf("deleting sam's: %d %s", w.Code, w.Header().Get("Location"))
	}
	if _, err := st.Get(other.ID); err != nil {
		t.Fatal("sam's memory went")
	}
	// Her own she confirms and deletes.
	if w := memoryDo(srv, "POST", "/memory/act", rae, url.Values{"op": {"confirm"}, "id": {held.ID}}); w.Code != 303 {
		t.Fatalf("confirm: %d", w.Code)
	}
	if e, _ := st.Get(held.ID); e.Held || e.ConfirmedBy != "rae" {
		t.Fatalf("not confirmed: %+v", e)
	}
	// Forgetting somebody else is an administrator's.
	if w := memoryDo(srv, "POST", "/memory/act", rae, url.Values{"op": {"forget"}, "about": {"sam"}}); w.Code != 403 {
		t.Fatalf("rae forgetting sam: %d", w.Code)
	}
	if w := memoryDo(srv, "POST", "/memory/act", rae, url.Values{"op": {"forget"}}); w.Code != 303 {
		t.Fatalf("forget me: %d", w.Code)
	}
	if left, _ := st.List(memory.Filter{About: "rae"}); len(left) != 0 {
		t.Fatal("rae is still remembered")
	}
	_ = mine
	// An administrator sees everybody's, and removes anybody's.
	if page := memoryDo(srv, "GET", "/memory", editor, nil).Body.String(); !strings.Contains(page, "Sam is on wholesale") {
		t.Fatal("the administrator does not see sam's")
	}
	if w := memoryDo(srv, "POST", "/memory/act", editor, url.Values{"op": {"delete"}, "id": {other.ID}}); w.Code != 303 {
		t.Fatalf("administrator delete: %d", w.Code)
	}
	if _, err := st.Get(other.ID); err == nil {
		t.Fatal("the administrator could not delete it")
	}
}
