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
		Edit:    func(id, text, by string) error { _, err := st.Edit(id, text, by, time.Now()); return err },
		Forget: func(about, by string) (int, error) {
			gone, err := st.Forget(about)
			return len(gone), err
		},
		Receipt: func(about string) ([]byte, error) {
			if about == "rae" {
				return []byte(`{"format":"quilzo-memory-receipt/1","person":"rae"}`), nil
			}
			return nil, nil
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

// Rae rewrites what is remembered about her; nobody rewrites what is
// remembered about somebody else, an administrator included, and an
// administrator rewrites an agent's own procedures.
func TestAPersonRewritesWhatIsRememberedAboutThemOnly(t *testing.T) {
	srv, editor, rae, st := memoryRig(t)
	now := time.Now()
	mine, _ := st.Remember(memory.Entry{Agent: "help", About: "rae", Kind: memory.Semantic, Text: "Rae prefers French",
		Run: "r", By: "rae", Tier: memory.TierUnreviewed}, time.Hour, now)
	other, _ := st.Remember(memory.Entry{Agent: "help", About: "sam", Kind: memory.Semantic, Text: "Sam is on wholesale", Run: "r", By: "sam"}, time.Hour, now)
	proc, _ := st.Remember(memory.Entry{Agent: "help", Kind: memory.Procedural, Text: "Refunds over 100 go to finance", Run: "r", By: "sam"}, time.Hour, now)

	page := memoryDo(srv, "GET", "/memory", rae, nil).Body.String()
	if !strings.Contains(page, "after reading what nobody here reviewed") || !strings.Contains(page, "/memory?edit="+mine.ID) {
		t.Fatalf("rae's page shows no tier or no edit: %s", page)
	}
	if form := memoryDo(srv, "GET", "/memory?edit="+mine.ID, rae, nil).Body.String(); !strings.Contains(form, ">Rae prefers French</textarea>") {
		t.Fatal("the edit form is not shown")
	}
	if form := memoryDo(srv, "GET", "/memory?edit="+other.ID, rae, nil).Body.String(); strings.Contains(form, "wholesale</textarea>") {
		t.Fatal("rae was offered sam's memory to rewrite")
	}
	memoryDo(srv, "POST", "/memory/act", rae, url.Values{"op": {"edit"}, "id": {mine.ID}, "text": {"Rae prefers Spanish"}})
	if e, _ := st.Get(mine.ID); e.Text != "Rae prefers Spanish" || e.Tier != memory.TierPerson {
		t.Fatalf("not rewritten: %+v", e)
	}
	for _, who := range []string{rae, editor} {
		memoryDo(srv, "POST", "/memory/act", who, url.Values{"op": {"edit"}, "id": {other.ID}, "text": {"Sam left"}})
	}
	if e, _ := st.Get(other.ID); e.Text != "Sam is on wholesale" {
		t.Fatalf("sam's memory was rewritten: %q", e.Text)
	}
	memoryDo(srv, "POST", "/memory/act", rae, url.Values{"op": {"edit"}, "id": {proc.ID}, "text": {"Refunds go anywhere"}})
	if e, _ := st.Get(proc.ID); e.Text != "Refunds over 100 go to finance" {
		t.Fatal("an author rewrote an agent's procedure")
	}
	memoryDo(srv, "POST", "/memory/act", editor, url.Values{"op": {"edit"}, "id": {proc.ID}, "text": {"Refunds over 200 go to finance"}})
	if e, _ := st.Get(proc.ID); e.Text != "Refunds over 200 go to finance" {
		t.Fatal("an administrator could not rewrite a procedure")
	}
	// The receipt: your own, as a file; somebody else's is an administrator's.
	w := memoryDo(srv, "GET", "/memory/receipt", rae, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") ||
		!strings.Contains(w.Body.String(), "quilzo-memory-receipt/1") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if w := memoryDo(srv, "GET", "/memory/receipt?about=sam", rae, nil); w.Code != http.StatusForbidden {
		t.Fatalf("rae fetched sam's receipt: %d", w.Code)
	}
	if w := memoryDo(srv, "GET", "/memory/receipt?about=sam", editor, nil); w.Code != http.StatusSeeOther ||
		!strings.Contains(w.Header().Get("Location"), "nothing+has+been+forgotten") {
		t.Fatalf("an empty receipt: %d %s", w.Code, w.Header().Get("Location"))
	}
}
