// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collab"
)

// readerOf is setup with a reader, rita, besides the administrator, and the
// claims on pages kept where the test can see them.
func readerOf(t *testing.T) (srv *Server, admin, reader string, locks *collab.Locks) {
	t.Helper()
	srv, admin = setup(t)
	if err := srv.Policy.Grant(auth.Binding{Principal: "rita", Role: auth.RoleReader, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	reader, _, err := srv.Tokens.IssueSession("rita", "rita", auth.RoleReader, "/", time.Hour,
		auth.RoleReader, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	locks = &collab.Locks{}
	srv.Locks = func() (*collab.Locks, error) { return locks, nil }
	srv.SaveLocks = func(l *collab.Locks) error { locks = l; return nil }
	return srv, admin, reader, locks
}

// Reading a page is not starting to edit it.
//
// Every GET of /page/NAME claimed the page for whoever asked, reader or not,
// so an editor opening it was warned that a reader "opened this page for
// editing recently" — a person who could not edit it, holding a claim whose
// whole purpose is to make two editors talk before one loses work. Any
// address claimed one, a page or not, and the reader was shown "Edit" over a
// screen that said they could not.
func TestAReaderOpeningAPageClaimsNothing(t *testing.T) {
	srv, admin, reader, locks := readerOf(t)

	w := get(t, srv, "/page/about", reader)
	if w.Code != http.StatusOK {
		t.Fatalf("a reader could not read about: %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "You can view this page but not edit it.") {
		t.Fatal("the reader was not told they cannot edit")
	}
	if strings.Contains(body, "<h1>Edit") || strings.Contains(body, "<title>Edit") {
		t.Error("a reader is shown Edit over a page they cannot edit")
	}
	if !strings.Contains(body, "<h1>View “About”</h1>") {
		t.Error("the reader's heading does not say they are viewing the page")
	}
	if active := locks.Active(time.Now()); len(active) != 0 {
		t.Errorf("reading a page claimed it: %+v", active)
	}
	if strings.Contains(get(t, srv, "/page/about", admin).Body.String(), "opened this page for editing") {
		t.Error("an editor is told a reader opened the page for editing")
	}

	// An address with no page is not a page to read.
	if w := get(t, srv, "/page/ghost", reader); w.Code != http.StatusNotFound {
		t.Errorf("a reader opening a page that does not exist got %d", w.Code)
	}
	if _, held := locks.Holder("ghost", time.Now()); held {
		t.Error("reading an address with no page claimed it")
	}

	// Somebody who may edit still claims the page, so the next editor is told.
	if l, held := locks.Holder("about", time.Now()); !held || l.Holder != "editor" {
		t.Errorf("an editor opening the page did not claim it: %+v %v", l, held)
	}
}
