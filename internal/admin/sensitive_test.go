// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
)

func sensitiveSet(t *testing.T) *form.Set {
	t.Helper()
	set := &form.Set{}
	if err := set.Add(form.Form{
		Name: "wholesale", Label: "Wholesale", Notice: "we reply then delete",
		RetentionDays: 30,
		Fields: []form.Field{
			{Name: "company", Label: "Company", Kind: form.Line},
			{Name: "email", Label: "Email", Kind: form.Email, Sensitive: true},
		},
	}); err != nil {
		t.Fatal(err)
	}
	return set
}

// The erasure search does not print the fields the form marked held.
//
// The listing above it honours Sensitive; this table did not, which made the
// search the way around the setting. An editor typing "@" into the erasure box
// got every sensitive value of every matching submission across every form, on
// one screen — with none of the authority erasing them needs, and Search
// matching any substring, so one character is enough.
func TestTheErasureSearchWithholdsSensitiveFields(t *testing.T) {
	set := sensitiveSet(t)
	rows := redactFound(set, []form.Submission{{
		Form: "wholesale", ID: "0123456789abcdef0123456789abcdef",
		At: time.Now().Unix(),
		Values: map[string]string{
			"company": "Acme", "email": "ada@example.com",
		},
	}})

	if len(rows) != 1 {
		t.Fatalf("got %d rows", len(rows))
	}
	shown := strings.Join(rows[0].Shown, " ")
	if strings.Contains(shown, "ada@example.com") {
		t.Errorf("the search prints a value the form marked held: %q", shown)
	}
	if !strings.Contains(shown, "Acme") {
		t.Errorf("the search withheld a field nobody marked sensitive: %q", shown)
	}
	if rows[0].Withheld != 1 {
		t.Errorf("the row does not say anything was withheld, so it looks "+
			"emptier than the submission is: %d", rows[0].Withheld)
	}
}

// And the export redacts them unless somebody asks.
//
// internal/form says what Sensitive means: "not shown in listings and redacted
// in exports unless somebody asks for it explicitly". The listing honoured
// that; the export wrote every value, so a CSV was the way to get the fields
// the operator had marked held-not-shown with no more authority than reading
// the screen that hides them.
func TestTheExportRedactsSensitiveFieldsUnlessAsked(t *testing.T) {
	srv, token := setup(t)
	srv.Forms = wiredForms(t, sensitiveSet(t))

	body := postForm(t, srv, "/forms/export", token, "form=wholesale").Body.String()
	if strings.Contains(body, "ada@example.com") {
		t.Errorf("the export carries a field marked sensitive without being "+
			"asked:\n%s", body)
	}
	if !strings.Contains(body, "Acme") {
		t.Errorf("the export dropped a field nobody marked sensitive:\n%s", body)
	}

	asked := postForm(t, srv, "/forms/export", token,
		"form=wholesale&sensitive=1").Body.String()
	if !strings.Contains(asked, "ada@example.com") {
		t.Errorf("asking for the held fields did not produce them:\n%s", asked)
	}
}

// wiredForms is a form set with one submission in it.
func wiredForms(t *testing.T, set *form.Set) *Forms {
	t.Helper()
	store, err := form.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(form.Submission{
		Form: "wholesale", ID: "0123456789abcdef0123456789abcdef",
		At: time.Now().Unix(),
		Values: map[string]string{
			"company": "Acme", "email": "ada@example.com",
		},
	}); err != nil {
		t.Fatal(err)
	}
	return &Forms{
		Load:  func() (*form.Set, error) { return set, nil },
		Save:  func(*form.Set) error { return nil },
		Store: store,
	}
}

// Deleting a page says which pages reference it.
//
// The menus were checked here from the start and the references were not,
// although the reason is the same sentence and schema.Unresolved has been
// refusing publishes over it all along. Deleting a page that two others name
// left the store publishable-until-you-try: the refusal arrived at the gate,
// naming pages somebody had changed for unrelated reasons, and the page that
// caused it was already gone.
func TestDeletingAReferencedPageSaysWhoNamesIt(t *testing.T) {
	srv, token := setup(t)

	reg := schema.NewRegistry()
	if err := reg.Add(schema.Type{
		Name: "article",
		Fields: []schema.Field{
			{Name: "title", Kind: schema.Text, Required: true},
			{Name: "about", Kind: schema.Reference},
		},
	}); err != nil {
		t.Fatal(err)
	}
	types := &schema.Store{Registry: reg,
		Bound: map[string]string{"index": "article"}}
	srv.Types = &Types{
		Load: func() (*schema.Store, error) { return types, nil },
		Save: func(*schema.Store) error { return nil },
	}

	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	pages["index"] = map[string]any{"title": "Home", "about": "about"}
	if _, err := site.SaveDraft(srv.Store, pages, "point at about",
		"test"); err != nil {
		t.Fatal(err)
	}

	w := postForm(t, srv, "/page/delete", token, "name=about")
	// The refusal travels back in the redirect, which is where every other
	// message from this screen goes.
	said, err := url.QueryUnescape(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(said, "index") {
		t.Errorf("deleting a page that another references did not name it: %q",
			said)
	}
	if !strings.Contains(said, "about") {
		t.Errorf("the refusal does not say which page was being deleted: %q",
			said)
	}

	// And the page is still there, because the refusal is a refusal.
	pages, perr := site.PagesAt(srv.Store, site.RefDraft)
	if perr != nil {
		t.Fatal(perr)
	}
	if _, there := pages["about"]; !there {
		t.Error("the page was deleted anyway")
	}
}
