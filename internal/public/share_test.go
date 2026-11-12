// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/analytics"
	"github.com/quilzo/quilzo/internal/form"
)

// A share target whose form cannot be satisfied is refused at startup.
//
// The failure this catches is silent and late: a share carries at most a
// title, a text and a url, so a form with a required field none of those map
// onto refuses every share — weeks after the manifest was published, from
// somebody's phone, with no error anybody sees.
func TestAShareTargetThatCouldNeverWorkIsRefused(t *testing.T) {
	good := &ShareTarget{Form: "enquiry", TitleField: "subject", TextField: "body"}
	if err := good.Validate([]string{"subject"}); err != nil {
		t.Fatalf("a workable target was refused: %v", err)
	}

	// A required field no shared value reaches.
	err := good.Validate([]string{"subject", "email"})
	if err == nil {
		t.Fatal("a form requiring a field no share carries was accepted, so " +
			"every share would be refused at the phone")
	}
	if !strings.Contains(err.Error(), "email") {
		t.Errorf("the refusal does not name the unreachable field: %v", err)
	}

	// Mapping nothing means a share arrives empty.
	if err := (&ShareTarget{Form: "enquiry"}).Validate(nil); err == nil {
		t.Error("a target mapping none of title, text or url was accepted")
	}
	// And no form at all.
	if err := (&ShareTarget{}).Validate(nil); err == nil {
		t.Error("a target naming no form was accepted")
	}
}

// The manifest fragment is what makes the OS offer this in the share sheet.
//
// POST with multipart/form-data specifically: a GET share target puts whatever
// somebody shared into a query string, and therefore into every access log
// between them and here.
func TestTheManifestDeclaresAServerSideShare(t *testing.T) {
	st := &Site{Share: &ShareTarget{
		Form: "enquiry", TitleField: "subject", TextField: "body",
		URLField: "link"}}
	m := st.shareManifest()
	if m == nil {
		t.Fatal("no share_target produced for a configured target")
	}
	if m["method"] != "POST" {
		t.Errorf("method is %v; a GET share puts the shared text in a query "+
			"string and therefore in every access log on the way", m["method"])
	}
	if m["enctype"] != "multipart/form-data" {
		t.Errorf("enctype is %v, which is what selects the form POST a plain "+
			"server handler can read", m["enctype"])
	}
	if m["action"] != "/share" {
		t.Errorf("action is %v", m["action"])
	}
	params := m["params"].(map[string]any)
	for shared, want := range map[string]string{
		"title": "subject", "text": "body", "url": "link"} {
		if params[shared] != want {
			t.Errorf("%s maps to %v, want %q", shared, params[shared], want)
		}
	}

	// Nothing configured, nothing declared. A share_target pointing at a form
	// that does not exist is an entry in the OS share sheet that fails when
	// somebody picks it.
	if (&Site{}).shareManifest() != nil {
		t.Error("a site with no share target declared one anyway")
	}
	if (&Site{Share: &ShareTarget{Form: "enquiry"}}).shareManifest() != nil {
		t.Error("a target mapping no fields was declared in the manifest")
	}
}

// A shared value that is enormous is not stored, whole or cut, and an
// ordinary one is stored as it was shared.
//
// Each value is cut to maxShareField before the form sees it, which bounds
// what the form is given to check. Every value cut is still longer than any
// answer a form takes, so the form refuses it rather than keep a part.
func TestSharedValuesAreBounded(t *testing.T) {
	st, fs := withForm(t)
	st.Share = &ShareTarget{Form: "contact", TitleField: "name"}
	send := func(title string) int {
		t.Helper()
		v := url.Values{"title": {title}}
		r := httptest.NewRequest(http.MethodPost, "/share", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("User-Agent", browser)
		w := httptest.NewRecorder()
		st.Handler().ServeHTTP(w, r)
		return w.Code
	}
	if code := send(strings.Repeat("中", maxShareField)); code != http.StatusBadRequest {
		t.Errorf("an enormous share answered %d", code)
	}
	if subs, _ := fs.List("contact"); len(subs) != 0 {
		t.Fatalf("an enormous share was stored: %+v", subs)
	}
	if code := send("Ana"); code != http.StatusSeeOther {
		t.Fatalf("an ordinary share answered %d", code)
	}
	if subs, _ := fs.List("contact"); len(subs) != 1 || subs[0].Values["name"] != "Ana" {
		t.Errorf("an ordinary share was stored as %+v", subs)
	}
}

// A share is told about as a submission through the form's own page is.
//
// /share wrote through form.AcceptShare and Store.Put and nothing else, while
// /form/NAME also wrote the form.submit audit record, alerted staff through
// Notify and counted the conversion. So a submission from the share sheet,
// the less defended of the two routes, left no record of the source that
// wrote it and woke nobody: an abuse investigation saw nothing, and a real
// enquiry sent that way waited until somebody opened the admin.
func TestAShareIsAuditedAndNotifiedAsASubmissionIs(t *testing.T) {
	st, fs := withForm(t)
	type said struct {
		name, source string
		ok           bool
	}
	var audited []said
	var notified []string
	st.Forms.Audit = func(name, source string, ok bool) {
		audited = append(audited, said{name, source, ok})
	}
	st.Forms.Notify = func(name string) { notified = append(notified, name) }
	counter, err := analytics.Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	st.Analytics = counter
	st.Share = &ShareTarget{Form: "contact", TitleField: "name", TextField: "email"}

	send := func(path, from string, v url.Values) int {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("User-Agent", browser)
		r.RemoteAddr = from + ":1"
		w := httptest.NewRecorder()
		st.Handler().ServeHTTP(w, r)
		return w.Code
	}

	// The form's own route, for what the share is to match.
	if code := send("/form/contact", "198.51.100.4", url.Values{"name": {"Ana"},
		form.StampField: {fmt.Sprint(time.Now().Add(-time.Minute).Unix())}}); code != http.StatusOK {
		t.Fatalf("control: the form answered %d", code)
	}
	if len(audited) != 1 || len(notified) != 1 {
		t.Fatalf("control: the form audited %v and notified %v", audited, notified)
	}
	audited, notified = nil, nil

	if code := send("/share", "203.0.113.7", url.Values{"title": {"Bo"}}); code != http.StatusSeeOther {
		t.Fatalf("the share answered %d", code)
	}
	if subs, _ := fs.List("contact"); len(subs) != 2 {
		t.Fatalf("the share was not stored: %d submissions", len(subs))
	}
	if len(audited) != 1 || audited[0] != (said{"contact", "203.0.113.7", true}) {
		t.Errorf("a stored share was audited as %v; it should be one accepted "+
			"record naming the form and the source", audited)
	}
	if len(notified) != 1 || notified[0] != "contact" {
		t.Errorf("a stored share notified %v; staff are told about a share "+
			"as about any submission", notified)
	}
	if n := counter.Today().Goals["form:contact"]; n != 2 {
		t.Errorf("the form's goal counted %d visitors after one sent the form "+
			"and another shared to it; a share reaches the goal too", n)
	}

	// A refused share is audited as refused and tells nobody, as a refused
	// submission does.
	audited, notified = nil, nil
	if code := send("/share", "203.0.113.7", url.Values{"text": {"not an address"}}); code == http.StatusSeeOther {
		t.Fatalf("a share failing the form's kinds was stored")
	}
	if len(audited) != 1 || audited[0].ok {
		t.Errorf("a refused share was audited as %v", audited)
	}
	if len(notified) != 0 {
		t.Errorf("a refused share notified %v", notified)
	}
}
