// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
)

// A grant, a deny and a revocation from the People screen are recorded
// under the names the command line and the access review write for the same
// acts: auth.granted, auth.denied and auth.revoke.
//
// The screen wrote access.grant for a grant and for a deny alike, and
// access.revoke, so a SIEM rule on auth.* and the log screen's filter for
// auth.revoke missed every change of access made in the browser, and the
// export filed them as application activity rather than identity.
func TestAccessChangedInTheBrowserIsRecordedUnderTheCommandLinesNames(t *testing.T) {
	srv, token := setup(t)
	var got []string
	srv.Audit = func(action, _ string, _ map[string]string) { got = append(got, action) }

	for _, step := range []struct {
		path string
		form url.Values
		want string
	}{
		{"/people/grant", url.Values{"principal": {"kim"}, "role": {"author"}, "resource": {"/"}}, "auth.granted"},
		{"/people/grant", url.Values{"principal": {"kim"}, "role": {"publisher"}, "resource": {"/legal"},
			"deny": {"on"}}, "auth.denied"},
		{"/people/revoke", url.Values{"principal": {"kim"}, "role": {"author"}, "resource": {"/"}}, "auth.revoke"},
	} {
		got = nil
		w := postForm(t, srv, step.path, token, step.form.Encode())
		if w.Code >= 400 {
			t.Fatalf("%s answered %d", step.path, w.Code)
		}
		if !slices.Contains(got, step.want) {
			t.Errorf("%s %v recorded %v, not %s", step.path, step.form, got, step.want)
		}
	}
}

// The log screen's filter finds an act under its old name and its new one,
// and lists it once, so a bookmark to ?action=access.grant keeps finding
// grants and the grants made before the rename are not lost to the filter
// for auth.granted.
func TestTheLogFilterFindsAnActUnderItsOldAndNewNames(t *testing.T) {
	dir := t.TempDir()
	l, err := audit.New(audit.Options{Path: dir + "/a.jsonl", Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []audit.Record{
		{Action: "access.grant", Resource: "/old-grant", Outcome: audit.Success,
			Principal: "dana", Kind: audit.KindHuman, Verified: true},
		{Action: "auth.granted", Resource: "/new-grant", Outcome: audit.Success,
			Principal: "dana", Kind: audit.KindHuman, Verified: true},
		{Action: "publish", Resource: "/published", Outcome: audit.Success,
			Principal: "dana", Kind: audit.KindHuman, Verified: true},
	} {
		if _, err := l.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	events, err := audit.Read(dir + "/a.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	s, tok := logServer(t, events, true)
	for _, asked := range []string{"access.grant", "auth.granted"} {
		body, code := getLogs(t, s, tok, "?action="+asked)
		if code != http.StatusOK {
			t.Fatalf("?action=%s answered %d", asked, code)
		}
		for _, want := range []string{"/old-grant", "/new-grant"} {
			if !strings.Contains(body, want) {
				t.Errorf("?action=%s does not show the grant at %s", asked, want)
			}
		}
		if strings.Contains(body, "/published") {
			t.Errorf("?action=%s shows a publication", asked)
		}
		if n := strings.Count(body, `<option value="access.grant"`); n != 0 {
			t.Errorf("the filter offers the old name beside the new one")
		}
	}
}
