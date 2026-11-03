// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// may reports what the profile's "What you may do" row for one action
// says: yes or no.
func may(t *testing.T, body string, action auth.Action) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<code>` + regexp.QuoteMeta(string(action)) +
		`</code></th>\s*<td><span class="tag tag-(ok|bad)">`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no row for %s", action)
	}
	return map[string]string{"ok": "yes", "bad": "no"}[m[1]]
}

// An analyst is an administrator of /@security and nothing else; their
// session carries admin as its cap. The profile said "holding the role
// admin", the menu "Signed in as admin", and every row of what they may do
// was no, because each was asked about "/" only. A contributor, author on
// /blog, was told they may do nothing too.
func TestTheProfileSaysWhatAPersonHoldsAndWhere(t *testing.T) {
	srv, _ := setup(t)
	if err := srv.Policy.Grant(auth.Binding{Principal: "analyst", Role: auth.RoleAdmin,
		Resource: auth.AreaSecurity}); err != nil {
		t.Fatal(err)
	}
	if err := srv.Policy.Grant(auth.Binding{Principal: "contributor", Role: auth.RoleAuthor,
		Resource: "/blog"}); err != nil {
		t.Fatal(err)
	}
	session := func(who string) string {
		secret, _, err := srv.Tokens.IssueSession("passkey:"+who, who, srv.roleFor(who), "/", time.Hour,
			auth.RoleAdmin, auth.MethodPasskey)
		if err != nil {
			t.Fatal(err)
		}
		return secret
	}

	body := get(t, srv, "/profile", session("analyst")).Body.String()
	if !strings.Contains(body, "admin on /@security") {
		t.Errorf("the analyst is not told they administer /@security:\n%s", firstLines(body, 200))
	}
	if strings.Contains(body, "Signed in as admin") {
		t.Error("the menu says the analyst is signed in as admin")
	}
	if got := may(t, body, auth.ActGrant); got != "yes" {
		t.Errorf("an administrator of /@security may grant there; the profile says %s", got)
	}
	if got := may(t, body, auth.ActPublish); got != "yes" {
		t.Errorf("an administrator of /@security may publish there; the profile says %s", got)
	}

	body = get(t, srv, "/profile", session("contributor")).Body.String()
	if !strings.Contains(body, "author on /blog") {
		t.Error("the contributor is not told they are an author of /blog")
	}
	if got := may(t, body, auth.ActEditDraft); got != "yes" {
		t.Errorf("an author of /blog may edit drafts there; the profile says %s", got)
	}
	if got := may(t, body, auth.ActPublish); got != "no" {
		t.Errorf("an author of /blog may not publish; the profile says %s", got)
	}

	// A credential narrower than what the person holds is what it is: an
	// administrator's reader session may not grant, wherever they hold it.
	capped, _, err := srv.Tokens.IssueSession("capped", "editor", auth.RoleReader, "/", time.Hour,
		auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	body = get(t, srv, "/profile", capped).Body.String()
	if got := may(t, body, auth.ActGrant); got != "no" {
		t.Errorf("a reader session may not grant; the profile says %s", got)
	}
	if !strings.Contains(body, "reader on /") {
		t.Error("a reader session is shown holding more than reader")
	}
}
