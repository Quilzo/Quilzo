// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// Find offers the screens the menu offers. It asked its own copy of the
// menu's question, about the whole site, so a screen shown for an area was
// in somebody's menu and missing from what they found: a reader who also
// administers the security area had Shield beside them and no Shield when
// they searched for it.
func TestFindOffersTheScreensTheMenuOffers(t *testing.T) {
	srv, _ := setup(t)
	for _, b := range []auth.Binding{
		{Principal: "sam", Role: auth.RoleReader, Resource: "/"},
		{Principal: "sam", Role: auth.RoleAdmin, Resource: auth.AreaSecurity},
	} {
		if err := srv.Policy.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	tok, _, err := srv.Tokens.IssueSession("passkey:sam", "sam", srv.roleFor("sam"), "/", time.Hour,
		auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	body := get(t, srv, "/find?q=shield", tok).Body.String()
	whole(t, body)
	if !strings.Contains(menuOf(t, body), `href="/security/shield"`) {
		t.Fatal("the menu does not offer Shield, so this proves nothing")
	}
	results := body[strings.Index(body, "<h1>Find</h1>"):]
	if !strings.Contains(results, `<a href="/security/shield">Shield</a>`) {
		t.Errorf("Find does not find Shield, which the menu beside it offers:\n%s", firstLines(results, 30))
	}
}

// Searching from the box every screen shows is never a refusal: somebody
// whose work is one area finds the screens their menu offers and nothing of
// the site's, and Find names the way to what people sent only to somebody
// it is open to.
//
// The box is on every screen, and Find asked whether the person could read
// the whole site, so the reference stack's approver, on the Approvals screen
// their menu offers, typed into it and was refused, as was everybody whose
// grant is on one area. And Nothing matched sent a reader to Forms, which
// refuses readers.
func TestSearchingFromTheBoxIsNotARefusal(t *testing.T) {
	srv, editor := setup(t)
	for _, b := range []auth.Binding{
		{Principal: "aria", Permission: auth.ActApprove, Resource: "/"},
		{Principal: "rita", Role: auth.RoleReader, Resource: "/"},
	} {
		if err := srv.Policy.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	session := func(name string) string {
		tok, _, err := srv.Tokens.IssueSession("passkey:"+name, name, srv.roleFor(name), "/", time.Hour,
			auth.RoleAdmin, auth.MethodPasskey)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	aria, rita := session("aria"), session("rita")
	found := func(tok, q string) string {
		t.Helper()
		w := get(t, srv, "/find?q="+q, tok)
		if w.Code != http.StatusOK {
			t.Fatalf("searching for %q from the box was answered %d", q, w.Code)
		}
		body := w.Body.String()
		whole(t, body)
		return body[strings.Index(body, "<h1>Find</h1>"):]
	}

	if !strings.Contains(get(t, srv, "/approvals", aria).Body.String(), `action="/find"`) {
		t.Fatal("the approver's screen has no search box, so this proves nothing")
	}
	if got := found(aria, "approvals"); !strings.Contains(got, `<a href="/approvals">Approvals</a>`) {
		t.Errorf("the approver does not find Approvals, which their menu offers:\n%s", firstLines(got, 30))
	}
	// The pages are the site's, which the approver may not read; a reader
	// finds the same words.
	if got := found(aria, "welcome"); strings.Contains(got, `href="/page/`) {
		t.Errorf("the approver finds pages they may not read:\n%s", firstLines(got, 30))
	}
	if got := found(rita, "welcome"); !strings.Contains(got, `href="/page/index"`) {
		t.Errorf("a reader no longer finds the page the words are on:\n%s", firstLines(got, 30))
	}
	for who, tok := range map[string]string{"the approver": aria, "a reader": rita, "an administrator": editor} {
		linked := strings.Contains(found(tok, "zzqxv"), `href="/forms`)
		// Refused, not unwired: this store has no forms wired in, which
		// Forms says to an administrator instead of refusing them.
		opens := get(t, srv, "/forms", tok).Code != http.StatusForbidden
		if linked != opens {
			t.Errorf("when nothing matched, %s is linked to Forms: %v, and may open it: %v", who, linked, opens)
		}
	}
}
