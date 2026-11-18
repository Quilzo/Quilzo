// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// pageText is a page as somebody reads it: its words, without the markup.
func pageText(page string) string {
	return strings.Join(strings.Fields(regexp.MustCompile(`<[^>]*>`).ReplaceAllString(page, " ")), " ")
}

// The sign-in page says where a passkey comes from.
//
// It gave a grant and a token as the way in, and a token is one factor:
// whoever followed it signed in to "Confirm it's you", with no passkey to
// confirm with, and on a new store nobody to give them one. What gives a
// person a passkey is a link: `quilzo auth enrol`, or on a new store
// `quilzo init --admin`.
func TestTheSignInPageSaysWhereAPasskeyComesFrom(t *testing.T) {
	srv, _ := setup(t)
	page := get(t, srv, "/signin", "").Body.String()
	for _, want := range []string{"<code>quilzo auth enrol NAME</code>", "<code>quilzo init --admin NAME</code>"} {
		if !strings.Contains(page, want) {
			t.Errorf("the sign-in page does not name %s", want)
		}
	}
	// The token is still how somebody signs in from here, and the page
	// still says how to make one.
	if !strings.Contains(page, `name="token"`) || !strings.Contains(page, "quilzo token issue") {
		t.Error("the sign-in page no longer takes a token, or no longer says how to make one")
	}
}

// "Confirm it's you" names the command that gives a passkey.
//
// It said an administrator could give one "from People", which is behind the
// same wall: for the store's only administrator, signed in with a token,
// that was nobody. A token that reaches this page is enough to run the
// command that gives the link.
func TestConfirmingItsYouNamesTheCommandThatGivesAPasskey(t *testing.T) {
	srv, _ := fullyWired(t)
	token, _, err := srv.Tokens.Issue("cli", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	srv.MFAFrom = time.Now().Add(-time.Minute)
	session := cookieFrom(signInPost(srv, token))
	if session == "" {
		t.Fatal("signing in with a token set no session")
	}
	page := browse(srv, http.MethodGet, "/signin/verify", &http.Cookie{Name: "quilzo_token", Value: session}, nil).Body.String()
	if !strings.Contains(page, "You have no passkey here yet") || !strings.Contains(page, "<code>quilzo auth enrol editor</code>") {
		t.Errorf("Confirm it's you does not name the command that gives editor a passkey:\n%s", pageText(page))
	}
}
