// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"os"
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

// The sign-in page says what Quilzo is, and what it says of itself is true.
//
// It is the first thing anybody sees of the admin, and its "What this is"
// was the content store alone, from before Quilzo was the agent platform
// it is. Two of its three claims were false as well: "no JavaScript in this
// interface", of an interface that serves /admin.js to every screen and
// signs people in with passkeys from a script, and "an image built from
// scratch", of an image built on distroless. The README is held to the
// image it describes (docs_claims_test.go); this page was not.
func TestTheSignInPageSaysWhatQuilzoIsAndOnlyWhatIsTrue(t *testing.T) {
	srv, token := setup(t)
	text := pageText(get(t, srv, "/signin", "").Body.String())

	if !strings.Contains(text, "The self-hosted AI agent platform") {
		t.Errorf("the sign-in page does not say what Quilzo is: %.400q", text)
	}
	if w := get(t, srv, "/admin.js", token); w.Code == http.StatusOK &&
		regexp.MustCompile(`(?i)no JavaScript`).MatchString(text) {
		t.Error("the sign-in page says there is no JavaScript here, and /admin.js is served")
	}

	df, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	from := regexp.MustCompile(`(?m)^FROM\s+(\S+)`).FindAllStringSubmatch(string(df), -1)
	if len(from) == 0 {
		t.Fatal("no FROM in the Dockerfile; this test cannot check anything")
	}
	if base := from[len(from)-1][1]; !strings.EqualFold(base, "scratch") {
		if regexp.MustCompile(`(?i)from scratch`).MatchString(text) {
			t.Errorf("the sign-in page says the image is built from scratch; it is built on %s", base)
		}
		if strings.Contains(text, "image") && !strings.Contains(text, "distroless") {
			t.Errorf("the sign-in page describes the image without naming what it is built on, %s", base)
		}
	}
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
