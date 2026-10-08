// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/url"
	"strings"
	"testing"
)

// unsigned removes the message signature from a redirect, for tests that
// assert where something redirects rather than what signed it.
func unsigned(loc string) string {
	u, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	q := u.Query()
	if _, ok := q[flashSig]; !ok {
		return loc
	}
	q.Del(flashSig)
	u.RawQuery = q.Encode()
	return u.String()
}

// TestALinkCannotPutWordsOnAScreen.
//
// Every screen that reports the outcome of a form reads ?m= and ?e= and shows
// them as its own notice. Anybody could send an administrator a link that
// made a trusted screen say anything. A message now shows only when this
// server signed it.
func TestALinkCannotPutWordsOnAScreen(t *testing.T) {
	srv, token := setup(t)
	forged := "Your session expired. Sign in again at quilzo-login.example"
	for _, path := range []string{
		"/?e=" + url.QueryEscape(forged),
		"/?m=" + url.QueryEscape(forged),
		"/?m=" + url.QueryEscape(forged) + "&fs=AAAAAAAAAAAAAAAAAAAAAAAA",
		"/media?e=" + url.QueryEscape(forged),
		"/publishing?m=" + url.QueryEscape(forged),
	} {
		if body := get(t, srv, path, token).Body.String(); strings.Contains(body, "quilzo-login.example") {
			t.Errorf("%s put its words on the screen", path)
		}
	}
	// A signature for one message does not carry another.
	good := signFlash(srv.flashKey, "/?m=Published")
	swapped := strings.Replace(good, "m=Published", "m="+url.QueryEscape(forged), 1)
	if body := get(t, srv, swapped, token).Body.String(); strings.Contains(body, "quilzo-login.example") {
		t.Error("a signature was reused for different words")
	}
}

// TestTheServersOwnMessagesStillShow, after a real round trip.
func TestTheServersOwnMessagesStillShow(t *testing.T) {
	srv, token := setup(t)
	signed := signFlash(srv.flashKey, "/?m="+url.QueryEscape("Saved the draft of about"))
	if body := get(t, srv, signed, token).Body.String(); !strings.Contains(body, "Saved the draft of about") {
		t.Fatal("a signed message did not show")
	}
	// And the middleware signs a redirect as it goes out.
	w := signInPost(srv, "qz_wrong")
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, flashSig+"=") {
		t.Fatalf("a redirect with a message went out unsigned: %q", loc)
	}
}

// TestOnlyLocalRedirectsAreSigned.
func TestOnlyLocalRedirectsAreSigned(t *testing.T) {
	key := newFlashKey()
	for _, loc := range []string{
		"https://idp.example/authorize?e=x",
		"//idp.example/?m=x",
	} {
		if got := signFlash(key, loc); got != loc {
			t.Errorf("%s was changed to %s", loc, got)
		}
	}
	if got := signFlash(key, "/media"); got != "/media" {
		t.Errorf("a redirect with no message was changed: %s", got)
	}
}
