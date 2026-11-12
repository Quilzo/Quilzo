// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/connect"
)

// The screen lists the providers and the signed-in person's own
// connections; connecting sends them to the provider; the provider's
// answer is finished for whoever is signed in, and its refusal is said.
func TestConnectedAccountsAreAPersonsOwn(t *testing.T) {
	srv, token := setup(t)
	var started, finished, revoked []string
	srv.Connections = &Connections{
		Providers: func() ([]connect.Provider, error) {
			return []connect.Provider{{Name: "acme", Title: "Acme", Scopes: []string{"calendar"}, Hosts: []string{"api.acme.example"}},
				{Name: "other", Title: "Other", Hosts: []string{"api.other.example"}}}, nil
		},
		Mine: func(person string) ([]ConnectedAccount, error) {
			return []ConnectedAccount{{Provider: "acme", Connected: time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)}}, nil
		},
		Start: func(provider, person string) (string, error) {
			started = append(started, provider+"/"+person)
			return "https://id.acme.example/authorize?state=s", nil
		},
		Finish: func(_ context.Context, state, code, person string) (string, error) {
			finished = append(finished, state+"/"+code+"/"+person)
			if code == "bad" {
				return "", errors.New("this connection was started by somebody else; start your own")
			}
			return "Acme", nil
		},
		Revoke: func(_ context.Context, provider, person string) error {
			revoked = append(revoked, provider+"/"+person)
			return nil
		},
	}
	body := get(t, srv, "/connections", token).Body.String()
	whole(t, body)
	for _, want := range []string{"Acme", "<code>calendar</code>", "api.acme.example", "Disconnect", "Connect"} {
		if !strings.Contains(body, want) {
			t.Errorf("the screen does not show %q", want)
		}
	}
	w := decideForm(t, srv, "/connections/change", token, url.Values{"op": {"connect"}, "provider": {"other"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "https://id.acme.example/authorize?state=s" ||
		len(started) != 1 || started[0] != "other/editor" {
		t.Fatalf("%d %s %v", w.Code, w.Header().Get("Location"), started)
	}
	w = get(t, srv, "/connections/callback?state=s&code=the-code", token)
	if !strings.Contains(w.Header().Get("Location"), "m=") || finished[0] != "s/the-code/editor" {
		t.Fatalf("%s %v", w.Header().Get("Location"), finished)
	}
	w = get(t, srv, "/connections/callback?state=s&code=bad", token)
	if !strings.Contains(w.Header().Get("Location"), "e=") {
		t.Fatalf("a refused connection was reported done: %s", w.Header().Get("Location"))
	}
	w = get(t, srv, "/connections/callback?error=access_denied&error_description=the+person+said+no", token)
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "e=") || !strings.Contains(loc, "access_denied") || len(finished) != 2 {
		t.Fatalf("%s %v", loc, finished)
	}
	// The callback is a GET anybody can link to: what it says the provider
	// answered is an OAuth error code or nothing, never a linker's sentence.
	for _, q := range []string{
		"error=Sign+in+again+at+elsewhere.example",
		"error=access_denied&error_description=Sign+in+again+at+elsewhere.example",
	} {
		loc := get(t, srv, "/connections/callback?"+q, token).Header().Get("Location")
		if !strings.Contains(loc, "e=") || strings.Contains(loc, "elsewhere") {
			t.Errorf("?%s went to %s", q, loc)
		}
	}
	decideForm(t, srv, "/connections/change", token, url.Values{"op": {"revoke"}, "provider": {"acme"}})
	if len(revoked) != 1 || revoked[0] != "acme/editor" {
		t.Fatalf("%v", revoked)
	}
	if w := get(t, srv, "/connections", ""); w.Code == http.StatusOK {
		t.Error("the screen answered somebody not signed in")
	}
}

// Your accounts says when each connection's tokens end, and which have to
// be connected again soon; one kept before its ends were says it does not
// know. Showing only when it was connected, a connection simply stopped
// one day (a LinkedIn refresh token a year old, an Instagram token sixty
// days old), and the first anybody heard was a post that failed.
func TestYourAccountsSaysWhenAConnectionExpires(t *testing.T) {
	srv, token := setup(t)
	now := time.Now().UTC()
	// Counted from now, not fixed dates: a refresh token's fixed end
	// comes within the week one day, and the test would fail that week.
	access, refresh := now.Add(50*24*time.Hour), now.Add(300*24*time.Hour)
	srv.Connections = &Connections{
		Providers: func() ([]connect.Provider, error) {
			return []connect.Provider{{Name: "linkedin", Title: "LinkedIn", Hosts: []string{"api.linkedin.com"}},
				{Name: "instagram", Title: "Instagram", Hosts: []string{"graph.instagram.com"}},
				{Name: "acme", Title: "Acme", Hosts: []string{"api.acme.example"}}}, nil
		},
		Mine: func(person string) ([]ConnectedAccount, error) {
			return []ConnectedAccount{
				{Provider: "linkedin", Connected: now.AddDate(0, -2, 0), Expires: connect.Ends{
					Access: access, Refresh: refresh, Renews: true}},
				{Provider: "instagram", Connected: now.AddDate(0, -2, 0), Expires: connect.Ends{Access: now.Add(3 * 24 * time.Hour)}},
				{Provider: "acme", Connected: now.AddDate(-1, 0, 0)},
			}, nil
		},
	}
	body := get(t, srv, "/connections", token).Body.String()
	whole(t, body)
	for _, want := range []string{access.Format("2 Jan 2006 15:04"), "refresh token until " + refresh.Format("2 Jan 2006"),
		"no refresh token", "not known",
		"Connect it again before " + now.Add(3*24*time.Hour).Format("2 Jan 2006")} {
		if !strings.Contains(body, want) {
			t.Errorf("the screen does not say %q", want)
		}
	}
	if strings.Count(body, "Connect it again before") != 1 {
		t.Error("a connection that does not end within the week is said to")
	}
}
