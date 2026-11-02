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
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "e=") || len(finished) != 2 {
		t.Fatalf("%s %v", loc, finished)
	}
	decideForm(t, srv, "/connections/change", token, url.Values{"op": {"revoke"}, "provider": {"acme"}})
	if len(revoked) != 1 || revoked[0] != "acme/editor" {
		t.Fatalf("%v", revoked)
	}
	if w := get(t, srv, "/connections", ""); w.Code == http.StatusOK {
		t.Error("the screen answered somebody not signed in")
	}
}
