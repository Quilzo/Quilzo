// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A call through the gateway that a person approves is shown with its
// arguments and decided here.
func TestAHeldGatewayCallIsDecidedOnTheScreen(t *testing.T) {
	srv, token := setup(t)
	var decided []string
	srv.Integrations = &Integrations{
		Held: func() ([]GatewayHeld, error) {
			return []GatewayHeld{{ID: "gq_0123456789ab", Integration: "tracker", Tool: "create_issue", For: "rae",
				App: "https://app.example.com/meta", Args: `{"title":"Printer on fire"}`, Asked: time.Now()}}, nil
		},
		Decide: func(id string, approve bool, act Actor) error {
			by := act.Name
			decided = append(decided, fmt.Sprintf("%s %v %s", id, approve, by))
			return nil
		},
	}
	body := get(t, srv, "/integrations", token).Body.String()
	for _, want := range []string{"Calls waiting for a person", "gq_0123456789ab", "Printer on fire", "through https://app.example.com/meta"} {
		if !strings.Contains(body, want) {
			t.Errorf("the screen lacks %q", want)
		}
	}
	w := postForm(t, srv, "/integrations/held", token, url.Values{"id": {"gq_0123456789ab"}, "decision": {"approve"}}.Encode())
	if w.Code != http.StatusSeeOther || len(decided) != 1 || decided[0] != "gq_0123456789ab true editor" {
		t.Fatalf("%d %v", w.Code, decided)
	}
	postForm(t, srv, "/integrations/held", token, url.Values{"id": {"gq_0123456789ab"}, "decision": {"decline"}}.Encode())
	if len(decided) != 2 || decided[1] != "gq_0123456789ab false editor" {
		t.Fatalf("%v", decided)
	}
}

// A call held for what it says is shown with what was found, beside its
// arguments, so the person deciding reads why it waits.
func TestAGatewayCallHeldForItsWordsShowsWhy(t *testing.T) {
	srv, token := setup(t)
	srv.Integrations = &Integrations{
		Held: func() ([]GatewayHeld, error) {
			return []GatewayHeld{{ID: "gq_0123456789ab", Integration: "social", Tool: "post_update", For: "rae",
				Args: `{"text":"Every order guaranteed"}`, Asked: time.Now(),
				Why: `the brand rules hold it: text: "guaranteed", a guarantee is a promise somebody has to honour`}}, nil
		},
		Decide: func(string, bool, Actor) error { return nil },
	}
	body := get(t, srv, "/integrations", token).Body.String()
	if !strings.Contains(body, "the brand rules hold it: text: &#34;guaranteed&#34;") {
		t.Errorf("the screen does not say what the brand rules found:\n%s", body)
	}
}
