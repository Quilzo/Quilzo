// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

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
		Decide: func(id string, approve bool, by string) error {
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
