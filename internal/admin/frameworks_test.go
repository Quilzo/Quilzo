// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/posture"
)

func wirePosture(srv *Server, undisclosed bool) {
	srv.Posture = func() posture.Report {
		s := posture.State{Now: time.Now(), AI: posture.AIFacts{Checked: true,
			Chatbots: []posture.ChatbotFact{{Name: "help", Public: true,
				Disclosed: !undisclosed, LastEval: time.Now()}}}}
		return posture.Scan(s, nil)
	}
}

func TestTheFrameworksScreenReadsTheSameScan(t *testing.T) {
	srv, token := setup(t)
	wirePosture(srv, true)
	body := get(t, srv, "/security/frameworks", token).Body.String()
	whole(t, body)
	for _, want := range []string{"FedRAMP Moderate", "ISO/IEC 27001", "EU AI Act",
		"GDPR", "NIST AI RMF", "/security/frameworks/eu-ai-act", "not claimed"} {
		if !strings.Contains(body, want) {
			t.Errorf("the frameworks screen is missing %q", want)
		}
	}
	page := get(t, srv, "/security/frameworks/eu-ai-act", token).Body.String()
	whole(t, page)
	if !strings.Contains(page, "Art. 50(1)") || !strings.Contains(page, "failing") ||
		!strings.Contains(page, "help is public and its conversation page") {
		t.Error("the AI Act page does not show the undisclosed chatbot against Article 50(1)")
	}
	// A state nobody gathered is not passing: this scan was given no access
	// policy, so GDPR's security-of-processing requirement cannot pass.
	if gdpr := get(t, srv, "/security/frameworks/gdpr", token).Body.String(); !strings.Contains(gdpr, "not checked") {
		t.Error("requirements whose checks did not run are not marked as such")
	}
	wirePosture(srv, false)
	page = get(t, srv, "/security/frameworks/eu-ai-act", token).Body.String()
	if strings.Contains(page, "help is public and its conversation page") {
		t.Error("a disclosed chatbot is still reported")
	}
	if w := get(t, srv, "/security/frameworks/no-such", token); w.Code != http.StatusNotFound {
		t.Errorf("an unknown framework answered %d", w.Code)
	}
}

func TestFrameworksAreForWhoeverMayGrant(t *testing.T) {
	srv, _ := setup(t)
	wirePosture(srv, true)
	if err := srv.Policy.Grant(auth.Binding{Principal: "pub",
		Role: auth.RolePublisher, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	tok, _, err := srv.Tokens.Issue("p", "pub", auth.RolePublisher, "/", time.Hour, auth.RolePublisher)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/security/frameworks", "/security/frameworks/gdpr"} {
		if w := get(t, srv, path, tok); w.Code == http.StatusOK {
			t.Errorf("%s answered a publisher", path)
		}
	}
}
