// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// Vouching for somebody takes at least their standing.
func TestAnAnalystCannotLetAnAdministratorPastAStepUp(t *testing.T) {
	srv, token := asJob(t, "analyst")
	if err := srv.Policy.Grant(auth.Binding{Principal: "boss", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	_, tok, err := srv.Tokens.IssueSession("s", "boss", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Tokens.RequireStepUp(tok.ID, "Sydney"); err != nil {
		t.Fatal(err)
	}
	postForm(t, srv, "/security/signins/act", token, "do=letin&session="+tok.ID)
	for _, x := range srv.Tokens.Snapshot() {
		if x.ID == tok.ID && x.StepUp == "" {
			t.Error("an analyst let a site administrator in")
		}
	}
}
