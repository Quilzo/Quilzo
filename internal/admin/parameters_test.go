// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/odp"
)

// On the screen as on the command line: one proposes, another approves,
// the setting rises to meet it, and a reader can look but not change.
func TestThePolicyScreenTakesTwo(t *testing.T) {
	srv, editor := setup(t)
	if err := srv.Policy.Grant(auth.Binding{Principal: "second", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	second, _, err := srv.Tokens.Issue("second", "second", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.New()
	saved := cfg
	srv.Settings = &Settings{Load: func() (*config.Config, error) {
		c := saved
		return c, nil
	}, Save: func(c *config.Config) error { saved = c; return nil }}
	path := filepath.Join(t.TempDir(), "parameters.json")
	srv.Parameters = &Parameters{Path: path, OnlyAdmin: func(string) bool { return false }}

	form := url.Values{"do": {"propose"}, "param": {"ac-12_odp"}, "value": {"4 hours"}, "reason": {"audit finding 12"}}
	if w := postForm(t, srv, "/security/parameters/act", editor, form.Encode()); !strings.Contains(w.Header().Get("Location"), "m=") {
		t.Fatalf("propose: %d %s", w.Code, w.Header().Get("Location"))
	}
	pol, _ := odp.Load(path)
	if len(pol.Proposals) != 1 {
		t.Fatalf("%+v", pol)
	}
	id := pol.Proposals[0].ID
	if body := get(t, srv, "/security/parameters", editor).Body.String(); !strings.Contains(body, "Withdraw") || strings.Contains(body, `value="approve"`) {
		t.Fatal("the proposer is offered approval of their own change")
	}
	approve := url.Values{"do": {"approve"}, "id": {id}}.Encode()
	if w := postForm(t, srv, "/security/parameters/act", editor, approve); !strings.Contains(w.Header().Get("Location"), "e=") {
		t.Fatalf("the proposer approved: %s", w.Header().Get("Location"))
	}
	if w := postForm(t, srv, "/security/parameters/act", second, approve); !strings.Contains(w.Header().Get("Location"), "raised") {
		t.Fatalf("approve: %s", w.Header().Get("Location"))
	}
	if saved.Raw("session.max") != "4h" {
		t.Fatalf("session.max is %s", saved.Raw("session.max"))
	}
	body := get(t, srv, "/security/parameters", second).Body.String()
	if !strings.Contains(body, "Declared, met") || !strings.Contains(body, "approved by second") {
		t.Fatal("the screen does not show the declaration as met")
	}
	if w := get(t, srv, "/security/parameters/export", second); !strings.Contains(w.Body.String(), `"param-id": "ac-12_odp"`) {
		t.Fatalf("export: %d", w.Code)
	}
}
