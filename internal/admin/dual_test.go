// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/dual"
)

// On the People screen, making somebody an administrator waits for a
// second administrator, who sees it there and approves it; whoever asked
// may only withdraw it.
func TestMakingAnAdministratorOnTheScreenTakesTwo(t *testing.T) {
	srv, editor := setup(t)
	if err := srv.Policy.Grant(auth.Binding{Principal: "lee", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	lee, _, err := srv.Tokens.IssueSession("lee", "lee", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	w := postForm(t, srv, "/people/grant", editor, url.Values{"principal": {"pat"}, "role": {"admin"}, "resource": {"/"}}.Encode())
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); !strings.Contains(loc, "waits for a second administrator") {
		t.Fatalf("granting: %d %s", w.Code, loc)
	}
	if srv.Policy.Evaluate("pat", auth.ActGrant, "/").Allowed {
		t.Fatal("pat became an administrator on one administrator's word")
	}
	pend, _ := srv.Dual.Store.Pending(time.Now())
	if len(pend) != 1 {
		t.Fatalf("pending: %+v", pend)
	}
	mine := get(t, srv, "/people", editor).Body.String()
	if !strings.Contains(mine, "Waiting for a second administrator") || strings.Contains(mine, `value="approve"`) ||
		!strings.Contains(mine, `value="withdraw"`) {
		t.Error("the asker is offered the wrong buttons")
	}
	if !strings.Contains(get(t, srv, "/people", lee).Body.String(), `value="approve"`) {
		t.Fatal("another administrator is not offered to approve")
	}
	postForm(t, srv, "/people/pending", editor, url.Values{"id": {pend[0].ID}, "do": {"approve"}}.Encode())
	if srv.Policy.Evaluate("pat", auth.ActGrant, "/").Allowed {
		t.Fatal("the asker approved their own request")
	}
	postForm(t, srv, "/people/pending", lee, url.Values{"id": {pend[0].ID}, "do": {"approve"}}.Encode())
	if !srv.Policy.Evaluate("pat", auth.ActGrant, "/").Allowed {
		t.Fatal("approved, and pat is not an administrator")
	}
}

// A weaker setting from the Settings screen waits too, and is made when
// approved; the only administrator makes theirs at once.
func TestAWeakerSettingOnTheScreenTakesTwo(t *testing.T) {
	srv, editor := setup(t)
	// Read and written as bytes, as the file is: a change the handler
	// makes and does not save is not seen by the next read.
	saved := []byte("{}")
	srv.Settings = &Settings{
		Load: func() (*config.Config, error) { return config.Parse(saved) },
		Save: func(c *config.Config) error { b, err := c.Bytes(); saved = b; return err }}
	weaken := url.Values{"key": {"publish.require_a11y"}, "value": {"false"}, "reason": {"a migration"}}.Encode()
	if w := postForm(t, srv, "/settings/save", editor, weaken); w.Code != http.StatusSeeOther {
		t.Fatalf("alone: %d", w.Code)
	}
	cfg, _ := srv.Settings.Load()
	if cfg.Bool("publish.require_a11y") {
		t.Fatal("the only administrator could not weaken a setting")
	}
	saved = []byte("{}")
	if err := srv.Policy.Grant(auth.Binding{Principal: "lee", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	postForm(t, srv, "/settings/save", editor, weaken)
	if cfg, _ := srv.Settings.Load(); !cfg.Bool("publish.require_a11y") {
		t.Fatal("a weaker setting took effect on one administrator's word")
	}
	pend, _ := srv.Dual.Store.Pending(time.Now())
	if len(pend) != 1 || pend[0].Kind != dual.Setting {
		t.Fatalf("pending: %+v", pend)
	}
	lee, _, _ := srv.Tokens.IssueSession("lee", "lee", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	postForm(t, srv, "/people/pending", lee, url.Values{"id": {pend[0].ID}, "do": {"approve"}}.Encode())
	if cfg, _ := srv.Settings.Load(); cfg.Bool("publish.require_a11y") {
		t.Fatal("approved, and the setting did not change")
	}
}
