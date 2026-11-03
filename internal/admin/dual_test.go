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

// On People, the administrator left after removing the other does not
// approve alone for a day, and is told why and until when; a second
// administrator ends the wait.
//
// One administrator may remove another, and the only administrator
// approves alone. Together they were one administrator approving anything
// alone: the editor asked for pat to be made an administrator, removed lee,
// who would have decided it, and approved it as the only one left.
func TestRemovingTheOtherAdministratorOnTheScreenDoesNotLetTheOneLeftApproveAlone(t *testing.T) {
	srv, editor := setup(t)
	var refused []map[string]string
	srv.Audit = func(action, _ string, detail map[string]string) {
		if action == "dual.alone-refused" {
			refused = append(refused, detail)
		}
	}
	if err := srv.Policy.Grant(auth.Binding{Principal: "lee", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	postForm(t, srv, "/people/grant", editor, url.Values{"principal": {"pat"}, "role": {"admin"}, "resource": {"/"}}.Encode())
	pend, _ := srv.Dual.Store.Pending(time.Now())
	if len(pend) != 1 {
		t.Fatalf("pending: %+v", pend)
	}
	postForm(t, srv, "/people/revoke", editor, url.Values{"principal": {"lee"}, "role": {"admin"}, "resource": {"/"}}.Encode())
	if srv.Policy.Evaluate("lee", auth.ActGrant, "/").Allowed {
		t.Fatal("control: lee was not removed")
	}

	w := postForm(t, srv, "/people/pending", editor, url.Values{"id": {pend[0].ID}, "do": {"approve"}}.Encode())
	if srv.Policy.Evaluate("pat", auth.ActGrant, "/").Allowed {
		t.Fatal("the editor removed the other administrator and approved their own request alone")
	}
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); !strings.Contains(loc, "until") {
		t.Errorf("the refusal does not say why and until when: %s", loc)
	}
	if len(refused) == 0 || refused[0]["subject"] != "lee" || refused[0]["until"] == "" {
		t.Errorf("the refusal was not recorded with the removal it follows: %v", refused)
	}
	if strings.Contains(get(t, srv, "/people", editor).Body.String(), `value="approve"`) {
		t.Error("the only administrator is still offered to approve their own request")
	}
	// A change they ask for now waits as well.
	postForm(t, srv, "/people/grant", editor, url.Values{"principal": {"kim"}, "role": {"admin"}, "resource": {"/"}}.Encode())
	if srv.Policy.Evaluate("kim", auth.ActGrant, "/").Allowed {
		t.Fatal("an administrator was made alone a moment after the other was removed")
	}

	// sam is made an administrator as the identity provider makes one, by
	// a group already mapped, and approves.
	if err := srv.changePolicy(func(p *auth.Policy) error {
		return p.Grant(auth.Binding{Principal: "sam", Role: auth.RoleAdmin, Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	if rm, err := srv.Dual.Store.Settling(time.Now()); err != nil || rm != nil {
		t.Fatalf("two administrators again, and the wait goes on: %+v %v", rm, err)
	}
	sam, _, _ := srv.Tokens.IssueSession("sam", "sam", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	postForm(t, srv, "/people/pending", sam, url.Values{"id": {pend[0].ID}, "do": {"approve"}}.Encode())
	if !srv.Policy.Evaluate("pat", auth.ActGrant, "/").Allowed {
		t.Fatal("a second administrator could not approve")
	}
}
