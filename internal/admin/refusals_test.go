// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/config"
)

// followed is the screen a redirect lands on.
func followed(t *testing.T, srv *Server, token string, w interface{ Header() http.Header }) string {
	t.Helper()
	loc := w.Header().Get("Location")
	if loc == "" {
		t.Fatal("no redirect")
	}
	return get(t, srv, loc, token).Body.String()
}

// People and Settings say a refusal as a refusal.
//
// Both sent every outcome back as m=, so "Until has to be a day in the
// future." and "auth.throttle.after: \"banana\" is not a number" sat in the
// same grey notice as "dana is now author on /", and a screen reader heard
// neither as anything but text. flash.go has always had e= for a refusal;
// these two screens never used it.
func TestPeopleAndSettingsSayARefusalAsOne(t *testing.T) {
	srv, token := setup(t)
	saved := []byte(`{}`)
	srv.Settings = &Settings{
		Load: func() (*config.Config, error) { return config.Parse(saved) },
		Save: func(c *config.Config) error { b, err := c.Bytes(); saved = b; return err }}

	for _, c := range []struct {
		path, form, says string
		refused          bool
	}{
		{"/people/grant", url.Values{"principal": {"dana"}, "role": {"author"}, "resource": {"/"},
			"until": {"2000-01-01"}}.Encode(), "Until has to be a day in the future.", true},
		{"/people/grant", url.Values{"principal": {"dana"}, "role": {"permission:nonsense"}}.Encode(),
			"That is not a permission.", true},
		{"/people/grant", url.Values{"principal": {"dana"}, "role": {"author"}, "resource": {"/"}}.Encode(),
			"dana is now author on /", false},
		{"/settings/save", url.Values{"key": {"auth.throttle.after"}, "value": {"banana"}}.Encode(),
			"auth.throttle.after", true},
		{"/settings/save", url.Values{"key": {"auth.throttle.after"}, "value": {"3"}}.Encode(),
			"auth.throttle.after is now 3", false},
	} {
		w := postForm(t, srv, c.path, token, c.form)
		q := redirectQuery(w)
		if c.refused && (q.Get("e") == "" || q.Get("m") != "") {
			t.Errorf("%s %s: a refusal came back as %s", c.path, c.form, w.Header().Get("Location"))
		}
		if !c.refused && (q.Get("m") == "" || q.Get("e") != "") {
			t.Errorf("%s %s: a success came back as %s", c.path, c.form, w.Header().Get("Location"))
		}
		body := followed(t, srv, token, w)
		notice := `<p class="notice ok" role="status">`
		if c.refused {
			notice = `<p class="notice bad" role="alert">`
		}
		at := strings.Index(body, notice)
		if at < 0 || !strings.Contains(body[at:min(len(body), at+300)], c.says) {
			t.Errorf("%s %s: %q is not shown in %s", c.path, c.form, c.says, notice)
		}
	}

	// The group a refusal names is open, as it is for a confirmation.
	w := postForm(t, srv, "/settings/save", token,
		url.Values{"key": {"auth.throttle.after"}, "value": {"banana"}}.Encode())
	body := followed(t, srv, token, w)
	at := strings.Index(body, "auth.throttle.after</code>")
	open := strings.LastIndex(body[:max(at, 0)], `<details class="settinggroup"`)
	if at < 0 || open < 0 || !strings.HasPrefix(body[open:], `<details class="settinggroup" open>`) {
		t.Error("the setting a refusal is about is in a closed group")
	}
}
