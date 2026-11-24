// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/config"
)

// Every group on Settings is named in words. A group whose heading is its
// raw key (mcp, a2a, guardrail) sat beside "Signing in" and "API tokens", and
// the one that was weaker than its default was the one labelled "mcp".
func TestEverySettingsGroupHasALabel(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range config.New().Effectives() {
		g, _, _ := strings.Cut(e.Setting.Key, ".")
		if seen[g] {
			continue
		}
		seen[g] = true
		if settingGroupLabel(g) == g {
			t.Errorf("the settings group %q has no label: add it to settingGroupLabel", g)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no settings were listed")
	}
}

// A duration on Settings is shown in the largest whole unit it is, and a
// value given in days is taken.
//
// The screen printed what the file holds, so the access review's ninety
// days was 2160h in the Value and Default columns, and typing 60d in the
// box was refused as not a duration.
func TestADurationOnSettingsIsShownAndTakenInDays(t *testing.T) {
	srv, editor := setup(t)
	saved := []byte(`{"values":{"token.ttl.max":"720h"}}`)
	srv.Settings = &Settings{
		Load: func() (*config.Config, error) { return config.Parse(saved) },
		Save: func(c *config.Config) error { b, err := c.Bytes(); saved = b; return err }}
	body := get(t, srv, "/settings", editor).Body.String()
	for _, want := range []string{`<strong>30d</strong>`, `<td class="hint">90d</td>`, `value="30d"`} {
		if !strings.Contains(body, want) {
			t.Errorf("Settings does not show %s", want)
		}
	}
	for _, hours := range []string{`<td class="hint">2160h</td>`, `<strong>720h</strong>`, `value="720h"`} {
		if strings.Contains(body, hours) {
			t.Errorf("Settings still shows %s where it is a whole number of days", hours)
		}
	}
	postForm(t, srv, "/settings/save", editor, url.Values{"key": {"access.review.every"}, "value": {"60d"}}.Encode())
	if cfg, _ := srv.Settings.Load(); cfg.Dur("access.review.every") != 60*24*time.Hour {
		t.Errorf("60d was not taken: %s", cfg.Raw("access.review.every"))
	}
}

// What Settings says after a change gives a duration as the table does.
//
// The table said 60d, and the message above it, read from the file, said
// "access.review.every is now 1440h"; put back to its default it said
// 2160h, and somebody who had typed 90d was told a number they did not
// recognise as what they had asked for.
func TestASavedDurationIsSaidAsTheTableSaysIt(t *testing.T) {
	srv, editor := setup(t)
	saved := []byte(`{}`)
	srv.Settings = &Settings{
		Load: func() (*config.Config, error) { return config.Parse(saved) },
		Save: func(c *config.Config) error { b, err := c.Bytes(); saved = b; return err }}
	for _, c := range []struct {
		form url.Values
		want string
	}{
		{url.Values{"key": {"access.review.every"}, "value": {"1440h"}}, "access.review.every is now 60d"},
		{url.Values{"key": {"access.review.every"}, "value": {"90d"}}, "access.review.every is now 90d"},
		{url.Values{"key": {"access.review.every"}, "value": {"60d"}}, "access.review.every is now 60d"},
		{url.Values{"key": {"access.review.every"}, "reset": {"1"}}, "access.review.every is now 90d"},
		{url.Values{"key": {"session.idle"}, "value": {"30m"}}, "session.idle is now 30m"},
		{url.Values{"key": {"publish.require_a11y"}, "value": {"true"}}, "publish.require_a11y is now true"},
	} {
		w := postForm(t, srv, "/settings/save", editor, c.form.Encode())
		loc, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if got := loc.Query().Get("m"); got != c.want {
			t.Errorf("%v: Settings said %q, want %q", c.form, got, c.want)
		}
	}
}

// The settings screen says the count of approvals that applies beside a
// setting that says less.
//
// The larger of the setting and approval.json applies, and approval.json
// is written by `quilzo review require`, so the screen said two beside
// review.required_approvals while five applied. A setting the file does not
// ask more of is shown as it was.
func TestTheSettingsScreenSaysTheApprovalCountThatApplies(t *testing.T) {
	srv, token := setup(t)
	withSettings(t, srv, map[string]string{"review.required_approvals": "2", "approval.required_humans": "3"})
	srv.Approvals = &Approvals{
		Policy:  func() (collab.Policy, error) { return collab.Policy{Required: 5, RequiredHumans: 3}, nil },
		Current: func() (*collab.Proposal, error) { return nil, nil },
		Save:    func(*collab.Proposal) error { return nil },
		KindOf:  func(string) string { return "human" },
	}
	body := get(t, srv, "/settings", token).Body.String()
	if !strings.Contains(body, "5 apply") {
		t.Errorf("the settings screen does not say that five approvals apply beside a setting of two")
	}
	if strings.Contains(body, "3 apply") {
		t.Errorf("the settings screen says the file asks more of a setting it does not")
	}
}
