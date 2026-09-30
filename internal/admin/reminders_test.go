// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/remind"
)

type fakeReminders struct {
	enabled bool
	sends   int
	by      string
}

func (f *fakeReminders) wire() *Reminders {
	return &Reminders{
		Preview: func(now time.Time) (remind.Config, []remind.Message,
			[]remind.Held, map[remind.Channel]string, error) {
			c := remind.Default()
			c.Enabled = f.enabled
			c.FromHour, c.ToHour, c.Weekdays = 0, 24, false
			return c, []remind.Message{{Person: "vanta:v1", Name: "Sam Okafor",
					Channel: remind.Email, Subject: "Security tasks",
					Body: "Hello\n\n- Finish your security training (in KnowBe4)\n"}},
				[]remind.Held{{Name: "Ann", Why: "reminded 2 day(s) ago"}},
				map[remind.Channel]string{}, nil
		},
		Ledger: func() ([]remind.Sent, error) {
			return []remind.Sent{{At: time.Now(), Person: "vanta:v1",
				Channel: remind.Email, Items: []string{"training"}, OK: true}}, nil
		},
		Enable: func(on bool, by string) error { f.enabled, f.by = on, by; return nil },
		Send: func(now time.Time, by string) (int, int, error) {
			f.sends++
			f.by = by
			return 1, 0, nil
		},
	}
}

func postAct(t *testing.T, srv *Server, token string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/workforce/reminders/act",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func TestRemindersNeedTheirBoxTickedAndSaySo(t *testing.T) {
	srv, token := setup(t)
	f := &fakeReminders{}
	srv.Reminders = f.wire()

	page := get(t, srv, "/workforce/reminders", token).Body.String()
	for _, want := range []string{"Sam Okafor", "Finish your security training",
		"Enable reminders", "Held back (1)", "</html>"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}

	w := postAct(t, srv, token, url.Values{"do": {"enable"}})
	if f.enabled || w.Code != http.StatusSeeOther {
		t.Error("reminders were enabled without the preview being read")
	}
	postAct(t, srv, token, url.Values{"do": {"enable"}, "read": {"yes"}})
	if !f.enabled || f.by == "" {
		t.Error("enabling with the box ticked did not enable, or not as whom")
	}
	postAct(t, srv, token, url.Values{"do": {"send"}})
	if f.sends != 0 {
		t.Error("sent without the confirmation box")
	}
	postAct(t, srv, token, url.Values{"do": {"send"}, "confirm": {"yes"}})
	if f.sends != 1 {
		t.Error("confirmed and not sent")
	}
	if w := get(t, srv, "/workforce/reminders/act", token); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("a GET acted: %d", w.Code)
	}
}

func TestOnlyAnAdministratorSendsReminders(t *testing.T) {
	srv, _ := setup(t)
	f := &fakeReminders{enabled: true}
	srv.Reminders = f.wire()
	if err := srv.Policy.Grant(auth.Binding{Principal: "writer",
		Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	secret, _, err := srv.Tokens.Issue("w", "writer", auth.RoleAuthor, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	postAct(t, srv, secret, url.Values{"do": {"send"}, "confirm": {"yes"}})
	if f.sends != 0 {
		t.Error("an author sent reminders to the company")
	}
	if strings.Contains(get(t, srv, "/workforce/reminders", secret).Body.String(),
		"Sam Okafor") {
		t.Error("an author saw who has what outstanding")
	}
}
