// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// The People screen showed when each token expires as a day alone, so a
// token issued for an hour read "until 12 Nov 2026", the same as one that
// lasts the month, and nobody could tell it would end before lunch. A token
// shorter than a day is shown with the hour and the zone; a longer one
// keeps the day.
func TestAShortTokenOnThePeopleScreenEndsAtAnHour(t *testing.T) {
	srv, tok := setup(t)
	if _, _, err := srv.Tokens.Issue("ci-hour", "editor", auth.RoleReader, "/", time.Hour, auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, _, err := srv.Tokens.Issue("ci-month", "editor", auth.RoleReader, "/", 30*24*time.Hour, auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	w := get(t, srv, "/people", tok)
	if w.Code != http.StatusOK {
		t.Fatalf("/people: %d", w.Code)
	}
	body := w.Body.String()
	row := func(name string) string {
		i := strings.Index(body, name)
		if i < 0 {
			t.Fatalf("the People screen does not list %s", name)
		}
		end := strings.Index(body[i:], "</tr>")
		return body[i : i+end]
	}
	hour := time.Now().Add(time.Hour)
	if want := hour.Format("15:04 MST"); !strings.Contains(row("ci-hour"), want) {
		t.Errorf("an hour's token does not say the hour it ends (%s):\n%s", want, row("ci-hour"))
	}
	month := time.Now().Add(30 * 24 * time.Hour)
	if r := row("ci-month"); !strings.Contains(r, month.Format("2 Jan 2006")) || strings.Contains(r, month.Format("MST")+"<") {
		t.Errorf("a month's token is not shown by its day alone:\n%s", r)
	}
}
