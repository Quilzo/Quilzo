// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/gateway"
)

// Changing one limit of a budget on the Models screen keeps the others. The
// form started at zero and a save replaced the caller's whole budget, so an
// owner slowing a public chatbot to thirty calls a minute lifted its money
// and character caps without a word. A field left empty keeps what the
// caller has; 0 is unlimited, as the form says.
func TestABudgetChangedOnTheScreenKeepsWhatItIsNotGiven(t *testing.T) {
	srv, token := setup(t)
	m, cfg := modelsRig()
	cfg.Currency = "GBP"
	srv.Models = m
	save := func(fields url.Values) {
		t.Helper()
		fields.Set("op", "budget")
		fields.Set("name", "chatbot:help")
		if w := decideForm(t, srv, "/models/change", token, fields); strings.Contains(w.Header().Get("Location"), "e=") {
			t.Fatalf("refused: %s", w.Header().Get("Location"))
		}
	}
	budget := func() gateway.Budget {
		t.Helper()
		b, _ := cfg.BudgetFor("chatbot:help")
		return b
	}
	save(url.Values{"chars_per_day": {"100000"}, "money_per_day": {"5.00"}, "money_per_month": {"100"}})
	want := gateway.Budget{Consumer: "chatbot:help", CharsPerDay: 100000, MoneyPerDay: "5.00", MoneyPerMonth: "100"}
	if budget() != want {
		t.Fatalf("the budget saved is %+v", budget())
	}
	// As the form posts it: every field, the ones not typed in empty.
	save(url.Values{"per_minute": {"30"}, "chars_per_day": {""}, "tokens_per_day": {""},
		"money_per_day": {""}, "money_per_month": {""}})
	want.PerMinute = 30
	if budget() != want {
		t.Errorf("one limit changed left %+v", budget())
	}
	save(url.Values{"chars_per_day": {"0"}, "money_per_day": {"0"}})
	want.CharsPerDay, want.MoneyPerDay = 0, ""
	if budget() != want {
		t.Errorf("limits set to unlimited left %+v", budget())
	}
	if body := get(t, srv, "/models", token).Body.String(); strings.Contains(body, `name="per_minute" type="number" min="0" value="0"`) {
		t.Error("the form still starts at zero, which would lift a limit it was not meant to")
	}
}
