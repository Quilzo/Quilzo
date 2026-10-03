// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/form"
)

func richSite(t *testing.T, a assistant.Assistant) *Site {
	t.Helper()
	img := strings.Repeat("ab", 32)
	st := published(t, map[string]any{
		"index": map[string]any{"title": "Marginalia", "intro": "Paper, made in small runs."},
		"indigo": map[string]any{"title": `Indigo ink <b>bold</b>`, "image": img, "price": float64(12), "currency": "GBP",
			"availability": "Low stock", "summary": "A blue that is nearly black, in a 30ml bottle.",
			"body": "Indigo ink is a blue that is nearly black. It comes in a 30ml glass bottle."},
		"walnut":  map[string]any{"title": "Walnut ink", "body": "Walnut ink is brown, made from walnut husks, in a 30ml bottle."},
		"returns": map[string]any{"title": "Returns", "body": "Opened ink bottles cannot be returned."},
	})
	set := &assistant.Set{}
	if err := set.Put(a); err != nil {
		t.Fatal(err)
	}
	st.Assistants = &Assistants{Set: func() (*assistant.Set, error) { return set, nil },
		Forms: func() (*form.Set, error) { return &form.Set{}, nil }}
	return st
}

// A cited page with a picture, a price and a stock level is shown as a
// card made from that page, and the next questions are links that ask them.
func TestAnAnswerShowsCardsAndNextQuestions(t *testing.T) {
	a := assistant.Assistant{Name: "help", Title: "Ask", Public: true,
		Launcher: &assistant.Launcher{Suggestions: []string{"Can I return opened ink?", "What is indigo ink?"}}}
	st := richSite(t, a)
	body := get(st, "/ask/help?q=What%20is%20indigo%20ink%3f", nil).Body.String()
	for _, want := range []string{
		`<ul class="qz-cards"`, `src="/media/` + strings.Repeat("ab", 32) + `"`, `alt=""`,
		`Indigo ink &lt;b&gt;bold&lt;/b&gt;`, `£12 · Low stock`, `A blue that is nearly black`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	// The question asked is not offered again; the other suggestion is.
	if !strings.Contains(body, `aria-label="You could also ask"`) || !strings.Contains(body, `>Can I return opened ink?</a>`) {
		t.Error("the next questions are not offered")
	}
	if strings.Contains(body, `>What is indigo ink?</a>`) {
		t.Error("the question just asked was offered again")
	}
	// In the panel, a card opens the page behind it.
	panel := get(st, "/ask/help?q=What%20is%20indigo%20ink%3f&embed=panel", nil).Body.String()
	if !strings.Contains(panel, `target="_top">Indigo ink`) {
		t.Error("a card in the panel does not open in the page")
	}
}

// A page with nothing to show beyond its title gets no card: the source list
// already says it.
func TestAPlainPageIsNotACard(t *testing.T) {
	st := richSite(t, assistant.Assistant{Name: "help", Title: "Ask", Public: true})
	body := get(st, "/ask/help?q=Can%20opened%20ink%20be%20returned%3f", nil).Body.String()
	if strings.Contains(body, `class="qz-cards"`) {
		t.Errorf("a plain page became a card")
	}
}

func TestAPriceIsWrittenTheWayItIsMeant(t *testing.T) {
	for _, c := range []struct {
		body map[string]any
		want string
	}{
		{map[string]any{"price": float64(12)}, "12"},
		{map[string]any{"price": float64(12.5), "currency": "EUR"}, "€12.50"},
		{map[string]any{"price": "40", "currency": "nok"}, "40 NOK"},
		{map[string]any{}, ""},
	} {
		if got := priceOf(c.body); got != c.want {
			t.Errorf("%v: %q, want %q", c.body, got, c.want)
		}
	}
}
