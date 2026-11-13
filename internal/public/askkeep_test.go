// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"context"
	"html"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/assistant"
)

// A rebuilt site's chatbots carry on from the ones before: a rating handed
// out before the rebuild counts once, on either side of it. And they answer
// with their own settings: a guardrail the rebuilt ones were given screens
// what they answer from, though the knowledge itself has not changed.
//
// The server that rebuilds a site when its settings change used to keep the
// previous chatbots whole, to keep their rating keys, and with them the
// guardrail they had been built with; and an index built before a guardrail
// was turned on was keyed on the knowledge alone, so it would have been
// answered from even by chatbots that had one.
func TestRebuiltChatbotsKeepTheirVisitorsAndTakeTheirSettings(t *testing.T) {
	st, _ := askSite(t, shopBot)
	prev := st.Assistants
	rated := 0
	prev.Rated = func(string, string, bool) { rated++ }
	const q = "can I return opened ink?"
	body := askPost(st, "help", q).Body.String()
	if !strings.Contains(body, "cannot be returned") {
		t.Fatalf("the answer before any guardrail:\n%s", body)
	}
	m := reRateToken.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no rating was offered, so this checks nothing about the ratings")
	}
	token := html.UnescapeString(m[1])

	// The site built again, with a guardrail that flags the returns page.
	asked := 0
	next := &Assistants{Set: prev.Set, Forms: prev.Forms, Audit: prev.Audit, Rated: prev.Rated,
		Guardrail: func(_ context.Context, texts []string) ([]bool, int) {
			asked++
			flagged := make([]bool, len(texts))
			for i, text := range texts {
				flagged[i] = strings.Contains(text, "Opened ink")
			}
			return flagged, 0
		}}
	next.Keep(prev)
	st.Assistants = next

	if body := askPost(st, "help", q).Body.String(); asked == 0 || strings.Contains(body, "cannot be returned") {
		t.Fatalf("the rebuilt chatbot answered from an index its guardrail never saw (asked %d):\n%s", asked, body)
	}
	if w := ratePost(st, "help", url.Values{"q": {q}, "t": {token}, "helpful": {"yes"}}); !strings.Contains(w.Header().Get("Location"), "rated=yes") {
		t.Fatalf("a rating from before the rebuild: %s", w.Header().Get("Location"))
	}
	// Spent, on whichever side of the rebuild it is offered again.
	if prev.spendRateToken("help", q, token, time.Now()) {
		t.Error("a rating spent after the rebuild was taken again by the site before it")
	}
	if w := ratePost(st, "help", url.Values{"q": {q}, "t": {token}, "helpful": {"yes"}}); !strings.Contains(w.Header().Get("Location"), "rated=late") {
		t.Errorf("the same rating twice: %s", w.Header().Get("Location"))
	}
	if rated != 1 {
		t.Errorf("one rating counted %d times", rated)
	}

	// A third build follows the first, not a chain of every build there has
	// been, and still knows the token.
	third := &Assistants{Set: prev.Set}
	third.Keep(next)
	if third.own() != prev || third.spendRateToken("help", q, token, time.Now()) {
		t.Error("a third build does not share the first one's ratings")
	}
}

// What a rebuilt chatbot holds as new is what the one before it held, and a
// page entering its knowledge after the rebuild is new to it.
func TestRebuiltChatbotsKnowWhichPagesAreNew(t *testing.T) {
	st, _ := askSite(t, shopBot)
	prev := st.Assistants
	set, _ := prev.Set()
	a, _ := set.Get("help")
	was := assistant.NewIndex([]assistant.Passage{{Page: "index", Text: "x"}})
	now := assistant.NewIndex([]assistant.Passage{{Page: "index", Text: "x"}, {Page: "returns", Text: "y"}})
	prev.mu.Lock()
	prev.noteFresh(a.Name, was, now, time.Now())
	prev.mu.Unlock()

	next := &Assistants{Set: prev.Set}
	next.Keep(prev)
	if !next.isFresh("help", "returns", time.Now()) {
		t.Error("a page new before the rebuild is not new after it")
	}
	if next.isFresh("help", "index", time.Now()) {
		t.Error("a page that was always there is new")
	}
}
