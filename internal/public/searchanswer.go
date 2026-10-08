// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/throttle"
)

// An answer above the search results, from the site's own assistant.
//
// What documentation sites settled on in 2025–26 (Algolia's Ask AI,
// kapa.ai, Mintlify): a question typed into search gets a short answer
// with citations first, and the results after it. Here it is the same
// assistant, the same knowledge and the same checks as the conversation
// page — every sentence cites a page — so search adds no new way for the
// site to say something it does not say.
//
// It answers questions, not keywords: "returns policy" is a search, "can I
// return opened ink?" is a question. A search with nothing to say beside it
// is the right answer to a keyword, and asking a model about one would
// spend a call on every search box keystroke somebody sends. It counts
// against the same per-visitor budget as the conversation page, shows
// nothing when the site does not know, and is skipped for anything that
// looks like an attempt to instruct the model rather than ask it.

var questionWords = map[string]bool{
	"what": true, "how": true, "why": true, "when": true, "where": true, "who": true, "which": true,
	"can": true, "could": true, "do": true, "does": true, "did": true, "is": true, "are": true,
	"will": true, "should": true, "may": true, "would": true, "has": true, "have": true,
}

// isQuestion reports whether a search reads as a question.
func isQuestion(q string) bool {
	q = strings.TrimSpace(q)
	if strings.HasSuffix(q, "?") {
		return true
	}
	words := strings.Fields(strings.ToLower(q))
	return len(words) >= 3 && questionWords[words[0]]
}

// searchAssistant is the assistant search answers with: the one on the
// site's pages, or the only public one.
func (st *Site) searchAssistant() (assistant.Assistant, bool) {
	if st.Assistants == nil || st.Assistants.Set == nil {
		return assistant.Assistant{}, false
	}
	set, err := st.Assistants.Set()
	if err != nil || set == nil {
		return assistant.Assistant{}, false
	}
	if a, ok := set.Launcher(); ok {
		return a, true
	}
	var only assistant.Assistant
	n := 0
	for _, a := range set.Assistants {
		if a.Public {
			only, n = a, n+1
		}
	}
	return only, n == 1
}

// searchAnswer is the answer for the template, or nil.
func (st *Site) searchAnswer(r *http.Request, query string) map[string]any {
	if !isQuestion(query) || len([]rune(query)) > 300 {
		return nil
	}
	a, ok := st.searchAssistant()
	if !ok {
		return nil
	}
	if _, _, off := st.shielded("search-answers"); off {
		return nil // the results are still there
	}
	if level, _, on := st.shielded("chatbot:" + a.Name); on && level != "limited" {
		return nil
	}
	if LooksLikeInjection(query) {
		st.signal(ChatbotInjection, a.Name, r)
		return nil
	}
	source := sourceOf(r)
	if l := st.Assistants.Limit; l != nil {
		if d := l.Check(throttle.Subject{Source: source}); !d.Allowed {
			return nil // the results are still there; the answer can wait
		}
		l.Spend(throttle.Subject{Source: source})
	}
	idx, err := st.assistantIndex(a)
	if err != nil {
		return nil
	}
	var m assistant.Model
	if _, _, limited := st.shielded("chatbot:" + a.Name); a.UseModel && st.Assistants.Model != nil && !limited {
		m = st.Assistants.Model(a)
	}
	// Shorter than the conversation page allows: the results are waiting
	// behind this, and a slow answer is worse than none.
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	ans, err := assistant.RespondTo(ctx, a, idx, m, query, "")
	if st.Assistants.Audit != nil {
		st.Assistants.Audit(a.Name, source, err == nil && !ans.Refused)
	}
	if err != nil || ans.Refused || len(ans.Kept) == 0 {
		return nil
	}
	cited := st.citedSources(ans)
	href := map[int]string{}
	for _, c := range cited {
		href[c.N] = c.Href
	}
	var sentences []any
	for _, s := range ans.Kept {
		var cites []any
		for _, n := range s.Cites {
			if h, ok := href[n]; ok {
				cites = append(cites, map[string]any{"n": float64(n), "href": h})
			}
		}
		sentences = append(sentences, map[string]any{"text": s.Text, "cites": cites})
	}
	var sources []any
	for _, c := range cited {
		sources = append(sources, map[string]any{"n": float64(c.N), "title": c.Title, "href": c.Href})
	}
	return map[string]any{
		"title": a.Title, "assistant": a.Name, "sentences": sentences, "sources": sources,
		"more": "/ask/" + url.PathEscape(a.Name) + "?q=" + url.QueryEscape(query),
		// EU AI Act Article 50(1): an answer an automated system wrote says
		// so where it is shown; a search layout puts {{ answer.disclosure }}
		// beside it, and the posture checks that it does.
		"disclosure": Disclosure,
	}
}
