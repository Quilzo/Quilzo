// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"fmt"
	"math"
	"strings"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/media"
)

// Rich replies: what an answer can show besides its sentences.
//
// # A closed catalogue, drawn by this program
//
// The generative-UI work of 2025–26 (Google's A2UI, MCP Apps) settled on
// one idea worth keeping: the agent chooses from components the client
// already has, and never sends markup or code. Here the catalogue is three
// things, and the page template is the only thing that draws them:
//
//   - cards, for the pages an answer cites that have more to show than a
//     title — a picture, a price, whether it is in stock, a summary;
//   - choices, the next questions worth asking, each a link that asks it;
//   - the offer that was already here: a link, or the site's own form
//     filled in for the visitor to check and send.
//
// Everything on a card comes from the published page it stands for, never
// from what a model wrote, and every choice is either a question the owner
// wrote or one made from a page title. A model can influence which pages
// are cited; it cannot put a word on a card.

// askCard is a cited page, shown as more than a link.
type askCard struct {
	Title, Href, Image, Summary, Meta string
}

// maxCards is how many cards an answer shows: enough to compare, few
// enough that the answer stays the thing being read.
const maxCards = 3

// cardsFor builds cards for the cited pages that have something to show.
func (st *Site) cardsFor(sources []askSource, ans assistant.Answer) []askCard {
	pages, _, err := st.pages()
	if err != nil {
		return nil
	}
	var out []askCard
	for _, s := range sources {
		if len(out) == maxCards || s.N < 1 || s.N > len(ans.Sources) {
			break
		}
		h := ans.Sources[s.N-1]
		if h.Doc != "" {
			continue // a document has no fields to show
		}
		body, _ := pages[h.Page].(map[string]any)
		if body == nil {
			continue
		}
		c := askCard{Title: s.Title, Href: s.Href}
		if title, _ := body["title"].(string); strings.TrimSpace(title) != "" {
			c.Title = title
		}
		for _, k := range []string{"image", "photo", "picture", "cover"} {
			if v, _ := body[k].(string); v != "" {
				if id, ok := media.IDIn(v); ok {
					c.Image = "/media/" + id
					break
				}
			}
		}
		for _, k := range []string{"summary", "description", "standfirst", "intro", "lead"} {
			if v, _ := body[k].(string); strings.TrimSpace(v) != "" {
				c.Summary = clip(v, 140)
				break
			}
		}
		var meta []string
		if p := priceOf(body); p != "" {
			meta = append(meta, p)
		}
		for _, k := range []string{"availability", "stock", "status"} {
			if v, _ := body[k].(string); strings.TrimSpace(v) != "" {
				meta = append(meta, clip(v, 40))
				break
			}
		}
		c.Meta = strings.Join(meta, " · ")
		// A card that would say only what the source list says is not one.
		if c.Image == "" && c.Meta == "" && c.Summary == "" {
			continue
		}
		out = append(out, c)
	}
	return out
}

func priceOf(body map[string]any) string {
	var v string
	switch p := body["price"].(type) {
	case string:
		v = strings.TrimSpace(p)
	case float64:
		// Whole amounts without decimals, anything else with two, the way a
		// price is written: £12, £12.50.
		if p == math.Trunc(p) {
			v = fmt.Sprintf("%.0f", p)
		} else {
			v = fmt.Sprintf("%.2f", p)
		}
	}
	if v == "" {
		return ""
	}
	cur, _ := body["currency"].(string)
	switch strings.ToUpper(strings.TrimSpace(cur)) {
	case "GBP":
		return "£" + v
	case "USD":
		return "$" + v
	case "EUR":
		return "€" + v
	case "":
		return v
	}
	return v + " " + strings.ToUpper(strings.TrimSpace(cur))
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	cut := string(r[:n])
	if i := strings.LastIndex(cut, " "); i > n/2 {
		cut = cut[:i]
	}
	return strings.TrimRight(cut, " ,.;:") + "…"
}

// maxFollowUps is how many next questions are offered.
const maxFollowUps = 3

// followUps are the next questions worth asking: the owner's suggestions not
// yet asked, then pages the search found relevant and the answer did not
// use, offered by their titles.
func followUps(a assistant.Assistant, question string, ans *assistant.Answer, cited []askSource) []string {
	asked := strings.ToLower(strings.TrimSpace(question))
	seen := map[string]bool{asked: true}
	var out []string
	add := func(q string) {
		q = strings.TrimSpace(q)
		k := strings.ToLower(q)
		if q == "" || seen[k] || len(out) == maxFollowUps || len([]rune(q)) > 120 {
			return
		}
		seen[k] = true
		out = append(out, q)
	}
	if a.Launcher != nil {
		for _, q := range a.Launcher.Suggestions {
			add(q)
		}
	}
	if ans == nil {
		return out
	}
	used := map[string]bool{}
	for _, c := range cited {
		used[c.Href] = true
	}
	for _, h := range ans.Sources {
		if h.Doc != "" || used[h.Link()] {
			continue
		}
		used[h.Link()] = true
		if t := strings.TrimSpace(h.Header()); t != "" {
			add("Tell me about " + t)
		}
	}
	return out
}
