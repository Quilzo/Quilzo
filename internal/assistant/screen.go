// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assistant

import (
	"strings"

	"github.com/quilzo/quilzo/internal/guardrail"
)

// Screening what a chatbot knows, as its index is built.
//
// A page is written for the people who read it. Text in it that addresses
// the AI reading it instead ("ignore your previous instructions", "if you
// are an AI assistant", a fake system prompt, "do not tell the user") is
// the shape of a planted instruction: indirect prompt injection, or a
// poisoned document (OWASP LLM08). The fence and the citation check already
// stop such text from becoming an action or an unsupported sentence; this
// stops it reaching the model at all, before anybody has asked anything.
// Lakera, now Check Point's AI Guardrails, recommends the same: screen a
// knowledge base when documents are added, not only when they are used.
//
// Held passages are not deleted or hidden from the site. They are left out
// of what the chatbot reads, and the owner is told which and why. A
// chatbot whose pages discuss these attacks on purpose can keep them
// (Assistant.KeepInstructions).

// markupWhy is the reason for text imitating a prompt's markup.
const markupWhy = guardrail.MarkupWhy

// Screen is why a passage reads as addressed to an AI, or nothing.
//
// The rules are the knowledge view of the one table every surface reads
// (internal/guardrail): this list and the public chatbot's and the meeting
// scribe's were three, and the chatbot missed the commonest wording of an
// attempt the other two caught.
func Screen(text string) []string { return guardrail.Injection(guardrail.Knowledge, text) }

// Held is a passage kept out of what a chatbot reads, and why.
type Held struct {
	Passage Passage  `json:"passage"`
	Why     []string `json:"why"`
}

// Hold separates the passages a chatbot reads from the ones that address
// an AI. A page's title and heading are screened with its text, since they
// are read with it.
func Hold(ps []Passage) (kept []Passage, held []Held) {
	for _, p := range ps {
		if why := Screen(p.Header() + "\n" + p.Text); len(why) > 0 {
			held = append(held, Held{Passage: p, Why: why})
			continue
		}
		kept = append(kept, p)
	}
	return kept, held
}

// HeldPages is the pages and documents held passages came from, each with
// every reason, for an owner.
func HeldPages(held []Held) map[string][]string {
	out := map[string][]string{}
	for _, h := range held {
		where := h.Passage.Page
		if h.Passage.Doc != "" {
			where = "media/" + h.Passage.Doc
		}
		for _, w := range h.Why {
			if !containsString(out[where], w) {
				out[where] = append(out[where], w)
			}
		}
	}
	return out
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

// Redact is text with each sentence that addresses an AI replaced by a
// marker saying so, for an agent reading a whole page: it still sees that
// something was there, and why it was left out. Text whose instruction
// spans sentences (a prompt's markup across lines) is left out whole.
func Redact(text string) (string, []string) {
	why := Screen(text)
	if len(why) == 0 {
		return text, nil
	}
	// A prompt's own markup says that what follows it is a prompt: the
	// whole text goes, not only the line the markup is on.
	for _, w := range why {
		if w == markupWhy {
			return "[left out by Quilzo: this text " + strings.Join(why, ", and ") + "]", why
		}
	}
	lines := strings.Split(text, "\n")
	changed := false
	for i, line := range lines {
		ss := sentences(line)
		if len(ss) == 0 {
			continue
		}
		var out []string
		for _, s := range ss {
			if r := Screen(s); len(r) > 0 {
				out = append(out, "[left out by Quilzo: this "+r[0]+"]")
				changed = true
				continue
			}
			out = append(out, s)
		}
		lines[i] = strings.Join(out, " ")
	}
	if !changed || len(Screen(strings.Join(lines, "\n"))) > 0 {
		return "[left out by Quilzo: this text " + strings.Join(why, ", and ") + "]", why
	}
	return strings.Join(lines, "\n"), why
}
