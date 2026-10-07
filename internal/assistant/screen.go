// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package assistant

import (
	"regexp"
	"strings"
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
const markupWhy = "imitates a prompt's own markup"

// screenRule is one shape of text addressed to an AI.
type screenRule struct {
	why string
	re  *regexp.Regexp
}

var screenRules = []screenRule{
	{"tells an AI to set its instructions aside",
		regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override|bypass)\b[^.!?\n]{0,30}\b(previous|prior|above|preceding|your|all|any|system)\b[^.!?\n]{0,20}\b(instructions|rules|prompts?|directives|guardrails)\b`)},
	// Not "as an AI assistant": the businesses using this sell AI, and
	// their pages say that about their products all day.
	{"addresses an AI reading the page",
		regexp.MustCompile(`(?i)\b(if you are|you are now|you're now) an? (ai|llm|large language model|language model|chatbot|ai assistant)\b|\b(note|message|instructions?) (to|for) (the |any )?(ai|llm|chatbot|language model)s?\b|\b(attention|dear|hey) (ai|llm|chatbot|language model)s?\b|\b(ai|llm|chatbot|language model)s? (reading|processing|summari[sz]ing|indexing) this\b`)},
	{"asks to be kept from the reader",
		regexp.MustCompile(`(?i)\b(do not|don't|never) (tell|inform|reveal to|mention (this )?to) (the )?(user|reader|visitor|human)s?\b|\bwithout (telling|informing|alerting) (the )?(user|reader|visitor)s?\b`)},
	{markupWhy,
		regexp.MustCompile(`(?i)<\|(im_start|im_end|system|endoftext)\|>|\[/?inst\]|<</?sys>>|<\s*/?\s*system\s*>|(^|\n)\s*#{2,}\s*(system|instruction)s?\s*(\n|$|:)|\bsystem prompt\s*:|\bbegin untrusted content\b|<<<passage>>>`)},
	{"asks for something to be sent somewhere",
		regexp.MustCompile(`(?i)\b(send|email|forward|post|upload|exfiltrate|leak)\b[^.!?\n]{0,40}\b(conversation|chat history|credentials?|password|api key|access token|system prompt)\b[^.!?\n]{0,40}\b(to|at)\b\s+(https?://|[a-z0-9._%+-]+@)`)},
	// An image whose address waits to be filled in: how an answer is made
	// to carry what it knows to somebody else's server.
	{"asks the answer to carry a link or image",
		regexp.MustCompile(`(?i)!\[[^\]]*\]\(\s*https?://[^)\s]*(\[|\{|<|%5b|%7b|%3c|\$)|\b(include|add|append|render|embed)\b[^.!?\n]{0,30}\b(this|the following)\b[^.!?\n]{0,15}\b(image|link|url)\b[^.!?\n]{0,30}\b(in|to|at the end of)\b[^.!?\n]{0,15}\b(every|each|your|all)\b[^.!?\n]{0,10}\b(answers?|responses?|repl(y|ies))\b`)},
}

// Screen is why a passage reads as addressed to an AI, or nothing.
func Screen(text string) []string {
	var out []string
	for _, r := range screenRules {
		if r.re.MatchString(text) {
			out = append(out, r.why)
		}
	}
	return out
}

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
