// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"html"
	"net/http"
	"strings"

	"github.com/quilzo/quilzo/internal/form"
)

// The site's forms as tools a visitor's browser agent can use (WebMCP).
//
// # What changes
//
// WebMCP lets a page declare, on an ordinary form, that the form is a tool:
// a name, what it does, and what each field means. A browser agent acting
// for the visitor then fills and submits the form instead of guessing at
// the page from a screenshot. Google and Microsoft wrote the specification
// together; Chrome runs it in an origin trial from Chrome 149. Browsers that
// do not know the attributes ignore them, so this costs nothing anywhere.
//
// It is declarative — attributes on HTML this site already serves — so no
// script runs, the policy does not change, and a form works exactly as it
// did for everybody else.
//
// # What becomes a tool, and what may happen without the visitor
//
//   - Site search and asking a chatbot read and change nothing, so they are
//     marked toolautosubmit: an agent may run them on its own.
//   - A form the site declares — an enquiry, a booking — sends something to
//     the business, so the agent fills it in and the visitor submits it,
//     which is what WebMCP's security guidance asks of anything
//     consequential. A form with a sensitive field is not offered at all.
//   - Account and posting forms are left alone: what a person says in their
//     own name, and their own account, are theirs to operate.
//
// Every description comes from what the owner declared — the form's label
// and notice, each field's label and help — never from a model, and is
// escaped for the attribute it lands in.

// toolSpec is what one form becomes.
type toolSpec struct {
	name, description string
	auto              bool
	params            map[string]string
	// trap is the form's honeypot, made read-only so an agent leaves it
	// out of the tool. Chrome builds the tool from every control that is
	// not hidden, disabled or read-only — the honeypot included, which an
	// agent would then fill and the form would refuse as spam. A script
	// posting the form ignores the attribute and still falls in.
	trap string
}

// annotateTools marks the page's forms as tools. A form that already says
// what tool it is keeps what it says: an owner's template wins.
func (st *Site) annotateTools(page string) string {
	if st.ToolsOff {
		return page
	}
	var forms *form.Set
	if st.Forms != nil && st.Forms.Set != nil {
		forms, _ = st.Forms.Set()
	}
	var b strings.Builder
	rest := page
	for {
		at := indexFold(rest, "<form")
		if at < 0 {
			b.WriteString(rest)
			break
		}
		end, ok := tagEnd(rest, at)
		if !ok || !isTagBoundary(rest, at+len("<form")) {
			b.WriteString(rest[:at+len("<form")])
			rest = rest[at+len("<form"):]
			continue
		}
		tag := rest[at:end]
		attrs := tagAttrs(tag)
		closeAt := indexFold(rest[end:], "</form")
		if closeAt < 0 {
			closeAt = len(rest) - end
		}
		body := rest[end : end+closeAt]
		spec, ok := st.toolFor(attrs, body, forms)
		if !ok || attrs["toolname"] != "" {
			b.WriteString(rest[:end+closeAt])
			rest = rest[end+closeAt:]
			continue
		}
		b.WriteString(rest[:end-1])
		b.WriteString(` toolname=` + quoteAttr(spec.name) + ` tooldescription=` + quoteAttr(spec.description))
		if spec.auto {
			b.WriteString(` toolautosubmit`)
		}
		b.WriteString(">")
		b.WriteString(annotateParams(body, spec.params, spec.trap))
		rest = rest[end+closeAt:]
	}
	return b.String()
}

// toolFor decides what a form is, from where it sends.
func (st *Site) toolFor(attrs map[string]string, body string, forms *form.Set) (toolSpec, bool) {
	action := attrs["action"]
	method := strings.ToLower(attrs["method"])
	switch {
	case action == "/search" && (method == "" || method == "get"):
		if !hasField(body, "q") {
			return toolSpec{}, false
		}
		return toolSpec{name: "search-site", auto: true,
			description: "Search this site's published pages by keyword and list the pages that match.",
			params:      map[string]string{"q": "Words to look for. Every word has to appear on a page for it to match."}}, true
	case strings.HasPrefix(action, "/ask/"):
		name := strings.Trim(strings.TrimPrefix(action, "/ask/"), "/")
		if !validAssistantName(name) || !hasField(body, "q") || strings.Contains(attrs["class"], "ask-suggestions") {
			return toolSpec{}, false
		}
		title := "this site's assistant"
		if st.Assistants != nil && st.Assistants.Set != nil {
			if set, err := st.Assistants.Set(); err == nil && set != nil {
				a, ok := set.Get(name)
				if !ok || !a.Public {
					return toolSpec{}, false
				}
				title = a.Title
			}
		}
		return toolSpec{name: "ask-" + name, auto: true,
			description: title + ": answers a question from this site's published pages only, and every sentence links to the page it came from.",
			params:      map[string]string{"q": "The question, in plain words."}}, true
	case strings.HasPrefix(action, "/form/"):
		name := strings.Trim(strings.TrimPrefix(action, "/form/"), "/")
		if forms == nil {
			return toolSpec{}, false
		}
		f, ok := forms.Get(name)
		if !ok || f.Closed {
			return toolSpec{}, false
		}
		params := map[string]string{}
		for _, fd := range f.Fields {
			if fd.Sensitive {
				// Not offered: an agent filling in a card number or a
				// health question is not a convenience this site adds.
				return toolSpec{}, false
			}
			d := fd.Label
			if fd.Help != "" {
				d += ". " + fd.Help
			}
			if len(fd.Choices) > 0 {
				d += ". One of: " + strings.Join(fd.Choices, ", ")
			}
			if fd.Required {
				d += ". Required"
			}
			params[fd.Name] = d
		}
		label := f.Label
		if label == "" {
			label = f.Name
		}
		desc := label + ". Sends what is filled in to the business; the visitor reviews it and submits it themselves."
		if t := f.Told(); t != "" {
			desc += " " + t
		}
		return toolSpec{name: "form-" + name, description: desc, params: params, trap: form.Honeypot}, true
	}
	return toolSpec{}, false
}

// quoteAttr is a value as a double-quoted attribute. Escaped for HTML, and
// the double quote replaced by name as well, so it is plain to anybody
// reading this — and to a checker — that nothing a form's owner wrote can
// end the attribute it sits in.
func quoteAttr(v string) string {
	return `"` + strings.ReplaceAll(html.EscapeString(v), `"`, "&#34;") + `"`
}

func validAssistantName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// annotateParams describes each named control the tool takes.
func annotateParams(body string, params map[string]string, trap string) string {
	if len(params) == 0 && trap == "" {
		return body
	}
	var b strings.Builder
	rest := body
	for {
		at := -1
		for _, t := range []string{"<input", "<textarea", "<select"} {
			if i := indexFold(rest, t); i >= 0 && (at < 0 || i < at) && isTagBoundary(rest, i+len(t)) {
				at = i
			}
		}
		if at < 0 {
			b.WriteString(rest)
			return b.String()
		}
		end, ok := tagEnd(rest, at)
		if !ok {
			b.WriteString(rest)
			return b.String()
		}
		tag := rest[at:end]
		attrs := tagAttrs(tag)
		if trap != "" && attrs["name"] == trap {
			if _, ro := attrs["readonly"]; !ro {
				cut := end - 1
				if strings.HasSuffix(tag, "/>") {
					cut = end - 2
				}
				b.WriteString(rest[:cut] + " readonly" + rest[cut:end])
				rest = rest[end:]
				continue
			}
		}
		d, want := params[attrs["name"]]
		if !want || attrs["toolparamdescription"] != "" || strings.EqualFold(attrs["type"], "hidden") {
			b.WriteString(rest[:end])
			rest = rest[end:]
			continue
		}
		cut := end - 1
		if strings.HasSuffix(tag, "/>") {
			cut = end - 2
		}
		b.WriteString(rest[:cut])
		b.WriteString(` toolparamdescription=` + quoteAttr(d))
		b.WriteString(rest[cut:end])
		rest = rest[end:]
	}
}

func hasField(body, name string) bool {
	rest := body
	for {
		at := -1
		for _, t := range []string{"<input", "<textarea", "<select"} {
			if i := indexFold(rest, t); i >= 0 && (at < 0 || i < at) {
				at = i
			}
		}
		if at < 0 {
			return false
		}
		end, ok := tagEnd(rest, at)
		if !ok {
			return false
		}
		if tagAttrs(rest[at:end])["name"] == name {
			return true
		}
		rest = rest[end:]
	}
}

// indexFold is strings.Index ignoring ASCII case in the needle's letters.
func indexFold(s, sub string) int {
	return strings.Index(strings.ToLower(s), sub)
}

// isTagBoundary reports whether the name ends at i: "<form " or "<form>",
// not "<formula".
func isTagBoundary(s string, i int) bool {
	if i >= len(s) {
		return false
	}
	switch s[i] {
	case ' ', '\t', '\n', '\r', '\f', '>', '/':
		return true
	}
	return false
}

// tagEnd is the index just past the start tag beginning at at, honouring
// quoted attribute values, which may hold a ">".
func tagEnd(s string, at int) (int, bool) {
	var quote byte
	for i := at + 1; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '>':
			return i + 1, true
		}
	}
	return 0, false
}

// tagAttrs reads a start tag's attributes, names lower-cased, values
// unescaped.
func tagAttrs(tag string) map[string]string {
	out := map[string]string{}
	s := strings.TrimSuffix(strings.TrimSuffix(tag, ">"), "/")
	i := strings.IndexAny(s, " \t\n\r\f")
	if i < 0 {
		return out
	}
	s = s[i:]
	for len(s) > 0 {
		s = strings.TrimLeft(s, " \t\n\r\f")
		if s == "" {
			break
		}
		j := strings.IndexAny(s, "= \t\n\r\f")
		if j < 0 {
			out[strings.ToLower(s)] = ""
			break
		}
		name := strings.ToLower(s[:j])
		s = strings.TrimLeft(s[j:], " \t\n\r\f")
		if !strings.HasPrefix(s, "=") {
			out[name] = ""
			continue
		}
		s = strings.TrimLeft(s[1:], " \t\n\r\f")
		var v string
		if s != "" && (s[0] == '"' || s[0] == '\'') {
			q := s[0]
			k := strings.IndexByte(s[1:], q)
			if k < 0 {
				v, s = s[1:], ""
			} else {
				v, s = s[1:1+k], s[2+k:]
			}
		} else {
			k := strings.IndexAny(s, " \t\n\r\f")
			if k < 0 {
				v, s = s, ""
			} else {
				v, s = s[:k], s[k:]
			}
		}
		if _, dup := out[name]; !dup {
			out[name] = html.UnescapeString(v)
		}
	}
	return out
}

// originTrial adds the WebMCP origin trial token, when the site has one, so
// Chrome turns WebMCP on for visitors before it is on by default.
func (st *Site) originTrial(h http.Header) {
	if t := strings.TrimSpace(st.ToolsTrial); t != "" && !st.ToolsOff {
		h.Add("Origin-Trial", t)
	}
}
