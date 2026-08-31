package render

import "strings"

// A declared form, in the shape a template can render.
//
// # Why the page stopped listing the fields
//
// A form is declared once — its questions, their kinds, how long answers are
// kept, and the notice the sender is shown. A page said which form it carried,
// and then repeated the whole field list so the layout had something to iterate.
// Two lists of the same questions, kept in step by hand.
//
// They drift the first time somebody adds a question, and the drift is silent in
// the direction that matters: the page renders the old list, the sender submits
// it, and the server refuses because a required field they were never shown is
// missing. The refusal is deliberately uninformative — it is what a spam script
// is told — so the report is "the form does not work" with nothing to look at.
//
// It is also how a form comes out empty. A page carrying `form` and no `fields`
// rendered a heading, a button and the hidden honeypot: a form with no
// questions, which looks like a bug in the layout and is a missing list in the
// content.
//
// So the declaration is the only list. This turns it into plain maps — the only
// thing the template language reads — with one boolean per control, because the
// language cannot switch on a value.
type formData = map[string]any

// form resolves the form a page names.
//
// Nil when the page names none, when nothing wired a form set, or when the name
// matches no declaration: a template guards on `form` and renders nothing, which
// is the same behaviour as a page that never mentioned one. A name that matches
// nothing is reported by `quilzo form check` rather than rendered as an empty
// form nobody can submit.
func (s Sources) form(body any) formData {
	if s.Form == nil {
		return nil
	}
	m, ok := body.(map[string]any)
	if !ok {
		return nil
	}
	name, _ := m["form"].(string)
	if strings.TrimSpace(name) == "" {
		return nil
	}
	return s.Form(name)
}

// FormField is what one question becomes for a template.
//
// Exported so a host can build this from its own form package without this
// package importing it — internal/render knows about pages and layouts, and a
// retention period is not either.
type FormField struct {
	Name     string
	Label    string
	Help     string
	Required bool
	// Exactly one of these is true, because the template language has no
	// switch: a layout writes one conditional per control and the data says
	// which one applies.
	Textarea bool
	Checkbox bool
	Choices  []string
	// Type is the input type for the ordinary case: text, email, number.
	Type string
}

// FormOf assembles the data a layout needs from a declaration's parts.
//
// A function rather than a method so the host can call it with whatever its own
// form type holds, keeping the shape in one place: a second assembler is a
// second answer to "what does a form look like to a template".
func FormOf(name, label, intro, notice, submit string, fields []FormField) formData {
	items := make([]any, 0, len(fields))
	for _, f := range fields {
		item := map[string]any{
			"name": f.Name, "label": f.Label, "help": f.Help,
			"required": f.Required,
		}
		switch {
		case len(f.Choices) > 0:
			choices := make([]any, 0, len(f.Choices))
			for _, c := range f.Choices {
				choices = append(choices, c)
			}
			item["choices"] = choices
		case f.Textarea:
			item["textarea"] = true
		case f.Checkbox:
			item["checkbox"] = true
		default:
			t := f.Type
			if t == "" {
				t = "text"
			}
			item["type"] = t
		}
		items = append(items, item)
	}
	if submit == "" {
		submit = "Send"
	}
	if label == "" {
		label = name
	}
	return formData{
		"name": name, "title": label, "intro": intro, "notice": notice,
		"submit": submit, "fields": items,
	}
}
