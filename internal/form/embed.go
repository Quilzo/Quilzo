package form

import (
	"fmt"
	"html"
	"strings"
)

// The markup a form needs, written out for the person who has to embed it.
//
// A form declared here is answered by a template somebody writes, and two of
// the fields it must carry are not fields anybody declared: the honeypot and
// the timestamp. Both are named by constants in this package, both are refused
// when absent, and until now neither appeared anywhere a user could see —
// not on the screen that builds forms, not in the manual.
//
// The result was a form that could be built entirely through the interface and
// could not be made to work. Every submission came back "this submission was
// not accepted", which is deliberately uninformative because it is the answer
// a spam script gets, and there was no other answer to find. The only way to
// learn the field names was to read the Go source.
//
// So the screen prints the markup. Not a description of the markup — the
// markup, with the fields in it, ready to paste. A rule the product enforces
// and does not state is a rule that reads as a bug.

// Embed returns the HTML for one form, as a template author should write it.
//
// The action is a relative path, so the same markup works on any origin the
// site is served from. Nothing here is a template: the values are already
// escaped and the output is meant to be copied, edited and owned by whoever
// pastes it.
func Embed(f *Form) string {
	var b strings.Builder
	id := func(name string) string { return "f-" + f.Name + "-" + name }

	fmt.Fprintf(&b, "<form method=\"post\" action=\"/form/%s\">\n", esc(f.Name))

	for _, fl := range f.Fields {
		label := fl.Label
		if label == "" {
			label = fl.Name
		}
		req := ""
		if fl.Required {
			req = " required"
		}
		fmt.Fprintf(&b, "  <p>\n    <label for=\"%s\">%s</label>\n",
			esc(id(fl.Name)), esc(label))

		switch fl.Kind {
		case Para:
			fmt.Fprintf(&b,
				"    <textarea id=\"%s\" name=\"%s\" rows=\"5\"%s></textarea>\n",
				esc(id(fl.Name)), esc(fl.Name), req)
		case Choice:
			fmt.Fprintf(&b, "    <select id=\"%s\" name=\"%s\"%s>\n",
				esc(id(fl.Name)), esc(fl.Name), req)
			for _, c := range fl.Choices {
				fmt.Fprintf(&b, "      <option>%s</option>\n", esc(c))
			}
			b.WriteString("    </select>\n")
		case Agree:
			fmt.Fprintf(&b,
				"    <input id=\"%s\" name=\"%s\" type=\"checkbox\" value=\"true\"%s>\n",
				esc(id(fl.Name)), esc(fl.Name), req)
		default:
			fmt.Fprintf(&b,
				"    <input id=\"%s\" name=\"%s\" type=\"%s\"%s>\n",
				esc(id(fl.Name)), esc(fl.Name), inputType(fl.Kind), req)
		}
		if fl.Help != "" {
			fmt.Fprintf(&b, "    <span class=\"hint\">%s</span>\n", esc(fl.Help))
		}
		b.WriteString("  </p>\n")
	}

	// The two fields nobody declared and everybody needs.
	fmt.Fprintf(&b, `
  <!-- Required. The honeypot: a person never sees this, and anything that
       fills in every field it finds does. Keep it off-screen with CSS rather
       than display:none, and keep it out of the accessibility tree, or a
       screen reader user will fill it in and be silently refused. -->
  <p style="position:absolute;left:-9999px" aria-hidden="true">
    <label for="%s">Leave this empty</label>
    <input id="%s" name="%s" type="text" tabindex="-1" autocomplete="off">
  </p>

  <!-- Required. When the form was shown, as a unix timestamp. A submission
       arriving less than %d seconds after this, or without it at all, is
       refused — so removing the field is not a way around the check. -->
  <input type="hidden" name="%s" value="UNIX_TIMESTAMP_WHEN_RENDERED">
`,
		esc(Honeypot), esc(Honeypot), esc(Honeypot),
		MinFillSeconds, esc(StampField))

	if f.Notice != "" {
		fmt.Fprintf(&b, "\n  <p class=\"privacy\">%s</p>\n", esc(f.Notice))
	}
	b.WriteString("\n  <p><button type=\"submit\">Send</button></p>\n</form>\n")
	return b.String()
}

// inputType maps a kind onto the input type that gets the right keyboard on a
// phone and the right validation in the browser. It is a convenience for the
// person filling the form in; the server checks the value regardless.
func inputType(k Kind) string {
	switch k {
	case Email:
		return "email"
	case Number:
		return "number"
	}
	return "text"
}

func esc(s string) string { return html.EscapeString(s) }
