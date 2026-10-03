// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/form"
)

func toolSite(t *testing.T) *Site {
	t.Helper()
	st := &Site{}
	set := &assistant.Set{}
	_ = set.Put(assistant.Assistant{Name: "help", Title: `Ask "Marginalia"`, Public: true})
	_ = set.Put(assistant.Assistant{Name: "draft", Title: "Unreleased", Public: false})
	st.Assistants = &Assistants{Set: func() (*assistant.Set, error) { return set, nil }}
	forms := &form.Set{Forms: []form.Form{
		{Name: "contact", Label: `Write to us <script>x</script>`, Notice: "We keep this for 90 days.", Fields: []form.Field{
			{Name: "email", Label: "Your email", Kind: form.Email, Required: true},
			{Name: "topic", Label: "Topic", Kind: form.Choice, Choices: []string{"Orders", "Wholesale"}},
		}},
		{Name: "card", Label: "Pay", Notice: "n", Fields: []form.Field{{Name: "number", Label: "Card", Kind: form.Line, Sensitive: true}}},
		{Name: "old", Label: "Old", Notice: "n", Closed: true, Fields: []form.Field{{Name: "x", Label: "X", Kind: form.Line}}},
	}}
	st.Forms = &Forms{Set: func() (*form.Set, error) { return forms, nil }}
	return st
}

func TestSearchAndChatbotsAreToolsAnAgentMayRun(t *testing.T) {
	st := toolSite(t)
	out := st.annotateTools(`<form class="search" method="get" action="/search" role="search"><input id="q" name="q" type="search"></form>` +
		`<form class="ask-form" method="get" action="/ask/help/"><input id="ask" name="q" type="text"></form>` +
		`<form class="ask-suggestions" method="get" action="/ask/help/"><button name="q" value="x">x</button></form>`)
	for _, want := range []string{
		`action="/search" role="search" toolname="search-site" tooldescription="Search this site&#39;s published pages`,
		`toolautosubmit><input id="q" name="q" type="search" toolparamdescription="Words to look for.`,
		`toolname="ask-help" tooldescription="Ask &#34;Marginalia&#34;: answers a question from this site&#39;s published pages only`,
		`<input id="ask" name="q" type="text" toolparamdescription="The question, in plain words.">`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Count(out, "toolname=") != 2 {
		t.Errorf("the suggestions form, which has no question box, became a tool:\n%s", out)
	}
	if out := st.annotateTools(`<form method="get" action="/ask/draft/"><input name="q"></form>`); strings.Contains(out, "toolname") {
		t.Error("a chatbot the site does not serve was offered as a tool")
	}
}

// A form that sends something is filled in by the agent and submitted by
// the visitor; one with a sensitive field, or closed, is not offered.
func TestADeclaredFormIsAToolTheVisitorSubmits(t *testing.T) {
	st := toolSite(t)
	out := st.annotateTools(`<form method="post" action="/form/contact"><input type="hidden" name="email" value="trap">` +
		`<input id="e" name="email" type="email" required><select name="topic"><option>Orders</option></select>` +
		`<input name="` + form.Honeypot + `" tabindex="-1"><button>Send</button></form>`)
	if !strings.Contains(out, `toolname="form-contact"`) || strings.Contains(out, "toolautosubmit") {
		t.Fatalf("a declared form: %s", out)
	}
	if !strings.Contains(out, `tooldescription="Write to us &lt;script&gt;x&lt;/script&gt;. Sends what is filled in`) {
		t.Errorf("the description is not the escaped label: %s", out)
	}
	if !strings.Contains(out, `<input id="e" name="email" type="email" required toolparamdescription="Your email. Required">`) ||
		!strings.Contains(out, `<select name="topic" toolparamdescription="Topic. One of: Orders, Wholesale">`) {
		t.Errorf("fields are not described: %s", out)
	}
	if strings.Contains(out, `value="trap" toolparam`) || strings.Contains(out, `tabindex="-1" toolparam`) {
		t.Errorf("a hidden or undeclared field was described: %s", out)
	}
	// The honeypot is read-only in a tool, so an agent leaves it out and a
	// genuine visitor's agent-filled enquiry is not refused as spam.
	if !strings.Contains(out, `<input name="`+form.Honeypot+`" tabindex="-1" readonly>`) {
		t.Errorf("the honeypot would be filled by an agent: %s", out)
	}
	for _, f := range []string{"card", "old"} {
		if out := st.annotateTools(`<form method="post" action="/form/` + f + `"><input name="number"></form>`); strings.Contains(out, "toolname") {
			t.Errorf("the %s form was offered", f)
		}
	}
	for _, other := range []string{`<form method="post" action="/board/talk"><textarea name="body"></textarea></form>`,
		`<form method="post" action="/account/delete"><input name="confirm"></form>`} {
		if out := st.annotateTools(other); strings.Contains(out, "toolname") {
			t.Errorf("an account or posting form was offered: %s", out)
		}
	}
}

func TestAnOwnersOwnToolAndOddMarkupAreLeftAlone(t *testing.T) {
	st := toolSite(t)
	own := `<form action="/search" toolname="find" tooldescription="Mine"><input name="q"></form>`
	if out := st.annotateTools(own); out != own {
		t.Errorf("an owner's tool was changed: %s", out)
	}
	odd := `<formula>x</formula><form data-x="a>b" action="/search"><input value="1>0" name="q"></form>`
	out := st.annotateTools(odd)
	if !strings.Contains(out, `<formula>x</formula>`) || !strings.Contains(out, `data-x="a>b" action="/search" toolname="search-site"`) ||
		!strings.Contains(out, `<input value="1>0" name="q" toolparamdescription=`) {
		t.Errorf("odd markup: %s", out)
	}
	if out := st.annotateTools(`<form action="/search"><input name="q"`); !strings.Contains(out, `<form action="/search"><input name="q"`) {
		t.Errorf("an unfinished tag was mangled: %s", out)
	}
	st.ToolsOff = true
	if out := st.annotateTools(`<form action="/search"><input name="q"></form>`); strings.Contains(out, "toolname") {
		t.Error("tools were marked with the setting off")
	}
}

func TestTheConversationPageIsATool(t *testing.T) {
	st, _ := askSite(t, shopBot)
	body := get(st, "/ask/help", nil).Body.String()
	if !strings.Contains(body, `toolname="ask-help"`) || !strings.Contains(body, `toolparamdescription="The question, in plain words."`) {
		t.Errorf("the conversation page is not a tool")
	}
	if body := get(st, "/ask/help?embed=1", nil).Body.String(); strings.Contains(body, "toolname=") {
		t.Error("a framed conversation was offered as a tool of the page around it")
	}
	st.ToolsTrial = "AqZ1abc+/="
	if h := get(st, "/returns", nil).Header().Get("Origin-Trial"); h != "AqZ1abc+/=" {
		t.Errorf("the origin trial token was not sent: %q", h)
	}
}
