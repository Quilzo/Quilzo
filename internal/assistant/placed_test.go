// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assistant

import (
	"context"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/section"
)

// -- question boxes -----------------------------------------------------------

func box(name any, title string) map[string]any {
	inner := map[string]any{"title": title}
	if name != nil {
		inner[BoxField] = name
	}
	return map[string]any{SectionKind: inner}
}

// A box opening a chatbot that does not exist, or is not public, or names
// none, is found and said where it is; one opening a public chatbot is not.
func TestAQuestionBoxThatOpensNothingIsFound(t *testing.T) {
	set := &Set{}
	for _, a := range []Assistant{
		{Name: "help", Title: "Help", Public: true},
		{Name: "draft-bot", Title: "Not yet"},
	} {
		if err := set.Put(a); err != nil {
			t.Fatal(err)
		}
	}
	pages := map[string]any{
		"contact": map[string]any{"title": "Contact", "sections": []any{
			map[string]any{"prose": map[string]any{"title": "Write to us"}},
			box("help", "Ask a question"),
			box("helpp", "Ask another"),
		}},
		"about": map[string]any{"sections": []any{
			box("draft-bot", ""),
			box(nil, "Ask"),
			box(" help", "Spaced"),
			box(7.0, "A number"),
		}},
		"plain": map[string]any{"title": "No sections at all"},
	}
	got := set.Boxes(pages)
	var said []string
	for _, b := range got {
		said = append(said, b.Page+": "+b.String())
	}
	want := []string{
		`about: section 1: the question box opens the chatbot draft-bot, which is not public`,
		`about: section 2 (Ask): the question box names no chatbot`,
		`about: section 3 (Spaced): the question box opens the chatbot " help", which does not exist`,
		`about: section 4 (A number): the question box names no chatbot`,
		`contact: section 3 (Ask another): the question box opens the chatbot "helpp", which does not exist`,
	}
	if len(said) != len(want) {
		t.Fatalf("found %d boxes, want %d:\n  %s", len(said), len(want), strings.Join(said, "\n  "))
	}
	for i := range want {
		if !strings.HasPrefix(said[i], want[i]) {
			t.Errorf("box %d:\n  got  %s\n  want %s…", i, said[i], want[i])
		}
	}
}

// A site with no question boxes never asks for its chatbots, so a gate
// that reads a file to answer reads nothing.
func TestBoxesAsksOnlyAboutBoxesThatNameSomething(t *testing.T) {
	asked := 0
	find := func(string) (Assistant, bool) { asked++; return Assistant{}, false }
	Boxes(map[string]any{
		"index": map[string]any{"sections": []any{map[string]any{"prose": map[string]any{}}}},
		"about": map[string]any{"sections": []any{box("", "Empty")}},
	}, find)
	if asked != 0 {
		t.Fatalf("asked about %d chatbot(s) on pages that name none", asked)
	}
}

// The kind this package looks for and the kind a screen can add are the
// same, and the field it reads is the one the stub writes. A catalogue
// entry renamed on its own would leave every box unchecked, with nothing
// failing anywhere.
func TestTheQuestionBoxIsTheCataloguesAskSection(t *testing.T) {
	k, ok := section.Lookup(SectionKind)
	if !ok {
		t.Fatalf("this package reads a %q section and the catalogue does not "+
			"offer one", SectionKind)
	}
	if _, ok := k.Stub[BoxField]; !ok {
		t.Errorf("the %q stub has no %q field, so a box added from a screen "+
			"does not say which chatbot it opens", SectionKind, BoxField)
	}
	if section.Field != sectionsField {
		t.Errorf("sections live under %q and this reads %q", section.Field, sectionsField)
	}
}

// -- offers ---------------------------------------------------------------------

// Without a model nothing is offered, however the question asks for it,
// and the sentence every surface shows says so.
func TestActionsAreOfferedOnlyWithAModel(t *testing.T) {
	a := withActions()
	ans, err := Respond(context.Background(), a, shopIndex(t, a), nil,
		"I want to return my order, can I return unopened items")
	if err != nil {
		t.Fatal(err)
	}
	if ans.Proposed != nil {
		t.Fatalf("an extractive answer offered %s", ans.Proposed.Action.Name)
	}
	if why := WhyNoOffers(a, nil, "extractive by declaration"); !strings.HasPrefix(why, ActionsNeedModel) ||
		!strings.Contains(why, "without one") {
		t.Errorf("an extractive chatbot: %q", why)
	}
	a.UseModel = true
	if why := WhyNoOffers(a, nil, "no model configured: no key"); !strings.Contains(why, "no key") {
		t.Errorf("a chatbot meant to use a model that cannot: %q", why)
	}
	if why := WhyNoOffers(a, nil, ""); !strings.Contains(why, "none is configured") {
		t.Errorf("no reason given: %q", why)
	}
	if why := WhyNoOffers(a, &scripted{}, ""); why != "" {
		t.Errorf("a chatbot with a model was told it offers nothing: %q", why)
	}
}

func returnsForms() *form.Set {
	return &form.Set{Forms: []form.Form{{
		Name: "returns-form", Notice: "We use this to process the return.",
		Fields: []form.Field{
			{Name: "order", Label: "Order", Kind: form.Line},
			{Name: "reason", Label: "Reason", Kind: form.Para},
			{Name: "card", Label: "Card for the refund", Kind: form.Line, Sensitive: true},
		},
	}}}
}

// A form action is checked against the form it fills in: one that is not
// there, or a field it does not ask for, is refused with what there is;
// a sensitive field is let through and named, because it is never filled.
func TestAFormActionIsCheckedAgainstItsForm(t *testing.T) {
	ret := Action{Name: "start-return", Kind: Form, Target: "returns-form",
		Description: "start a return", Fields: []string{"order", "reason"}}
	if s, err := ret.CheckForm(returnsForms()); err != nil || len(s) != 0 {
		t.Fatalf("a good action: %v %v", s, err)
	}

	missing := ret
	missing.Target = "refunds"
	_, err := missing.CheckForm(returnsForms())
	if err == nil || !strings.Contains(err.Error(), `"refunds"`) || !strings.Contains(err.Error(), "returns-form") {
		t.Errorf("a form that is not there: %v", err)
	}
	if _, err := missing.CheckForm(nil); err == nil || !strings.Contains(err.Error(), "no forms yet") {
		t.Errorf("a site with no forms: %v", err)
	}

	stray := ret
	stray.Fields = []string{"order", "email"}
	_, err = stray.CheckForm(returnsForms())
	if err == nil || !strings.Contains(err.Error(), "email") ||
		!strings.Contains(err.Error(), "order, reason;") || !strings.Contains(err.Error(), SensitiveNever) {
		t.Errorf("a field the form does not ask for: %v", err)
	}

	secret := ret
	secret.Fields = []string{"order", "card"}
	s, err := secret.CheckForm(returnsForms())
	if err != nil || len(s) != 1 || s[0] != "card" {
		t.Fatalf("a sensitive field: %v %v", s, err)
	}
	if note := SensitiveNote(secret, s); !strings.Contains(note, "card") || !strings.Contains(note, SensitiveNever) {
		t.Errorf("the note: %q", note)
	}

	// A link names a page, and is not a form's to answer for.
	link := Action{Name: "contact", Kind: Link, Target: "contact", Description: "talk to us"}
	if _, err := link.CheckForm(nil); err != nil {
		t.Errorf("a link was checked as a form: %v", err)
	}

	a := withActions()
	if err := a.CheckForms(returnsForms()); err != nil {
		t.Errorf("a chatbot whose actions all work: %v", err)
	}
	a.Actions = append(a.Actions, stray)
	a.Actions[len(a.Actions)-1].Name = "stray"
	if err := a.CheckForms(returnsForms()); err == nil || !strings.HasPrefix(err.Error(), "helper: action stray") {
		t.Errorf("one action that does not: %v", err)
	}
}
