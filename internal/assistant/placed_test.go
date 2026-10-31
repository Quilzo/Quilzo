// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assistant

import (
	"context"
	"errors"
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

// Taking a chatbot away from visitors is refused while a box on a live or
// a draft page opens it, naming each; a chatbot no box opens, and a box
// that opened nothing before the change, are not this change's to refuse.
func TestAChatbotABoxOpensIsNotTakenAway(t *testing.T) {
	before := &Set{}
	for _, a := range []Assistant{
		{Name: "help", Title: "Help", Public: true},
		{Name: "shop", Title: "Shop", Public: true},
		{Name: "spare", Title: "Spare", Public: true},
		{Name: "draft-bot", Title: "Not yet"},
	} {
		if err := before.Put(a); err != nil {
			t.Fatal(err)
		}
	}
	was := before.PublicNames()
	live := map[string]any{"index": map[string]any{"sections": []any{box("help", "Ask us")}}}
	draft := map[string]any{
		"index": map[string]any{"sections": []any{box("shop", "")}},
		"about": map[string]any{"sections": []any{box("helpp", "Typo"), box("draft-bot", "")}},
	}
	after := func(change func(*Set)) *Set {
		s := &Set{Assistants: append([]Assistant(nil), before.Assistants...)}
		change(s)
		return s
	}

	private := after(func(s *Set) {
		a, _ := s.Get("help")
		a.Public = false
		_ = s.Put(a)
		s.Remove("shop")
	})
	err := private.Withdraws(was, live, draft)
	var e *Withdrawn
	if !errors.As(err, &e) {
		t.Fatalf("taking two chatbots that boxes open away was not refused: %v", err)
	}
	if strings.Join(e.Names, ",") != "help,shop" || len(e.Where) != 2 ||
		e.Where[0] != "the live page index, section 1 (Ask us), opens help" ||
		e.Where[1] != "the draft page index, section 1, opens shop" {
		t.Errorf("what the refusal names: %q %q", e.Names, e.Where)
	}
	if !strings.Contains(err.Error(), "removing them or making them private") {
		t.Errorf("the refusal: %v", err)
	}

	if err := after(func(s *Set) { s.Remove("spare") }).Withdraws(was, live, draft); err != nil {
		t.Errorf("a chatbot no box opens was refused: %v", err)
	}
	unrelated := after(func(s *Set) {
		a, _ := s.Get("spare")
		a.Title = "Spare, renamed"
		_ = s.Put(a)
	})
	if err := unrelated.Withdraws(was, live, draft); err != nil {
		t.Errorf("a change that takes nothing away was refused over boxes that already opened nothing: %v", err)
	}
	if err := private.Withdraws(was, nil, nil); err != nil {
		t.Errorf("a site with no pages yet was refused: %v", err)
	}
}

// A new question box opens the first chatbot visitors can reach, and none
// when there is none.
func TestANewBoxOpensTheFirstPublicChatbot(t *testing.T) {
	set := &Set{}
	if set.FirstPublic() != "" {
		t.Fatal("an empty set offered a chatbot")
	}
	for _, a := range []Assistant{{Name: "a-draft", Title: "Not yet"}, {Name: "shop", Title: "Shop", Public: true}} {
		if err := set.Put(a); err != nil {
			t.Fatal(err)
		}
	}
	if got := set.FirstPublic(); got != "shop" {
		t.Errorf("the first public chatbot is %q, want shop", got)
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
// a sensitive field is let through and named, because it is never filled,
// and so is a closed form, because nothing is offered until it reopens.
func TestAFormActionIsCheckedAgainstItsForm(t *testing.T) {
	ret := Action{Name: "start-return", Kind: Form, Target: "returns-form",
		Description: "start a return", Fields: []string{"order", "reason"}}
	if notes, err := ret.CheckForm(returnsForms()); err != nil || len(notes) != 0 {
		t.Fatalf("a good action: %q %v", notes, err)
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
	notes, err := secret.CheckForm(returnsForms())
	if err != nil || len(notes) != 1 || !strings.Contains(notes[0], "marks card sensitive") ||
		!strings.Contains(notes[0], SensitiveNever) {
		t.Fatalf("a sensitive field: %q %v", notes, err)
	}

	closed := returnsForms()
	closed.Forms[0].Closed = true
	notes, err = ret.CheckForm(closed)
	if err != nil || len(notes) != 1 || !strings.Contains(notes[0], "returns-form is closed") ||
		!strings.Contains(notes[0], "start-return is not offered") {
		t.Errorf("a closed form: %q %v", notes, err)
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
