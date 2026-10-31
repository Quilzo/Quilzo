// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assistant

import (
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/form"
)

// What an action needs before any visitor is offered it.
//
// Validate checks an action on its own: a kind it knows, a target on this
// site, a form action that names a field. Two things it cannot see broke
// actions silently. Only a model chooses an action, so one declared on a
// chatbot that answers without a model is a row on the owner's screen that
// no visitor ever sees. And a form action is pre-filled by name, so a form
// that does not exist is an offer the public site drops without a word, and
// a field the form does not ask for is one nobody is ever shown. Each
// declaration looked right where it was made and did nothing.

// ActionsNeedModel is what every surface says about a chatbot's actions
// when it will not offer them, in the same words, so that the screen, the
// command line and the agent interface are recognisably saying one thing.
const ActionsNeedModel = "Actions are offered only when this chatbot answers with a model"

// WhyNoOffers says why a chatbot's actions will never be offered, or
// nothing when they can be.
//
// m and why are what its model came to: nil and the reason when there is
// none, whether because it was declared extractive or because nothing is
// configured to answer. The extractive answer quotes sentences from pages
// and has nothing to choose an action with (see RespondTo).
func WhyNoOffers(a Assistant, m Model, why string) string {
	if m != nil {
		return ""
	}
	if !a.UseModel {
		return ActionsNeedModel + ", and this one quotes its pages without one"
	}
	if strings.TrimSpace(why) == "" {
		why = "none is configured"
	}
	return ActionsNeedModel + ", and none can be used: " + why
}

// SensitiveNever is what every surface says about the fields a chatbot
// may not fill in, wherever an action lists them.
const SensitiveNever = "a field marked sensitive is never filled in: the visitor types it"

// CheckForm refuses a form action whose form the site does not have, or
// which may fill in a field that form does not ask for. A link is not
// checked here: it names a page, and whether that page is published is a
// question about the site on the day, which the public site answers.
//
// What comes back on success is the fields it lists that the form marks
// sensitive. They are not refused, because listing one does no harm —
// offerFor in internal/public leaves it empty whatever the model wrote —
// but nobody should believe they will be filled, so the caller says so.
func (ac Action) CheckForm(forms *form.Set) (sensitive []string, err error) {
	if ac.Kind != Form {
		return nil, nil
	}
	var f *form.Form
	if forms != nil {
		f, _ = forms.Get(ac.Target)
	}
	if f == nil {
		have := "This site has no forms yet"
		if forms != nil && len(forms.Forms) > 0 {
			have = "Its forms are " + strings.Join(forms.Names(), ", ")
		}
		return nil, fmt.Errorf("action %s fills in the form %q, which this "+
			"site does not have, so it would never be offered. %s",
			ac.Name, ac.Target, have)
	}
	asks := map[string]form.Field{}
	var may []string
	for _, fl := range f.Fields {
		asks[fl.Name] = fl
		if !fl.Sensitive {
			may = append(may, fl.Name)
		}
	}
	var unknown []string
	for _, name := range ac.Fields {
		fl, ok := asks[name]
		switch {
		case !ok:
			unknown = append(unknown, name)
		case fl.Sensitive:
			sensitive = append(sensitive, name)
		}
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("action %s may fill in %s, which the form %s "+
			"does not ask for. It may fill in %s; %s",
			ac.Name, strings.Join(unknown, ", "), f.Name, orNothing(may),
			SensitiveNever)
	}
	return sensitive, nil
}

// CheckForms is CheckForm for every action a chatbot declares, for the
// places that take a whole declaration at once rather than one action.
func (a Assistant) CheckForms(forms *form.Set) error {
	for _, ac := range a.Actions {
		if _, err := ac.CheckForm(forms); err != nil {
			return fmt.Errorf("%s: %w", a.Name, err)
		}
	}
	return nil
}

// SensitiveNote is what to say about the sensitive fields an action lists,
// or nothing when it lists none.
func SensitiveNote(ac Action, sensitive []string) string {
	if len(sensitive) == 0 {
		return ""
	}
	return fmt.Sprintf("The form %s marks %s sensitive, and %s",
		ac.Target, strings.Join(sensitive, ", "), SensitiveNever)
}

func orNothing(names []string) string {
	if len(names) == 0 {
		return "nothing"
	}
	return strings.Join(names, ", ")
}
