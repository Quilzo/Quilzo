// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/form"
)

// withBox is the example with a question box on its page opening name.
func withBox(t *testing.T, name string) *Package {
	t.Helper()
	p := sample(t)
	p.Pages[0].Body["sections"] = []any{map[string]any{"ask": map[string]any{
		"title": "Ask about samples", "assistant": name}}}
	return p
}

func conflictsOf(p *Package, st State, owned []Ref) string {
	return strings.Join(p.MakePlan(st, owned).Conflicts, "\n")
}

// A question box in a package opens a chatbot the package declares or the
// site has, and a public one, or the install is refused, naming the page
// and the section. A chatbot this package made and no longer declares is
// one the install removes, so it is not there to open.
func TestAPackagesQuestionBoxMustOpenAChatbotThatWillBeThere(t *testing.T) {
	site := func(a assistant.Assistant, owner string) State {
		st := State{Current: map[Ref]json.RawMessage{{"chatbot", a.Name}: raw(t, a)}, Owner: map[Ref]string{}}
		if owner != "" {
			st.Owner[Ref{"chatbot", a.Name}] = owner
		}
		return st
	}
	public := assistant.Assistant{Name: "help", Title: "Help", Public: true}
	private := assistant.Assistant{Name: "help", Title: "Help"}

	if got := conflictsOf(withBox(t, "help"), State{}, nil); !strings.Contains(got,
		`page samples, section 1 (Ask about samples): the question box opens the chatbot "help", which does not exist`) {
		t.Errorf("a box opening nothing: %q", got)
	}
	if got := conflictsOf(withBox(t, "help"), site(public, ""), nil); got != "" {
		t.Errorf("a box opening the site's public chatbot: %q", got)
	}
	if got := conflictsOf(withBox(t, "help"), site(private, ""), nil); !strings.Contains(got, "not public") {
		t.Errorf("a box opening the site's private chatbot: %q", got)
	}

	own := withBox(t, "help")
	own.Chatbots = []assistant.Assistant{public}
	if got := conflictsOf(own, State{}, nil); got != "" {
		t.Errorf("a box opening the package's own public chatbot: %q", got)
	}
	// The package's own declaration is what will be there, whatever the
	// site has now.
	own.Chatbots = []assistant.Assistant{private}
	if got := conflictsOf(own, site(public, "lab-samples"), []Ref{{"chatbot", "help"}}); !strings.Contains(got, "not public") {
		t.Errorf("a box opening the package's own private chatbot: %q", got)
	}

	// Made by this package, dropped from this version: removed by the
	// install, so not there to open.
	if got := conflictsOf(withBox(t, "help"), site(public, "lab-samples"), []Ref{{"chatbot", "help"}}); !strings.Contains(got, "does not exist") {
		t.Errorf("a box opening the chatbot this install removes: %q", got)
	}
}

// A package's chatbot action fills in a form the package declares or the
// site has, and only fields that form asks for.
func TestAPackagesChatbotActionMustFillInAFormThatIsThere(t *testing.T) {
	intake := form.Form{Name: "sample_intake", Notice: "To log the sample.",
		Fields: []form.Field{{Name: "sample", Label: "Sample", Kind: form.Line}}}
	bot := func(fields ...string) assistant.Assistant {
		return assistant.Assistant{Name: "lab", Title: "Ask the lab", Actions: []assistant.Action{{
			Name: "log-sample", Kind: assistant.Form, Target: "sample_intake",
			Description: "log a sample", Fields: fields}}}
	}

	p := sample(t)
	p.Chatbots = []assistant.Assistant{bot("sample")}
	if got := conflictsOf(p, State{}, nil); !strings.Contains(got, `chatbot lab: action log-sample fills in the form "sample_intake", which this site does not have`) {
		t.Errorf("an action filling in no form: %q", got)
	}
	st := State{Current: map[Ref]json.RawMessage{{"form", "sample_intake"}: raw(t, intake)}}
	if got := conflictsOf(p, st, nil); got != "" {
		t.Errorf("an action filling in the site's form: %q", got)
	}
	p.Forms = []form.Form{intake}
	if got := conflictsOf(p, State{}, nil); got != "" {
		t.Errorf("an action filling in the package's own form: %q", got)
	}
	p.Chatbots = []assistant.Assistant{bot("sample", "notes")}
	if got := conflictsOf(p, State{}, nil); !strings.Contains(got, "notes, which the form sample_intake does not ask for") {
		t.Errorf("an action filling in a field the form does not ask for: %q", got)
	}
}

// A built site's question box answers without a model, so it declares
// nothing it could only offer with one: an action there is a row on the
// Chatbots screen that no visitor is ever shown. Asked of the built start,
// of a drafted site with actions of its own, and of an imported one.
func TestABuiltQuestionBoxDeclaresNoActionItCannotOffer(t *testing.T) {
	idle := func(where string, a assistant.Assistant) {
		t.Helper()
		if !a.UseModel && len(a.Actions) > 0 {
			t.Errorf("%s: %s answers without a model and declares %d action(s): %s",
				where, a.Name, len(a.Actions), assistant.WhyNoOffers(a, nil, ""))
		}
	}
	brief := SiteBrief{Description: "A bakery in Leeds", Name: "Hart's Bakery"}
	start, err := BuildSite(brief, "dana", buildTime)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range start.Chatbots {
		idle("built", a)
	}
	if got := conflictsOf(start, State{}, nil); got != "" {
		t.Errorf("a built site does not install as it stands: %s", got)
	}

	answer := `{"format": 1, "name": "harts", "version": "1.0.0", "title": "Hart's Bakery", "purpose": "The bakery's site.",
		"chatbots": [{"name": "help", "title": "Ask the bakery", "public": true, "actions": [
			{"name": "contact", "kind": "form", "target": "contact", "description": "Write to us", "fields": ["message"]}]}]}`
	drafted, _, err := ReadSiteDraft(answer, brief, start, "dana", "test-model", buildTime)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range drafted.Chatbots {
		idle("drafted", a)
	}

	for _, contact := range []bool{true, false} {
		box := QuestionBox("Hart's Bakery", nil, contact)
		idle("imported", box)
		if mentions := strings.Contains(box.Refusal, "contact page"); mentions != contact {
			t.Errorf("with a contact page %v, the refusal says %q", contact, box.Refusal)
		}
	}
}
