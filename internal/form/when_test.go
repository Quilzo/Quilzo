// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package form

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func returnsForm() *Form {
	return &Form{Name: "help", Notice: "We reply and then delete it.", Fields: []Field{
		{Name: "topic", Label: "Topic", Kind: Choice, Choices: []string{"Question", "Returns", `Odd "one" <b>`}, Required: true},
		{Name: "order", Label: "Order number", Kind: Line, Required: true, When: &When{Field: "topic", Is: "Returns"}},
		{Name: "gift", Label: "It was a gift", Kind: Agree},
		{Name: "giver", Label: "Who gave it", Kind: Line, Required: true, When: &When{Field: "gift"}},
	}}
}

func sent(v map[string]string) map[string]string {
	v[StampField] = fmt.Sprint(time.Now().Add(-10 * time.Second).Unix())
	return v
}

// A question asked only on an answer is required when that answer was
// given, and neither required nor kept when it was not, whatever arrived.
func TestAQuestionIsAskedOnlyOnItsAnswer(t *testing.T) {
	f := returnsForm()
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := Accept(f, sent(map[string]string{"topic": "Returns"}), "", now); err == nil {
		t.Fatal("asked and not answered")
	}
	s, err := Accept(f, sent(map[string]string{"topic": "Question", "order": "smuggled in", "giver": "x"}), "", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, kept := s.Values["order"]; kept {
		t.Fatal("kept an answer to a question not asked")
	}
	if _, kept := s.Values["giver"]; kept {
		t.Fatal("kept an answer behind an unticked box")
	}
	if _, err := Accept(f, sent(map[string]string{"topic": "Question", "gift": "true"}), "", now); err == nil {
		t.Fatal("a ticked box did not ask its question")
	}
	s, err = Accept(f, sent(map[string]string{"topic": "Returns", "order": "A-17", "gift": "on", "giver": "Ana"}), "", now)
	if err != nil || s.Values["order"] != "A-17" || s.Values["giver"] != "Ana" {
		t.Fatalf("%+v %v", s.Values, err)
	}
}

// A condition that cannot hold or be shown is refused when declared, and
// consent cannot rest on a box only some are asked to tick.
func TestAConditionThatCannotHoldIsRefused(t *testing.T) {
	for name, fields := range map[string][]Field{
		"later field": {{Name: "a", Label: "A", Kind: Line, When: &When{Field: "b", Is: "x"}},
			{Name: "b", Label: "B", Kind: Choice, Choices: []string{"x"}}},
		"not a choice": {{Name: "b", Label: "B", Kind: Line}, {Name: "a", Label: "A", Kind: Line, When: &When{Field: "b", Is: "x"}}},
		"no such choice": {{Name: "b", Label: "B", Kind: Choice, Choices: []string{"x"}},
			{Name: "a", Label: "A", Kind: Line, When: &When{Field: "b", Is: "y"}}},
		"a box with a choice": {{Name: "b", Label: "B", Kind: Agree}, {Name: "a", Label: "A", Kind: Line, When: &When{Field: "b", Is: "y"}}},
		"itself":              {{Name: "a", Label: "A", Kind: Agree, When: &When{Field: "a"}}},
	} {
		f := &Form{Name: "t", Notice: "n", Fields: fields}
		if err := f.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	f := &Form{Name: "t", Notice: "n", Basis: "consent", Fields: []Field{
		{Name: "b", Label: "B", Kind: Choice, Choices: []string{"x", "y"}},
		{Name: "ok", Label: "I agree", Kind: Agree, Required: true, When: &When{Field: "b", Is: "x"}}}}
	if err := f.Validate(); err == nil {
		t.Error("consent asked of only some")
	}
}

// The stylesheet hides each such question until its answer, inside
// @supports, and a choice cannot break out of its rule.
func TestTheStyleSheetHidesAQuestionUntilItsAnswer(t *testing.T) {
	css := returnsForm().StyleSheet()
	for _, want := range []string{"@supports selector(:has(a))", "#f-order-field{display:none}",
		`form:has(#f-topic option[value="Returns"]:checked) #f-order-field{display:block}`,
		"form:has(#f-gift:checked) #f-giver-field{display:block}"} {
		if !strings.Contains(css, want) {
			t.Errorf("missing %s in\n%s", want, css)
		}
	}
	f := returnsForm()
	f.Fields[1].When.Is = `Odd "one" <b>`
	css = f.StyleSheet()
	if strings.Contains(css, `"one"`) || strings.Contains(css, "<b>") || strings.Count(css, "{") != strings.Count(css, "}") {
		t.Fatalf("a choice broke out:\n%s", css)
	}
	if (&Form{Name: "x", Fields: []Field{{Name: "a"}}}).StyleSheet() != "" {
		t.Error("a stylesheet for a form with no conditions")
	}
	if !strings.Contains(Embed(returnsForm()), "Only if “Topic” is Returns.") {
		t.Error("the embedded form does not say when it is asked")
	}
	if strings.Contains(Embed(returnsForm()), `name="order" type="text" required`) {
		t.Error("a question asked only sometimes is required in the markup")
	}
}
