// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package schema

import "testing"

func productType() Type {
	min := 0.0
	return Type{
		Name: "product",
		Fields: []Field{
			{Name: "name", Kind: Text, Required: true, MaxLen: 80},
			{Name: "price", Kind: Number, Required: true, Min: &min},
			{Name: "currency", Kind: Choice, Choices: []string{"GBP", "EUR"}},
			{Name: "tags", Kind: List},
			{Name: "featured", Kind: Boolean},
			{Name: "launched", Kind: Date},
		},
	}
}

// A new record starts as the shape the type declares.
//
// It started as a placeholder in a textarea, so writing one meant remembering
// the field names, remembering which were required, and finding out which you
// had got wrong by being refused. The declaration knew the answer the whole
// time.
func TestBlankIsEveryFieldTheTypeDeclares(t *testing.T) {
	blank := productType().Blank()

	for _, want := range []string{"name", "price", "currency", "tags",
		"featured", "launched"} {
		if _, there := blank[want]; !there {
			t.Errorf("a new record does not mention %q, so somebody has to "+
				"already know the type has it", want)
		}
	}
	if len(blank) != 6 {
		t.Errorf("a new record carries %d fields and the type declares 6",
			len(blank))
	}
}

// Of the right shape, so what is written back is not a string where a number
// goes.
func TestBlankUsesTheShapeOfEachKind(t *testing.T) {
	blank := productType().Blank()
	if blank["price"] != 0 {
		t.Errorf("price starts as %#v, and a number field should start as a "+
			"number", blank["price"])
	}
	if blank["featured"] != false {
		t.Errorf("featured starts as %#v", blank["featured"])
	}
	if list, ok := blank["tags"].([]any); !ok || len(list) != 0 {
		t.Errorf("tags starts as %#v, and a list should start as an empty "+
			"list", blank["tags"])
	}
	if blank["name"] != "" {
		t.Errorf("name starts as %#v", blank["name"])
	}
	// A choice is left empty rather than set to its first option: the options
	// are a decision somebody makes, and prefilling one is how every record
	// ends up being whatever came first in the list.
	if blank["currency"] != "" {
		t.Errorf("currency starts as %#v, which is a decision nobody made",
			blank["currency"])
	}
}

// A declared starting value is used where there is one.
//
// For the handful of fields where the answer is nearly always the same, and
// typing it every time is how it comes to be typed wrong.
func TestADeclaredStartingValueIsUsed(t *testing.T) {
	ty := productType()
	ty.Stub = map[string]any{"currency": "GBP", "featured": true}

	blank := ty.Blank()
	if blank["currency"] != "GBP" {
		t.Errorf("currency starts as %#v and the type says GBP",
			blank["currency"])
	}
	if blank["featured"] != true {
		t.Errorf("featured starts as %#v and the type says true",
			blank["featured"])
	}
	// And everything else is still empty.
	if blank["name"] != "" {
		t.Errorf("name starts as %#v", blank["name"])
	}
}

// A starting value the type would refuse is refused where it is written.
//
// The alternative is a form that arrives already unsaveable, which reads as
// the tool being broken rather than as the type being wrong.
func TestAStartingValueTheTypeWouldRefuseIsRefused(t *testing.T) {
	ty := productType()
	ty.Stub = map[string]any{"currency": "USD"}
	if err := Compile(ty); err == nil {
		t.Error("a type shipped a starting value outside its own choices, so " +
			"the form it produces cannot be saved as it was handed over")
	}

	ty.Stub = map[string]any{"price": -5}
	if err := Compile(ty); err == nil {
		t.Error("a type shipped a starting value below its own minimum")
	}
}

// And one naming a field nobody declared.
func TestAStartingValueForAFieldNobodyDeclaredIsRefused(t *testing.T) {
	ty := productType()
	ty.Stub = map[string]any{"colour": "brass"}
	if err := Compile(ty); err == nil {
		t.Error("a type shipped a starting value for a field it does not " +
			"have, which quietly does nothing")
	}
}

// A required field with nothing in it is fine, because that is the point.
//
// A stub is where somebody starts, and a required field showing empty is
// exactly what it should show — checking it as a complete record would make it
// impossible to have one at all.
func TestAStubNeedNotBeACompleteRecord(t *testing.T) {
	ty := productType()
	ty.Stub = map[string]any{"currency": "GBP"}
	if err := Compile(ty); err != nil {
		t.Errorf("a stub leaving the required fields empty was refused: %v", err)
	}
}
