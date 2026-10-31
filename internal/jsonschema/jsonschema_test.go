// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package jsonschema

import (
	"encoding/json"
	"strings"
	"testing"
)

const invoice = `{"type":"object","required":["amount","currency"],
  "properties":{
    "amount":{"type":"integer","minimum":1,"maximum":100000},
    "currency":{"type":"string","enum":["GBP","EUR"]},
    "memo":{"type":"string","maxLength":10},
    "lines":{"type":"array","maxItems":2,"items":{"type":"object","properties":{"sku":{"type":"string","pattern":"^[A-Z]{3}-[0-9]+$"}}}},
    "payee":{"oneOf":[{"type":"string"},{"type":"object","properties":{"id":{"type":"string"}},"additionalProperties":false}]},
    "meta":{"type":"object","additionalProperties":{"type":"string"}}
  }}`

func TestABodyFitsItsSchemaOrSaysWhereNot(t *testing.T) {
	ok := []string{
		`{"amount":5,"currency":"GBP"}`,
		`{"amount":5,"currency":"EUR","memo":"rent","lines":[{"sku":"INK-12"}],"payee":"acme","meta":{"po":"77"}}`,
		`{"amount":5,"currency":"EUR","payee":{"id":"p1"}}`,
	}
	bad := map[string]string{
		`{"amount":5}`:                                           "needs currency",
		`{"amount":5.5,"currency":"GBP"}`:                        "must be integer",
		`{"amount":0,"currency":"GBP"}`:                          "less than",
		`{"amount":5,"currency":"USD"}`:                          "one of the values",
		`{"amount":5,"currency":"GBP","memo":"far too long"}`:    "longer than",
		`{"amount":5,"currency":"GBP","role":"admin"}`:           "not a property it takes",
		`{"amount":5,"currency":"GBP","lines":[{},{},{}]}`:       "more than 2 items",
		`{"amount":5,"currency":"GBP","lines":[{"sku":"x"}]}`:    "form it must be",
		`{"amount":5,"currency":"GBP","payee":{"id":"p","x":1}}`: "shapes",
		`{"amount":5,"currency":"GBP","meta":{"po":7}}`:          "not a property it takes",
		`"just text"`: "must be object",
	}
	for _, s := range ok {
		var v any
		_ = json.Unmarshal([]byte(s), &v)
		if err := Check(json.RawMessage(invoice), v); err != nil {
			t.Errorf("%s was refused: %v", s, err)
		}
	}
	for s, want := range bad {
		var v any
		_ = json.Unmarshal([]byte(s), &v)
		err := Check(json.RawMessage(invoice), v)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", s, err, want)
		}
	}
	// An open schema takes anything, as the importer writes for a body it
	// could not describe.
	if err := Check(json.RawMessage(`{"type":"object"}`), map[string]any{"anything": 1}); err != nil {
		t.Errorf("an open object refused a field: %v", err)
	}
}

// A reference is followed within the schema, as the schemas libraries
// write for structured output put each nested shape in $defs; without it
// a nested shape would take anything. A recursive schema is followed as
// far as the value goes.
func TestAReferenceIsFollowedWithinTheSchema(t *testing.T) {
	const order = `{"type":"object","required":["to","lines"],"additionalProperties":false,
	  "properties":{"to":{"$ref":"#/$defs/address"},"lines":{"type":"array","items":{"$ref":"#/$defs/line"}},
	    "note":{"$ref":"#/$defs/a~1b"},"elsewhere":{"$ref":"https://example.com/schema.json"}},
	  "$defs":{"address":{"type":"object","required":["city"],"additionalProperties":false,
	      "properties":{"city":{"type":"string"}}},
	    "line":{"type":"object","properties":{"sku":{"type":"string"},"parts":{"type":"array","items":{"$ref":"#/$defs/line"}}}},
	    "a/b":{"type":"string","maxLength":3}}}`
	ok := []string{
		`{"to":{"city":"Paris"},"lines":[{"sku":"a"}]}`,
		`{"to":{"city":"Paris"},"lines":[{"sku":"a","parts":[{"sku":"b","parts":[]}]}],"note":"hi","elsewhere":7}`,
	}
	bad := map[string]string{
		`{"to":{},"lines":[]}`:                                                "body.to needs city",
		`{"to":{"city":"Paris","role":"admin"},"lines":[]}`:                   "not a property it takes",
		`{"to":{"city":"Paris"},"lines":[{"sku":7}]}`:                         "body.lines[0].sku is a number",
		`{"to":{"city":"Paris"},"lines":[{"parts":[{"parts":[{"sku":1}]}]}]}`: "body.lines[0].parts[0].parts[0].sku",
		`{"to":{"city":"Paris"},"lines":[],"note":"far too long"}`:            "longer than 3",
	}
	for _, s := range ok {
		var v any
		_ = json.Unmarshal([]byte(s), &v)
		if err := Check(json.RawMessage(order), v); err != nil {
			t.Errorf("%s was refused: %v", s, err)
		}
	}
	for s, want := range bad {
		var v any
		_ = json.Unmarshal([]byte(s), &v)
		if err := Check(json.RawMessage(order), v); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", s, err, want)
		}
	}
}

// A schema that refers to itself is bounded: one that only ever points
// at itself, and one small enough to write in a line that would double
// the work at every level, are both refused rather than followed.
func TestASchemaThatRefersToItselfIsBounded(t *testing.T) {
	if err := Check(json.RawMessage(`{"$ref":"#"}`), "x"); err == nil || !strings.Contains(err.Error(), "deeper") {
		t.Errorf("a schema that is only a reference to itself: %v", err)
	}
	refs := strings.Repeat(`{"$ref":"#"},`, 9) + `{"$ref":"#"}`
	for _, combine := range []string{"anyOf", "oneOf"} {
		err := Check(json.RawMessage(`{"`+combine+`":[`+refs+`]}`), "x")
		if err == nil || !strings.Contains(err.Error(), "steps") {
			t.Errorf("%s of ten references to itself: %v", combine, err)
		}
	}
	// Ten nested lists, each item checked ten times over: ten to the
	// tenth checks, unbounded.
	var nested any = []any{}
	for i := 0; i < 10; i++ {
		nested = []any{nested}
	}
	err := Check(json.RawMessage(`{"type":"array","items":{"allOf":[`+refs+`]}}`), nested)
	if err == nil || !strings.Contains(err.Error(), "steps") {
		t.Errorf("allOf of ten references to itself, over ten nested lists: %v", err)
	}
}
