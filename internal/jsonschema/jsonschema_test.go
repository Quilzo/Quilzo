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
