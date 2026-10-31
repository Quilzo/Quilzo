// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package jsonschema

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
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

// What one visit costs is counted, not only how many there are: a long
// pattern, a long enumeration or a wide object, met again and again
// through references to the schema itself, used to take minutes on the
// steps a handful of visits are allowed.
func TestTheWorkOfEachVisitIsCounted(t *testing.T) {
	refs := strings.Repeat(`{"$ref":"#"},`, 9) + `{"$ref":"#"}`
	alts := make([]string, 300)
	for i := range alts {
		alts[i] = fmt.Sprintf("x%dy", i)
	}
	enum := make([]string, 20000)
	for i := range enum {
		enum[i] = fmt.Sprintf(`"v%d"`, i)
	}
	wide := map[string]any{}
	for i := 0; i < 20000; i++ {
		wide[fmt.Sprintf("k%d", i)] = 1
	}
	for name, c := range map[string]struct {
		schema string
		value  any
	}{
		"a pattern of 300 alternatives": {`{"pattern":"^(x|` + strings.Join(alts, "|") + `)$","anyOf":[` + refs + `]}`, "x"},
		"an enumeration of 20,000":      {`{"enum":[` + strings.Join(enum, ",") + `,"x"],"anyOf":[` + refs + `]}`, "x"},
		"a long string's length":        {`{"maxLength":2000000,"anyOf":[` + refs + `]}`, strings.Repeat("é", 500000)},
		"an object of 20,000":           {`{"additionalProperties":true,"anyOf":[` + refs + `]}`, wide},
		"a constant of 20,000":          {`{"const":` + mustJSON(wide) + `,"anyOf":[` + refs + `]}`, wide},
	} {
		start := time.Now()
		err := Check(json.RawMessage(c.schema), c.value)
		if took := time.Since(start); took > 5*time.Second {
			t.Errorf("%s took %v", name, took)
		}
		if err == nil || !strings.Contains(err.Error(), "steps") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A match is counted before it is run.
	long := `{"pattern":"` + strings.Repeat(`[a-z]{1000}`, 300) + `"}`
	start := time.Now()
	if err := Check(json.RawMessage(long), strings.Repeat("a", 1<<20)); err == nil || !strings.Contains(err.Error(), "steps") {
		t.Errorf("a pattern of 300,000 states over a megabyte: %v", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("a pattern of 300,000 states over a megabyte took %v", took)
	}
	many := make([]any, 20000)
	for i := range many {
		many[i] = float64(i)
	}
	if err := Check(json.RawMessage(`{"uniqueItems":true}`), many); err != nil {
		t.Errorf("20,000 different items: %v", err)
	}
	if err := Check(json.RawMessage(`{"pattern":"`+strings.Repeat("a", 5000)+`"}`), "a"); err == nil ||
		!strings.Contains(err.Error(), "longer than 4096 bytes") {
		t.Errorf("a pattern of 5,000 bytes: %v", err)
	}
	// What a schema in good faith asks stays well inside the bound.
	if err := Check(json.RawMessage(`{"type":"string","pattern":"^[a-z]+$","enum":["`+strings.Repeat("a", 100)+`"]}`),
		strings.Repeat("a", 100)); err != nil {
		t.Errorf("a modest pattern and enumeration: %v", err)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// inTime is how long the worst a schema can ask may take on a slow
// machine: what maxSteps allows, with room to spare. A case that takes
// longer is one whose work the steps do not count.
const inTime = 2 * time.Second

// wide is a shape of n properties, all of which take anything.
func wide(n int) string {
	props := make([]string, n)
	for i := range props {
		props[i] = fmt.Sprintf(`"p%d":{}`, i)
	}
	return `{"properties":{` + strings.Join(props, ",") + `}}`
}

// selfAndWide refers to itself under anyOf beside a wide shape, which an
// object with a property the shape does not list fails at every level.
func selfAndWide(n int) string {
	return `{"anyOf":[{"$ref":"#/$defs/big"},{"$ref":"#"},{"$ref":"#"}],"$defs":{"big":` + wide(n) + `}}`
}

// The costliest cases found are measured, not only counted, so the bound
// on steps is held to what a step costs. A shape that fails is written
// out only if its failure is the one returned, not for each anyOf throws
// away, which wrote out every property a schema of 2,000 takes at every
// level; and a long key costs its length, not one step, since each visit
// reads it to find it among the properties.
func TestTheCostliestCasesFinishInTime(t *testing.T) {
	long := strings.Repeat("k", 200<<10)
	for name, c := range map[string]struct {
		schema string
		value  any
		says   string
	}{
		"2,000 properties under anyOf (21 KB)":   {selfAndWide(2000), map[string]any{"zzz": 1.0}, "steps"},
		"20,000 properties under anyOf (229 KB)": {selfAndWide(20000), map[string]any{"zzz": 1.0}, "steps"},
		"a key of 200 KB under anyOf": {`{"type":"object","properties":{"name":{"type":"string"}},` +
			`"additionalProperties":true,"anyOf":[{"$ref":"#"},{"$ref":"#"},{"$ref":"#"}]}`,
			map[string]any{long: 1.0}, "steps"},
		"a key of 200 KB, once": {`{"type":"object","properties":{"name":{"type":"string"}},` +
			`"additionalProperties":{"type":"integer"}}`, map[string]any{long: 1.0}, ""},
		"one property of 20,000":  {wide(20000), map[string]any{"p19999": 1.0}, ""},
		"another than 20,000 take": {wide(20000), map[string]any{"zzz": 1.0}, "answer.zzz is not a property it takes; it takes p0, p1, p10,"},
	} {
		start := time.Now()
		err := CheckAnswer(json.RawMessage(c.schema), c.value, "answer")
		if took := time.Since(start); took > inTime {
			t.Errorf("%s took %v", name, took)
		}
		switch {
		case c.says == "" && err != nil:
			t.Errorf("%s was refused: %v", name, err)
		case c.says != "" && (err == nil || !strings.Contains(err.Error(), c.says)):
			t.Errorf("%s: %v, want %q", name, err, c.says)
		}
	}
}

// The keywords structured output holds an answer to are checked, so an
// answer that breaks one is not passed as fitting.
func TestEveryKeywordStructuredOutputUsesIsChecked(t *testing.T) {
	for _, c := range []struct {
		schema   string
		ok, bad  string
		saysWhat string
	}{
		{`{"multipleOf":0.1}`, `0.3`, `0.35`, "not a multiple of 0.1"},
		{`{"multipleOf":5}`, `-15`, `7`, "not a multiple of 5"},
		{`{"minProperties":2}`, `{"a":1,"b":2}`, `{"a":1}`, "fewer than 2 properties"},
		{`{"uniqueItems":true}`, `[1,"1",{"a":[1]},{"a":[2]}]`, `[{"a":[1]},2,{"a":[1]}]`, "same item twice, at 0 and 2"},
		{`{"not":{"type":"string"}}`, `7`, `"seven"`, "shape it must not take"},
		{`{"prefixItems":[{"type":"string"},{"type":"number"}],"items":false}`, `["a",1]`, `["a",1,true]`, "body[2] is not allowed"},
		{`{"prefixItems":[{"type":"string"}],"items":{"type":"number"}}`, `["a",1,2]`, `[1]`, "body[0] is a number"},
		{`{"enum":[0]}`, `-0`, `0.5`, "not one of the values"},
	} {
		var ok, bad any
		_ = json.Unmarshal([]byte(c.ok), &ok)
		_ = json.Unmarshal([]byte(c.bad), &bad)
		if err := Check(json.RawMessage(c.schema), ok); err != nil {
			t.Errorf("%s refused %s: %v", c.schema, c.ok, err)
		}
		if err := Check(json.RawMessage(c.schema), bad); err == nil || !strings.Contains(err.Error(), c.saysWhat) {
			t.Errorf("%s: %s came back as %v, want %q", c.schema, c.bad, err, c.saysWhat)
		}
	}
}

// What a model was held to as it wrote is held to its formats too, and
// called what the caller calls it; an API body's format is left as a note.
func TestAnAnswerIsHeldToItsFormats(t *testing.T) {
	for format, c := range map[string]struct{ ok, bad string }{
		"date-time": {"2026-10-31T09:26:45.5+05:45", "31/10/2026"},
		"date":      {"2026-10-31", "2026-10-31T00:00:00Z"},
		"time":      {"09:26:45.25Z", "9.26am"},
		"duration":  {"P1DT2H30M", "PT"},
		"email":     {"mira.k@mailhost.net", "Mira <mira.k@mailhost.net>"},
		"hostname":  {"mail.example.com", "-bad-.example.com"},
		"ipv4":      {"192.0.2.1", "::1"},
		"ipv6":      {"2001:db8::1", "192.0.2.1"},
		"uuid":      {"123e4567-e89b-12d3-a456-426614174000", "123e4567e89b12d3a456426614174000"},
		"uri":       {"https://example.com/a?b=c", "/only/a/path"},
	} {
		schema := json.RawMessage(`{"type":"object","properties":{"when":{"type":"string","format":"` + format + `"}}}`)
		if err := CheckAnswer(schema, map[string]any{"when": c.ok}, "answer"); err != nil {
			t.Errorf("%s refused %q: %v", format, c.ok, err)
		}
		err := CheckAnswer(schema, map[string]any{"when": c.bad}, "answer")
		if err == nil || !strings.Contains(err.Error(), "answer.when is not in the format "+format) {
			t.Errorf("%s: %q came back as %v", format, c.bad, err)
		}
		if err := Check(schema, map[string]any{"when": c.bad}); err != nil {
			t.Errorf("an API body's %s was held to it: %v", format, err)
		}
	}
	if err := CheckAnswer(json.RawMessage(`{"format":"colour"}`), "teal", "answer"); err != nil {
		t.Errorf("a format nothing knows: %v", err)
	}
}
