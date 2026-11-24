// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package jsonschema

import (
	"encoding/json"
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

// A property a schema does not take is named by a short form of its name.
//
// The name is the value's own, and a value checked here is whatever came
// in: a tool's arguments from the agent interface, where a name may be as
// long as the request. Named whole, the answer that one argument is not
// taken was as long as the argument's name, a megabyte sent back to the
// caller, where a tool or an operation nobody has is quoted in eighty bytes.
func TestAPropertyNobodyTakesIsNamedShort(t *testing.T) {
	huge := "x" + strings.Repeat("y", 1<<20)
	for name, tc := range map[string]struct {
		schema string
		value  map[string]any
	}{
		"among the properties listed": {`{"type":"object","properties":{"page":{"type":"string"}}}`,
			map[string]any{huge: 1}},
		"inside a property": {`{"type":"object","properties":{"fields":{"type":"object","properties":{"title":{"type":"string"}}}}}`,
			map[string]any{"fields": map[string]any{huge: 1}}},
		"where any other is held to a schema": {`{"type":"object","additionalProperties":{"type":"string"}}`,
			map[string]any{huge: 1}},
	} {
		err := CheckNamed(json.RawMessage(tc.schema), tc.value, "arguments")
		if err == nil {
			t.Fatalf("%s: a property nobody takes was taken", name)
		}
		if len(err.Error()) > 512 || !strings.Contains(err.Error(), "arguments.") ||
			!strings.Contains(err.Error(), "xyyy") || !strings.Contains(err.Error(), "not a property it takes") {
			t.Errorf("%s: answered %d bytes, not a short form of the name: %.120s", name, len(err.Error()), err.Error())
		}
	}
	// A name of ordinary length is said whole, as it was.
	err := CheckNamed(json.RawMessage(`{"type":"object","properties":{"page":{"type":"string"}}}`),
		map[string]any{"pagename": "about"}, "arguments")
	if err == nil || err.Error() != "arguments.pagename is not a property it takes; it takes page" {
		t.Errorf("an ordinary name: %v", err)
	}
}

// fits is each value against its schema: "" where it fits, and otherwise
// what the answer that it does not must say.
type fits struct {
	schema string
	value  string
	want   string
}

func checkAll(t *testing.T, cases []fits) {
	t.Helper()
	for _, c := range cases {
		var v any
		if err := json.Unmarshal([]byte(c.value), &v); err != nil {
			t.Fatalf("%s: %v", c.value, err)
		}
		err := CheckNamed(json.RawMessage(c.schema), v, "arguments")
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s against %s was refused: %v", c.value, c.schema, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s against %s: %v, want %q", c.value, c.schema, err, c.want)
		}
	}
}

// An object takes the properties every schema applied to it lists, not
// only the first one's.
//
// Each schema an object's schema was made of was held to the rule that an
// object schema listing its properties takes only those, alone. So a tool
// whose arguments were composed with allOf of two schemas, each listing some
// of them, took no call at all; nor did one whose alternatives in anyOf each
// listed their own, given properties of two, nor one with a $ref to the
// properties it shares; and a patternProperties for the names a tool takes
// besides those it lists refused every one of them as a property it does
// not take. A property none of them lists is refused as before.
func TestAnObjectTakesWhatEverySchemaAppliedToItLists(t *testing.T) {
	const composed = `{"allOf":[{"type":"object","properties":{"title":{"type":"string"}},"required":["title"]},
	  {"properties":{"priority":{"type":"integer"}}}]}`
	const shared = `{"$defs":{"base":{"properties":{"id":{"type":"string"}},"required":["id"]}},
	  "allOf":[{"$ref":"#/$defs/base"},{"properties":{"note":{"type":"string"}}}]}`
	const extended = `{"type":"object","properties":{"name":{"type":"string"}},"patternProperties":{"^x-":{"type":"string"}}}`
	const contact = `{"type":"object","anyOf":[{"properties":{"email":{"type":"string"}},"required":["email"]},
	  {"properties":{"phone":{"type":"string"}},"required":["phone"]}]}`
	const payment = `{"type":"object","properties":{"kind":{"enum":["card","bank"]}},"required":["kind"],
	  "if":{"properties":{"kind":{"const":"card"}}},
	  "then":{"properties":{"number":{"type":"string"}},"required":["number"]},
	  "else":{"properties":{"iban":{"type":"string"}},"required":["iban"]}}`
	const more = `{"allOf":[{"properties":{"a":{}}}],"unevaluatedProperties":{"type":"string"}}`
	checkAll(t, []fits{
		{composed, `{"title":"Printer on fire","priority":1}`, ""},
		{composed, `{"title":"Printer on fire","priority":"high"}`, "must be integer"},
		{composed, `{"priority":1}`, "needs title"},
		{composed, `{"title":"Printer on fire","role":"admin"}`, "arguments.role is not a property it takes; it takes priority, title"},
		{`{"type":"object","properties":{"a":{}},"allOf":[{"properties":{"b":{}}}]}`, `{"a":1,"b":2}`, ""},
		{shared, `{"id":"x","note":"y"}`, ""},
		{shared, `{"note":"y"}`, "needs id"},
		{shared, `{"id":"x","role":"admin"}`, "not a property it takes"},
		{extended, `{"name":"n","x-trace":"t"}`, ""},
		{extended, `{"name":"n","x-trace":5}`, "must be string"},
		{extended, `{"name":"n","role":"admin"}`, "not a property it takes"},
		{`{"type":"object","patternProperties":{"^[a-z]+$":{"type":"integer"}}}`, `{"apples":1}`, ""},
		{`{"type":"object","patternProperties":{"^[a-z]+$":{"type":"integer"}}}`, `{"apples":"one"}`, "must be integer"},
		{`{"type":"object","patternProperties":{"^[a-z]+$":{"type":"integer"}}}`, `{"Apples":1}`, "not a property it takes"},
		{contact, `{"email":"e"}`, ""},
		{contact, `{"email":"e","phone":"p"}`, ""},
		{contact, `{"email":"e","role":"admin"}`, "not a property it takes"},
		{contact, `{}`, "fits none"},
		{payment, `{"kind":"card","number":"4111"}`, ""},
		{payment, `{"kind":"card"}`, "needs number"},
		{payment, `{"kind":"bank","iban":"GB00"}`, ""},
		{payment, `{"kind":"bank","number":"4111"}`, "needs iban"},
		{payment, `{"kind":"card","number":"4111","role":"admin"}`, "not a property it takes"},
		{more, `{"a":1,"b":"s"}`, ""},
		{more, `{"a":1,"b":2}`, "arguments.b is not a property it takes"},
		// What this cannot read takes any property rather than refusing
		// all: a schema somewhere else, which is never fetched, and a
		// pattern RE2 does not compile.
		{`{"properties":{"a":{}},"allOf":[{"$ref":"https://schemas.example/more.json"}]}`, `{"a":1,"b":2}`, ""},
		{`{"properties":{"a":{}},"patternProperties":{"(?<=x)y":{}}}`, `{"a":1,"b":2}`, ""},
	})
}

// A keyword that constrains a value is held to.
//
// The subset read none of these, so each passed whatever it was meant to
// stop: the arguments of a property defined once and pointed at with $ref,
// as most generated schemas are, went unchecked; so did a schema's least
// number of properties, though its most was read, a value it must not be,
// a multiple, items that must differ, a property that needs another, the
// names a map's keys may have, a list of items each with its own shape,
// and an item a list must contain.
func TestEveryKeywordThatConstrainsAValueIsHeldTo(t *testing.T) {
	const address = `{"type":"object","$defs":{"addr":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}},
	  "properties":{"to":{"$ref":"#/$defs/addr"},"from":{"$ref":"#/definitions/addr"}},
	  "definitions":{"addr":{"$ref":"#/$defs/addr"}}}`
	const tree = `{"$defs":{"node":{"type":"object","properties":{"name":{"type":"string"},
	  "children":{"type":"array","items":{"$ref":"#/$defs/node"}}},"required":["name"]}},"$ref":"#/$defs/node"}`
	checkAll(t, []fits{
		{address, `{"to":{"city":"Leeds"},"from":{"city":"York"}}`, ""},
		{address, `{"to":{}}`, "arguments.to needs city"},
		{address, `{"from":{"city":7}}`, "arguments.from.city is a number"},
		{address, `{"to":{"city":"Leeds","role":"admin"}}`, "arguments.to.role is not a property it takes"},
		{tree, `{"name":"a","children":[{"name":"b","children":[{"name":"c"}]}]}`, ""},
		{tree, `{"name":"a","children":[{"name":"b","children":[{}]}]}`, "children[0].children[0] needs name"},
		{`{"type":"object","minProperties":1}`, `{}`, "fewer than 1 properties"},
		{`{"type":"object","properties":{"to":{"type":"string","not":{"const":"everyone"}}}}`, `{"to":"everyone"}`, "must not"},
		{`{"type":"object","properties":{"to":{"type":"string","not":{"const":"everyone"}}}}`, `{"to":"dana"}`, ""},
		{`{"type":"number","multipleOf":0.01}`, `0.07`, ""},
		{`{"type":"number","multipleOf":0.01}`, `0.075`, "not a multiple of 0.01"},
		{`{"type":"integer","multipleOf":5}`, `12`, "not a multiple of 5"},
		{`{"type":"array","uniqueItems":true}`, `[1,2,{"a":1},{"a":2}]`, ""},
		{`{"type":"array","uniqueItems":true}`, `[1,{"a":1},{"a":1}]`, "[2] is the same as arguments[1]"},
		{`{"properties":{"card":{},"cvc":{}},"dependentRequired":{"card":["cvc"]}}`, `{"card":"x"}`, "needs cvc"},
		{`{"properties":{"card":{},"cvc":{}},"dependentRequired":{"card":["cvc"]}}`, `{"card":"x","cvc":"1"}`, ""},
		{`{"properties":{"card":{},"cvc":{}},"dependencies":{"card":["cvc"]}}`, `{"card":"x"}`, "needs cvc"},
		{`{"type":"object","propertyNames":{"pattern":"^[a-z]+$"},"additionalProperties":true}`, `{"Bad":1}`, "arguments.Bad is not a name it takes"},
		{`{"type":"array","prefixItems":[{"type":"string"},{"type":"integer"}],"items":false}`, `["a",1]`, ""},
		{`{"type":"array","prefixItems":[{"type":"string"},{"type":"integer"}],"items":false}`, `["a","b"]`, "arguments[1] is text"},
		{`{"type":"array","prefixItems":[{"type":"string"},{"type":"integer"}],"items":false}`, `["a",1,2]`, "arguments[2] is not allowed"},
		{`{"type":"array","items":[{"type":"string"}],"additionalItems":{"type":"integer"}}`, `["a",1,"b"]`, "arguments[2] is text"},
		{`{"type":"array","contains":{"type":"integer"}}`, `["a",1]`, ""},
		{`{"type":"array","contains":{"type":"integer"}}`, `["a"]`, "no item of the shape it must have"},
		{`{"type":"array","contains":{"const":"admin"},"maxContains":0,"minContains":0}`, `["admin"]`, "more than 0 items"},
	})
}

// A schema that points back into itself is checked in bounded time, and a
// long value is not refused for its length.
//
// A $ref may name the schema it is in, and two alternatives each naming it
// double the work at every level: bounded by depth alone, a schema a few
// dozen bytes long would cost billions of steps for one call.
func TestASchemaThatPointsBackIntoItselfEnds(t *testing.T) {
	nested := map[string]any{}
	for i := 0; i < 8; i++ {
		nested = map[string]any{"a": nested}
	}
	ends := func(schema string, v any) error {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- Check(json.RawMessage(schema), v) }()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatalf("%s is still being checked", schema)
		}
		return nil
	}
	if err := ends(`{"anyOf":[{"$ref":"#"},{"$ref":"#"},{"$ref":"#"}]}`, map[string]any{}); err == nil {
		t.Error("a schema that is nothing but itself was taken as fitting")
	}
	if err := ends(`{"$ref":"#"}`, "x"); err == nil {
		t.Error("a schema that is only itself was taken as fitting")
	}
	// Where checking had to stop is not a fit, even under a not.
	for _, schema := range []string{`{"not":{"$ref":"#"}}`, `{"not":{"not":{"$ref":"#"}}}`} {
		if err := ends(schema, "x"); err == nil || !strings.Contains(err.Error(), "deeper than") {
			t.Errorf("%s: %v", schema, err)
		}
	}
	if err := ends(`{"type":"object","anyOf":[{"properties":{"a":{"$ref":"#"}}},{"properties":{"a":{"$ref":"#"}}}]}`, nested); err != nil {
		t.Errorf("a value eight deep in a schema of itself: %v", err)
	}
	long := make([]any, 400000)
	for i := range long {
		long[i] = float64(i)
	}
	if err := ends(`{"type":"array","items":{"anyOf":[{"type":"integer"},{"type":"string"}]}}`, long); err != nil {
		t.Errorf("a long list was refused: %v", err)
	}
}

// A part of a schema is checked with its $refs pointing into the whole:
// what a tool takes as one argument, when the argument is defined once and
// pointed at, is what the definition says.
func TestAPartOfASchemaPointsIntoTheWhole(t *testing.T) {
	whole := json.RawMessage(`{"type":"object","$defs":{"id":{"type":"string"}},"properties":{"order_id":{"$ref":"#/$defs/id"}}}`)
	part := json.RawMessage(`{"$ref":"#/$defs/id"}`)
	if err := CheckPart(whole, part, 42); err == nil || !strings.Contains(err.Error(), "must be string") {
		t.Errorf("a number for text: %v", err)
	}
	if err := CheckPart(whole, part, "42"); err != nil {
		t.Errorf("text for text: %v", err)
	}
}
