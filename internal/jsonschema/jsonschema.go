// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package jsonschema checks a value against the part of JSON Schema that
// API descriptions use for request bodies: types, properties and which are
// required, items, enumerations, lengths, bounds, allOf, anyOf and oneOf,
// and references to another part of the same schema ($ref, as $defs and
// recursive schemas are written). A keyword it does not know, or a
// reference to anywhere else, constrains nothing.
//
// One rule is stricter than the standard. An object schema that lists its
// properties takes only those, unless additionalProperties says otherwise:
// the standard allows any other property by default, and a model steered
// by something it read adding "role": "admin" to a body an API would
// accept is the mass assignment this exists to stop. A schema that wants
// other properties says additionalProperties: true.
package jsonschema

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxDepth bounds how far into a value, or a schema, a check goes.
const maxDepth = 32

// maxSteps bounds the work of one check, to under a second. A schema
// that refers to itself can be a few bytes and still ask for more work
// than there is time for: two references to itself under anyOf double the
// work at every level, and a schema can come from whoever is calling. A
// value that fits a schema written in good faith takes a few steps for
// each of its parts, so only one of megabytes would come near it.
const maxSteps = 1000000

// checker is one check: the schema it began with, which a reference
// points into, and the work done so far.
type checker struct {
	root  any
	steps int
}

// Check reports the first way v does not fit schema, or nil. v is a value
// as encoding/json decodes into any: maps, slices, strings, float64,
// bool and nil.
func Check(schema json.RawMessage, v any) error {
	if len(schema) == 0 {
		return nil
	}
	var s any
	if err := json.Unmarshal(schema, &s); err != nil {
		return fmt.Errorf("the schema cannot be read: %w", err)
	}
	// Round-trip the value, so integers and structs arrive as JSON does.
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var norm any
	if err := json.Unmarshal(b, &norm); err != nil {
		return err
	}
	c := &checker{root: s}
	return c.check(s, norm, "body", 0)
}

func (c *checker) check(schema any, v any, at string, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("%s is nested deeper than %d", at, maxDepth)
	}
	if c.steps++; c.steps > maxSteps {
		return c.tooMuch(at)
	}
	s, ok := schema.(map[string]any)
	if !ok {
		// true admits everything, false nothing.
		if b, isBool := schema.(bool); isBool && !b {
			return fmt.Errorf("%s is not allowed", at)
		}
		return nil
	}
	if t, ok := s["type"]; ok {
		if err := checkType(t, v, at); err != nil {
			return err
		}
	}
	if e, ok := s["enum"].([]any); ok {
		found := false
		for _, x := range e {
			found = found || equal(x, v)
		}
		if !found {
			return fmt.Errorf("%s is not one of the values it may take", at)
		}
	}
	if c, ok := s["const"]; ok && !equal(c, v) {
		return fmt.Errorf("%s is not the value it must be", at)
	}
	switch x := v.(type) {
	case string:
		n := float64(utf8.RuneCountInString(x))
		if m, ok := num(s["maxLength"]); ok && n > m {
			return fmt.Errorf("%s is longer than %v characters", at, m)
		}
		if m, ok := num(s["minLength"]); ok && n < m {
			return fmt.Errorf("%s is shorter than %v characters", at, m)
		}
		if p, ok := s["pattern"].(string); ok {
			// ECMA-262 and RE2 differ at the edges; a pattern this program
			// cannot compile constrains nothing rather than refusing all.
			if re, err := regexp.Compile(p); err == nil && !re.MatchString(x) {
				return fmt.Errorf("%s is not in the form it must be", at)
			}
		}
	case float64:
		if m, ok := num(s["maximum"]); ok && x > m {
			return fmt.Errorf("%s is more than %v", at, m)
		}
		if m, ok := num(s["minimum"]); ok && x < m {
			return fmt.Errorf("%s is less than %v", at, m)
		}
		if m, ok := num(s["exclusiveMaximum"]); ok && x >= m {
			return fmt.Errorf("%s is not less than %v", at, m)
		}
		if m, ok := num(s["exclusiveMinimum"]); ok && x <= m {
			return fmt.Errorf("%s is not more than %v", at, m)
		}
	case []any:
		if m, ok := num(s["maxItems"]); ok && float64(len(x)) > m {
			return fmt.Errorf("%s has more than %v items", at, m)
		}
		if m, ok := num(s["minItems"]); ok && float64(len(x)) < m {
			return fmt.Errorf("%s has fewer than %v items", at, m)
		}
		if items, ok := s["items"]; ok {
			for i, item := range x {
				if err := c.check(items, item, fmt.Sprintf("%s[%d]", at, i), depth+1); err != nil {
					return err
				}
			}
		}
	case map[string]any:
		if err := c.checkObject(s, x, at, depth); err != nil {
			return err
		}
	}
	if ref, ok := s["$ref"].(string); ok {
		if target, found := c.resolve(ref); found {
			if err := c.check(target, v, at, depth+1); err != nil {
				return err
			}
		}
	}
	if all, ok := s["allOf"].([]any); ok {
		for _, sub := range all {
			if err := c.check(sub, v, at, depth+1); err != nil {
				return err
			}
		}
	}
	// A shape that does not fit is not an error here, so running out of
	// steps is looked for apart: otherwise a check cut short would read as
	// a value that fits none of its shapes, or fits one.
	if anyOf, ok := s["anyOf"].([]any); ok && len(anyOf) > 0 {
		fits := false
		for _, sub := range anyOf {
			fits = fits || c.check(sub, v, at, depth+1) == nil
		}
		if c.steps > maxSteps {
			return c.tooMuch(at)
		}
		if !fits {
			return fmt.Errorf("%s fits none of the shapes it may take", at)
		}
	}
	if oneOf, ok := s["oneOf"].([]any); ok && len(oneOf) > 0 {
		n := 0
		for _, sub := range oneOf {
			if c.check(sub, v, at, depth+1) == nil {
				n++
			}
		}
		if c.steps > maxSteps {
			return c.tooMuch(at)
		}
		if n != 1 {
			return fmt.Errorf("%s fits %d of the shapes it may take, and must fit exactly one", at, n)
		}
	}
	return nil
}

func (c *checker) tooMuch(at string) error {
	return fmt.Errorf("%s takes more than %d steps to check against its schema", at, maxSteps)
}

// resolve finds what a reference points to in the schema the check began
// with: the whole of it ("#"), or a part by its JSON pointer
// ("#/$defs/address").
func (c *checker) resolve(ref string) (any, bool) {
	if ref == "#" {
		return c.root, true
	}
	path, ok := strings.CutPrefix(ref, "#/")
	if !ok {
		return nil, false
	}
	at := c.root
	for _, tok := range strings.Split(path, "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch x := at.(type) {
		case map[string]any:
			next, ok := x[tok]
			if !ok {
				return nil, false
			}
			at = next
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(x) {
				return nil, false
			}
			at = x[i]
		default:
			return nil, false
		}
	}
	return at, true
}

func (c *checker) checkObject(s map[string]any, x map[string]any, at string, depth int) error {
	props, _ := s["properties"].(map[string]any)
	if req, ok := s["required"].([]any); ok {
		for _, r := range req {
			if name, ok := r.(string); ok {
				if _, present := x[name]; !present {
					return fmt.Errorf("%s needs %s", at, name)
				}
			}
		}
	}
	if m, ok := num(s["maxProperties"]); ok && float64(len(x)) > m {
		return fmt.Errorf("%s has more than %v properties", at, m)
	}
	extra, hasExtra := s["additionalProperties"]
	keys := make([]string, 0, len(x))
	for k := range x {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		where := at + "." + k
		if p, ok := props[k]; ok {
			if err := c.check(p, x[k], where, depth+1); err != nil {
				return err
			}
			continue
		}
		switch {
		case hasExtra:
			if err := c.check(extra, x[k], where, depth+1); err != nil {
				if c.steps > maxSteps {
					return err
				}
				return errors.New(where + " is not a property it takes")
			}
		case props != nil:
			return fmt.Errorf("%s is not a property it takes; it takes %s", where, names(props))
		}
	}
	return nil
}

func checkType(t any, v any, at string) error {
	var types []string
	switch x := t.(type) {
	case string:
		types = []string{x}
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				types = append(types, s)
			}
		}
	}
	if len(types) == 0 {
		return nil
	}
	for _, want := range types {
		if is(want, v) {
			return nil
		}
	}
	return fmt.Errorf("%s is %s, and must be %s", at, kind(v), strings.Join(types, " or "))
}

func is(want string, v any) bool {
	switch want {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "number":
		_, ok := v.(float64)
		return ok
	case "integer":
		f, ok := v.(float64)
		return ok && f == math.Trunc(f) && !math.IsInf(f, 0)
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "null":
		return v == nil
	}
	return true
}

func kind(v any) string {
	switch v.(type) {
	case map[string]any:
		return "an object"
	case []any:
		return "a list"
	case string:
		return "text"
	case float64:
		return "a number"
	case bool:
		return "true or false"
	case nil:
		return "null"
	}
	return "something else"
}

func num(v any) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}

func equal(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}

func names(props map[string]any) string {
	out := make([]string, 0, len(props))
	for k := range props {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 12 {
		out = append(out[:12], "…")
	}
	return strings.Join(out, ", ")
}
