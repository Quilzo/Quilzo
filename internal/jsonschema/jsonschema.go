// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package jsonschema checks a value against JSON Schema as tool and API
// descriptions write it: types, enumerations and constants; lengths,
// patterns, bounds and multiples; items, prefixItems, contains and items
// that must differ; properties, patternProperties, additionalProperties,
// unevaluatedProperties, propertyNames, required, dependentRequired and how
// many properties; allOf, anyOf, oneOf, not, if, then and else, and
// dependentSchemas; and $ref to a part of the same schema. A keyword it
// does not know constrains nothing, and nor does a $ref to anywhere else:
// nothing is fetched.
//
// One rule is stricter than the standard. An object schema that lists its
// properties, by name or by pattern, takes only those, unless
// additionalProperties or unevaluatedProperties says otherwise: the
// standard allows any other property by default, and a model steered by
// something it read adding "role": "admin" to a body an API would accept is
// the mass assignment this exists to stop. A schema that wants other
// properties says additionalProperties: true.
//
// What an object takes is what every schema the value fits lists for it
// where it is: its own schema's, and those of the schemas it is made of,
// through allOf, $ref, the alternatives of anyOf and oneOf it fits, if and
// then or else, and dependentSchemas, at whatever depth they reach it. Each
// of them was held to the rule alone, so a tool's arguments composed with
// allOf of two schemas that each listed some of them took no call at all,
// and a patternProperties for the names a tool takes besides those it lists
// refused every name it matched. Where this cannot tell what a schema
// takes, a $ref it does not follow or a pattern RE2 does not compile, the
// object takes any property rather than none.
//
// So the rule is asked once, of the whole value, when the standard's rules
// have found what it fits, and never of what it is only tested against: a
// schema under not, an if that fails, an alternative it does not fit, or
// what contains looks for. Asked of each schema as it was applied, it did
// not only refuse more there, it changed the answer: an object failed a
// condition for carrying a property the condition happened not to list, so
// one argument more than a call needed walked it past a not that forbade
// it, down else where it belonged in then, and out of the count of oneOf's
// shapes and of maxContains.
package jsonschema

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/plaintext"
)

// maxDepth bounds how far into a value, or a schema, a check goes.
const maxDepth = 32

// maxSteps bounds how much checking one value against one schema takes,
// with stepsPerByte more for each byte of the value, so that a long list
// is not refused for being long. A $ref may name the schema it is in, and
// alternatives that each name it multiply the work at every level: bounded
// by depth alone, a schema a few dozen bytes long would cost billions of
// steps for one call. What following a $ref made of a value is kept, so a
// schema whose parts name each other is followed once for each, and this
// bound is for what is left.
const (
	maxSteps     = 1 << 20
	stepsPerByte = 4
)

// Check reports the first way v does not fit schema, or nil. v is a value
// as encoding/json decodes into any: maps, slices, strings, float64,
// bool and nil.
func Check(schema json.RawMessage, v any) error { return CheckNamed(schema, v, "body") }

// CheckNamed is Check, with the value called name in what it says: a
// request's body is "body", and an MCP tool's arguments are "arguments",
// which is the field a client sent them in.
func CheckNamed(schema json.RawMessage, v any, name string) error {
	if len(schema) == 0 {
		return nil
	}
	var s any
	if err := json.Unmarshal(schema, &s); err != nil {
		return fmt.Errorf("the schema cannot be read: %w", err)
	}
	norm, size, err := normal(v)
	if err != nil {
		return err
	}
	return (&checker{root: s, budget: maxSteps + stepsPerByte*size}).check(s, norm, name)
}

// CheckPart is Check against part, a part of the schema whole, such as one
// property's: a $ref in it points into whole, as it does where the part was
// taken from. Checked alone, a property defined once and pointed at said
// nothing of what it takes.
func CheckPart(whole, part json.RawMessage, v any) error {
	if len(part) == 0 {
		return nil
	}
	var w, p any
	if err := json.Unmarshal(part, &p); err != nil {
		return fmt.Errorf("the schema cannot be read: %w", err)
	}
	if len(whole) > 0 {
		if err := json.Unmarshal(whole, &w); err != nil {
			return fmt.Errorf("the schema cannot be read: %w", err)
		}
	}
	norm, size, err := normal(v)
	if err != nil {
		return err
	}
	return (&checker{root: w, budget: maxSteps + stepsPerByte*size}).check(p, norm, "body")
}

// normal is v round-tripped, so integers and structs arrive as JSON does,
// and how long it is as JSON.
func normal(v any) (any, int, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, 0, err
	}
	var norm any
	if err := json.Unmarshal(b, &norm); err != nil {
		return nil, 0, err
	}
	return norm, len(b), nil
}

// checker is one check of one value: the whole schema, which a $ref points
// into, how much checking it has taken and may take, the patterns it has
// compiled, and what following each $ref made of each part of the value.
type checker struct {
	root          any
	steps, budget int
	patterns      map[string]*regexp.Regexp
	followed      map[followedKey]followed
}

// followedKey is a $ref followed for a part of the value: the part by where
// it is, how deep the check had gone, and the value itself where it can be
// compared, or its address where it cannot. A value decoded from JSON
// shares nothing, so an address is one place in it.
type followedKey struct {
	ref, at string
	depth   int
	value   any
}

type followed struct {
	t   takes
	err error
}

// stopped is an error from a bound on the check rather than from the value.
// It stands wherever it was met: inside an alternative, a check that had to
// stop would be read as a shape the value does not fit, and inside a not,
// as one it does not, so a schema that costs too much to check would be
// one everything fits.
type stopped struct{ error }

func isStopped(err error) bool {
	var s stopped
	return errors.As(err, &s)
}

// address is where an object or a list is, as a key.
type address uintptr

// emptyList is any list with nothing in it, which has no address of its own
// and is the same as any other.
type emptyList struct{}

func identity(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return address(reflect.ValueOf(x).Pointer())
	case []any:
		if len(x) == 0 {
			return emptyList{}
		}
		return address(reflect.ValueOf(x).Pointer())
	}
	return v
}

// taken is what the schemas applied to one object in the value took of it.
type taken struct {
	// at is where the object is, and obj the object, for asking of it at
	// the end.
	at  string
	obj map[string]any
	// names are its properties that one of them named or matched, and
	// listed every property they list, for saying what it takes.
	names, listed map[string]bool
	// lists is whether one of them lists properties, by name or pattern;
	// open is whether one of them took every property, or could not be
	// read for what it takes.
	lists, open bool
	// shared is whether more than one takes holds it, so that it is
	// copied before it is changed rather than every time it is added.
	shared bool
}

func (t *taken) take(k string) {
	if t.names == nil {
		t.names = map[string]bool{}
	}
	t.names[k] = true
}

func (t *taken) list(k string) {
	if t.listed == nil {
		t.listed = map[string]bool{}
	}
	t.listed[k] = true
}

func (t *taken) add(o *taken) {
	for k := range o.names {
		t.take(k)
	}
	for k := range o.listed {
		t.list(k)
	}
	t.lists = t.lists || o.lists
	t.open = t.open || o.open
}

// takes is what the schemas a value fits took of each object in it, by the
// object's address. Made afresh by every schema applied, and added to what
// applied it only when the value fits it, so what a schema the value does
// not fit lists is never taken. What one has made is never changed by
// another: what following a $ref made is kept and handed out again.
type takes map[address]*taken

// of is what has been taken of the object x, at at, to be added to: made
// when nothing has, and copied when another takes holds it too.
func (ts *takes) of(x map[string]any, at string) *taken {
	if *ts == nil {
		*ts = takes{}
	}
	a := address(reflect.ValueOf(x).Pointer())
	t := (*ts)[a]
	switch {
	case t == nil:
		t = &taken{at: at, obj: x}
		(*ts)[a] = t
	case t.shared:
		own := &taken{at: t.at, obj: t.obj}
		own.add(t)
		t = own
		(*ts)[a] = t
	}
	return t
}

// add is what o took added to what ts took, leaving o as it was.
func (ts *takes) add(o takes) {
	for a, t := range o {
		if *ts == nil {
			*ts = takes{}
		}
		if (*ts)[a] == nil {
			t.shared = true
			(*ts)[a] = t
			continue
		}
		ts.of(t.obj, t.at).add(t)
	}
}

// strict is the rule, asked of every object the schemas the value fits
// list properties for: it has none they do not take.
func (ts takes) strict() error {
	objects := make([]*taken, 0, len(ts))
	for _, t := range ts {
		if t.lists && !t.open {
			objects = append(objects, t)
		}
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].at < objects[j].at })
	for _, t := range objects {
		for _, k := range sortedKeys(t.obj) {
			if t.names[k] {
				continue
			}
			where := t.at + "." + named(k)
			if len(t.listed) == 0 {
				return errors.New(where + " is not a property it takes")
			}
			return fmt.Errorf("%s is not a property it takes; it takes %s", where, names(t.listed))
		}
	}
	return nil
}

// check is v against schema: by the standard's rules, and then this
// package's own, that each object in it takes only the properties the
// schemas it fits list for it.
func (c *checker) check(schema any, v any, at string) error {
	t, err := c.apply(schema, v, at, 0)
	if err != nil {
		return err
	}
	return t.strict()
}

// apply is v against schema where v is, by the standard's rules alone, and
// what schema and the schemas it is made of took of each object in v.
func (c *checker) apply(schema any, v any, at string, depth int) (takes, error) {
	var t takes
	c.steps++
	if depth > maxDepth {
		return nil, stopped{fmt.Errorf("%s is nested deeper than %d", at, maxDepth)}
	}
	if c.steps > c.budget {
		return nil, stopped{fmt.Errorf("%s takes more checking than a schema may ask for", at)}
	}
	s, ok := schema.(map[string]any)
	if !ok {
		// true admits everything, false nothing, and what is not a
		// schema at all says nothing of what an object takes.
		b, isBool := schema.(bool)
		if isBool && !b {
			return nil, fmt.Errorf("%s is not allowed", at)
		}
		if x, isObject := v.(map[string]any); isObject && !isBool {
			t.of(x, at).open = true
		}
		return t, nil
	}
	if ref, ok := s["$ref"].(string); ok {
		ft, err := c.follow(ref, v, at, depth)
		if err != nil {
			return nil, err
		}
		t.add(ft)
	}
	if ty, ok := s["type"]; ok {
		if err := checkType(ty, v, at); err != nil {
			return nil, err
		}
	}
	if e, ok := s["enum"].([]any); ok {
		found := false
		for _, x := range e {
			found = found || equal(x, v)
		}
		if !found {
			return nil, fmt.Errorf("%s is not one of the values it may take", at)
		}
	}
	if cv, ok := s["const"]; ok && !equal(cv, v) {
		return nil, fmt.Errorf("%s is not the value it must be", at)
	}
	switch x := v.(type) {
	case string:
		n := float64(utf8.RuneCountInString(x))
		if m, ok := num(s["maxLength"]); ok && n > m {
			return nil, fmt.Errorf("%s is longer than %v characters", at, m)
		}
		if m, ok := num(s["minLength"]); ok && n < m {
			return nil, fmt.Errorf("%s is shorter than %v characters", at, m)
		}
		if p, ok := s["pattern"].(string); ok {
			// ECMA-262 and RE2 differ at the edges; a pattern this program
			// cannot compile constrains nothing rather than refusing all.
			if re := c.compile(p); re != nil && !re.MatchString(x) {
				return nil, fmt.Errorf("%s is not in the form it must be", at)
			}
		}
	case float64:
		if m, ok := num(s["maximum"]); ok && x > m {
			return nil, fmt.Errorf("%s is more than %v", at, m)
		}
		if m, ok := num(s["minimum"]); ok && x < m {
			return nil, fmt.Errorf("%s is less than %v", at, m)
		}
		if m, ok := num(s["exclusiveMaximum"]); ok && x >= m {
			return nil, fmt.Errorf("%s is not less than %v", at, m)
		}
		if m, ok := num(s["exclusiveMinimum"]); ok && x <= m {
			return nil, fmt.Errorf("%s is not more than %v", at, m)
		}
		if m, ok := num(s["multipleOf"]); ok && m > 0 {
			// Within what a float64 can say: 0.07 is a multiple of 0.01,
			// though 0.07 / 0.01 is 7.000000000000001.
			q := x / m
			if !math.IsInf(q, 0) && math.Abs(q-math.Round(q)) > 1e-9*math.Max(1, math.Abs(q)) {
				return nil, fmt.Errorf("%s is not a multiple of %v", at, m)
			}
		}
	case []any:
		it, err := c.array(s, x, at, depth)
		if err != nil {
			return nil, err
		}
		t.add(it)
	case map[string]any:
		ot, err := c.object(s, x, at, depth)
		if err != nil {
			return nil, err
		}
		t.add(ot)
	}
	if all, ok := s["allOf"].([]any); ok {
		for _, sub := range all {
			st, err := c.apply(sub, v, at, depth+1)
			if err != nil {
				return nil, err
			}
			t.add(st)
		}
	}
	if anyOf, ok := s["anyOf"].([]any); ok && len(anyOf) > 0 {
		fits := false
		for _, sub := range anyOf {
			st, err := c.apply(sub, v, at, depth+1)
			if isStopped(err) {
				return nil, err
			}
			if err == nil {
				fits = true
				t.add(st)
			}
		}
		if !fits {
			return nil, fmt.Errorf("%s fits none of the shapes it may take", at)
		}
	}
	if oneOf, ok := s["oneOf"].([]any); ok && len(oneOf) > 0 {
		n := 0
		var one takes
		for _, sub := range oneOf {
			st, err := c.apply(sub, v, at, depth+1)
			if isStopped(err) {
				return nil, err
			}
			if err == nil {
				n, one = n+1, st
			}
		}
		if n != 1 {
			return nil, fmt.Errorf("%s fits %d of the shapes it may take, and must fit exactly one", at, n)
		}
		t.add(one)
	}
	if not, ok := s["not"]; ok {
		_, err := c.apply(not, v, at, depth+1)
		if isStopped(err) {
			return nil, err
		}
		if err == nil {
			return nil, fmt.Errorf("%s is in a shape it must not be", at)
		}
	}
	if cond, ok := s["if"]; ok {
		branch, has := s["else"]
		it, err := c.apply(cond, v, at, depth+1)
		if isStopped(err) {
			return nil, err
		}
		if err == nil {
			t.add(it)
			branch, has = s["then"]
		}
		if has {
			bt, err := c.apply(branch, v, at, depth+1)
			if err != nil {
				return nil, err
			}
			t.add(bt)
		}
	}
	if x, ok := v.(map[string]any); ok {
		if err := c.unevaluated(s, x, at, depth, &t); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// array is the keywords about a list's items, and what the schemas its
// items fit took of the objects in them.
func (c *checker) array(s map[string]any, x []any, at string, depth int) (takes, error) {
	var t takes
	if m, ok := num(s["maxItems"]); ok && float64(len(x)) > m {
		return nil, fmt.Errorf("%s has more than %v items", at, m)
	}
	if m, ok := num(s["minItems"]); ok && float64(len(x)) < m {
		return nil, fmt.Errorf("%s has fewer than %v items", at, m)
	}
	if u, _ := s["uniqueItems"].(bool); u {
		// By their encoding, which sorts an object's keys: two items are
		// the same where JSON says they are.
		seen := make(map[string]int, len(x))
		for i, item := range x {
			b, err := json.Marshal(item)
			if err != nil {
				continue
			}
			if j, dup := seen[string(b)]; dup {
				return nil, fmt.Errorf("%s[%d] is the same as %s[%d], and its items must differ", at, i, at, j)
			}
			seen[string(b)] = i
		}
	}
	// The first items each to a schema of their own, and the rest to
	// items; before 2020-12, items as a list and additionalItems.
	prefix, _ := s["prefixItems"].([]any)
	rest, hasRest := s["items"]
	if tuple, ok := rest.([]any); ok {
		prefix = tuple
		rest, hasRest = s["additionalItems"]
	}
	for i, item := range x {
		where := fmt.Sprintf("%s[%d]", at, i)
		var it takes
		var err error
		switch {
		case i < len(prefix):
			it, err = c.apply(prefix[i], item, where, depth+1)
		case hasRest:
			it, err = c.apply(rest, item, where, depth+1)
		}
		if err != nil {
			return nil, err
		}
		t.add(it)
	}
	// What contains looks for is a test of each item, not a shape it is
	// held to, so what it lists of one is not taken.
	if want, ok := s["contains"]; ok {
		least, most := 1.0, math.Inf(1)
		if m, ok := num(s["minContains"]); ok {
			least = m
		}
		if m, ok := num(s["maxContains"]); ok {
			most = m
		}
		n := 0.0
		for i, item := range x {
			_, err := c.apply(want, item, fmt.Sprintf("%s[%d]", at, i), depth+1)
			if isStopped(err) {
				return nil, err
			}
			if err == nil {
				n++
			}
		}
		switch {
		case n < least && least == 1:
			return nil, fmt.Errorf("%s has no item of the shape it must have", at)
		case n < least:
			return nil, fmt.Errorf("%s has fewer than %v items of the shape it must have", at, least)
		case n > most:
			return nil, fmt.Errorf("%s has more than %v items of the shape it may have", at, most)
		}
	}
	return t, nil
}

// object is the keywords about an object's properties, and what the schema
// takes of it and of the objects in it.
func (c *checker) object(s map[string]any, x map[string]any, at string, depth int) (takes, error) {
	var t takes
	props, _ := s["properties"].(map[string]any)
	if props != nil {
		own := t.of(x, at)
		own.lists = true
		for k := range props {
			own.list(k)
		}
	}
	if req, ok := s["required"].([]any); ok {
		for _, r := range req {
			if name, ok := r.(string); ok {
				if _, present := x[name]; !present {
					return nil, fmt.Errorf("%s needs %s", at, name)
				}
			}
		}
	}
	if m, ok := num(s["maxProperties"]); ok && float64(len(x)) > m {
		return nil, fmt.Errorf("%s has more than %v properties", at, m)
	}
	if m, ok := num(s["minProperties"]); ok && float64(len(x)) < m {
		return nil, fmt.Errorf("%s has fewer than %v properties", at, m)
	}
	// A property that needs others, as dependentRequired has it and as
	// dependencies did with a list.
	for _, key := range []string{"dependentRequired", "dependencies"} {
		deps, _ := s[key].(map[string]any)
		for _, k := range sortedKeys(deps) {
			need, isList := deps[k].([]any)
			if _, present := x[k]; !present || !isList {
				continue
			}
			for _, n := range need {
				if name, ok := n.(string); ok {
					if _, present := x[name]; !present {
						return nil, fmt.Errorf("%s needs %s, as it has %s", at, name, named(k))
					}
				}
			}
		}
	}
	keys := sortedKeys(x)
	if pn, ok := s["propertyNames"]; ok {
		for _, k := range keys {
			if _, err := c.apply(pn, k, at, depth+1); isStopped(err) {
				return nil, err
			} else if err != nil {
				return nil, fmt.Errorf("%s.%s is not a name it takes", at, named(k))
			}
		}
	}
	type pattern struct {
		re     *regexp.Regexp
		schema any
	}
	var patterns []pattern
	if pp, ok := s["patternProperties"].(map[string]any); ok && len(pp) > 0 {
		own := t.of(x, at)
		own.lists = true
		for _, p := range sortedKeys(pp) {
			re := c.compile(p)
			if re == nil {
				// Which names it takes cannot be told, so it takes any.
				own.open = true
				continue
			}
			patterns = append(patterns, pattern{re, pp[p]})
		}
	}
	extra, hasExtra := s["additionalProperties"]
	for _, k := range keys {
		where := at + "." + named(k)
		matched := false
		if p, ok := props[k]; ok {
			matched = true
			pt, err := c.apply(p, x[k], where, depth+1)
			if err != nil {
				return nil, err
			}
			t.add(pt)
		}
		for _, p := range patterns {
			if p.re.MatchString(k) {
				matched = true
				pt, err := c.apply(p.schema, x[k], where, depth+1)
				if err != nil {
					return nil, err
				}
				t.add(pt)
			}
		}
		if matched {
			t.of(x, at).take(k)
			continue
		}
		if hasExtra {
			// A bound met beneath it stands as itself: read as a property
			// it does not take, under a not it would be one it does.
			et, err := c.apply(extra, x[k], where, depth+1)
			if isStopped(err) {
				return nil, err
			} else if err != nil {
				return nil, errors.New(where + " is not a property it takes")
			}
			t.add(et)
		}
	}
	if hasExtra {
		t.of(x, at).open = true
	}
	return t, nil
}

// unevaluated is the keywords applied to an object once the rest of its
// schema has been: the schemas its properties call for, and what to make of
// the properties none of the schemas applied to it took.
func (c *checker) unevaluated(s map[string]any, x map[string]any, at string, depth int, t *takes) error {
	for _, key := range []string{"dependencies", "dependentSchemas"} {
		deps, _ := s[key].(map[string]any)
		for _, k := range sortedKeys(deps) {
			if _, isList := deps[k].([]any); isList {
				continue
			}
			if _, present := x[k]; !present {
				continue
			}
			dt, err := c.apply(deps[k], x, at, depth+1)
			if err != nil {
				return err
			}
			t.add(dt)
		}
	}
	u, ok := s["unevaluatedProperties"]
	if !ok {
		return nil
	}
	own := t.of(x, at)
	if own.open {
		return nil
	}
	for _, k := range sortedKeys(x) {
		if own.names[k] {
			continue
		}
		where := at + "." + named(k)
		ut, err := c.apply(u, x[k], where, depth+1)
		if isStopped(err) {
			return err
		} else if err != nil {
			return errors.New(where + " is not a property it takes")
		}
		t.add(ut)
	}
	t.of(x, at).open = true
	return nil
}

// follow applies what a $ref names to v, once for each part of the value
// at each depth, and is what it took. One it cannot follow says nothing of
// what an object takes, so the object takes any property.
func (c *checker) follow(ref string, v any, at string, depth int) (takes, error) {
	key := followedKey{ref: ref, at: at, depth: depth, value: identity(v)}
	f, ok := c.followed[key]
	if !ok {
		target, found := c.resolve(ref)
		if !found {
			if x, isObject := v.(map[string]any); isObject {
				f.t.of(x, at).open = true
			}
		} else {
			f.t, f.err = c.apply(target, v, at, depth+1)
		}
		if c.followed == nil {
			c.followed = map[followedKey]followed{}
		}
		c.followed[key] = f
	}
	return f.t, f.err
}

// resolve is what a $ref names in the schema it is part of: the whole
// schema, or a part of it by a JSON pointer, as "#/$defs/address" is. A
// $ref to anywhere else, or to an anchor, is not followed, and nothing is
// fetched: a schema validator that dereferences a URL is a server-side
// request forgery (internal/schema).
func (c *checker) resolve(ref string) (any, bool) {
	frag, ok := strings.CutPrefix(ref, "#")
	if !ok {
		return nil, false
	}
	if frag == "" {
		return c.root, c.root != nil
	}
	if u, err := url.PathUnescape(frag); err == nil {
		frag = u
	}
	if !strings.HasPrefix(frag, "/") {
		return nil, false
	}
	node := c.root
	for _, part := range strings.Split(frag[1:], "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		switch n := node.(type) {
		case map[string]any:
			if node, ok = n[part]; !ok {
				return nil, false
			}
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(n) {
				return nil, false
			}
			node = n[i]
		default:
			return nil, false
		}
	}
	return node, true
}

// compile is a pattern compiled once for the check, or nil for one RE2
// does not compile.
func (c *checker) compile(p string) *regexp.Regexp {
	if re, ok := c.patterns[p]; ok {
		return re
	}
	if c.patterns == nil {
		c.patterns = map[string]*regexp.Regexp{}
	}
	re, err := regexp.Compile(p)
	if err != nil {
		re = nil
	}
	c.patterns[p] = re
	return re
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// named is a property's name as an answer says it: enough to say which,
// and no more.
//
// The name is the value's own. For a tool's arguments that is whatever a
// caller of the agent interface sent, up to the whole body of the request,
// and an answer that named it whole was as long: a megabyte sent back for
// one argument nobody takes, where a tool or an operation nobody has is
// quoted in eighty bytes (internal/mcp's quoteName).
func named(k string) string { return plaintext.Clip(k, 80, "…") }

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

func names(props map[string]bool) string {
	out := sortedKeys(props)
	if len(out) > 12 {
		out = append(out[:12], "…")
	}
	return strings.Join(out, ", ")
}
