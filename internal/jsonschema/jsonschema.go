// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package jsonschema checks a value against the part of JSON Schema that
// API descriptions and structured output use: types, properties and which
// are required, how many properties, items and prefixItems, uniqueItems,
// enumerations and constants, lengths, patterns, bounds and multipleOf,
// allOf, anyOf, oneOf and not, and references to another part of the same
// schema ($ref, as $defs and recursive schemas are written). What a model
// was held to as it wrote (CheckAnswer) is held to its string formats too.
// A keyword it does not know, or a reference to anywhere else, constrains
// nothing.
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
	"net/mail"
	"net/netip"
	"net/url"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// maxDepth bounds how far into a value, or a schema, a check goes.
const maxDepth = 32

// maxSteps bounds the work of one check, to about a quarter of a second
// on a small machine. A step is one part of the value checked against one
// part of the schema, about a microsecond, and whatever else that costs is
// counted with it: a string read for its length or its form, a pattern
// compiled and run, an enumeration searched, an object's properties put
// in order. Counting visits alone would not do, since one visit can cost a
// great deal and a schema can come from whoever is calling: one that
// refers to itself can be a few bytes and still ask for more work than
// there is time for, as two references to itself under anyOf double the
// work at every level. A value that fits a schema written in good faith
// takes a few steps for each of its parts, so only one of a megabyte or
// more would come near it.
const maxSteps = 250000

// stringBytes is how much of a string one step reads: counting its
// characters, comparing it, or checking its form.
const stringBytes = 32

// patternWork is how much of a pattern match one step is: Go's regular
// expressions take time in proportion to the size of the compiled pattern
// times the length of the string, at worst about ten nanoseconds for each.
const patternWork = 32

// maxPattern bounds a pattern, which is compiled before what it costs is
// known; a longer one is more than this checks, and says so.
const maxPattern = 4096

// checker is one check: the schema it began with, which a reference
// points into, and the work done so far.
type checker struct {
	root  any
	steps int
	// formats holds a string to its format.
	formats bool
	// patterns are the patterns compiled in this check, so each is
	// compiled once however often it is met.
	patterns map[string]compiled
}

// compiled is a pattern as a check runs it, and what its program costs;
// re is nil for one that does not compile.
type compiled struct {
	re   *regexp.Regexp
	size int
}

// Check reports the first way v does not fit schema, or nil. v is a value
// as encoding/json decodes into any: maps, slices, strings, float64,
// bool and nil. What it says calls the value "body", as the body of an
// API request is checked.
func Check(schema json.RawMessage, v any) error {
	return check(schema, v, "body", false)
}

// CheckAnswer is Check for what a model wrote to a schema it was held to
// as it wrote: an answer as structured output, or a strict tool's
// arguments. What it says calls the value name. A string is held to its
// format (date-time, email, uuid and the rest), as the providers'
// structured output holds it; Check leaves format alone, since in an API
// description it is as often a note as a rule.
func CheckAnswer(schema json.RawMessage, v any, name string) error {
	return check(schema, v, name, true)
}

func check(schema json.RawMessage, v any, name string, formats bool) error {
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
	c := &checker{root: s, formats: formats, patterns: map[string]compiled{}}
	return c.check(s, norm, name, 0)
}

// spend counts work, and reports whether it is more than a check may do.
func (c *checker) spend(n int) bool {
	c.steps += n
	return c.steps > maxSteps
}

func (c *checker) check(schema any, v any, at string, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("%s is nested deeper than %d", at, maxDepth)
	}
	if c.spend(1) {
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
		if err := c.checkType(t, v, at); err != nil {
			return err
		}
	}
	if e, ok := s["enum"].([]any); ok {
		found := false
		for _, x := range e {
			if found = c.same(x, v); found {
				break
			}
		}
		if c.steps > maxSteps {
			return c.tooMuch(at)
		}
		if !found {
			return fmt.Errorf("%s is not one of the values it may take", at)
		}
	}
	if k, ok := s["const"]; ok {
		same := c.same(k, v)
		if c.steps > maxSteps {
			return c.tooMuch(at)
		}
		if !same {
			return fmt.Errorf("%s is not the value it must be", at)
		}
	}
	switch x := v.(type) {
	case string:
		if err := c.checkString(s, x, at); err != nil {
			return err
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
		if m, ok := num(s["multipleOf"]); ok && m > 0 {
			// Within rounding, so 0.3 is a multiple of 0.1, as it is
			// written if not as it is stored.
			q := x / m
			if math.IsInf(q, 0) || math.IsNaN(q) || math.Abs(q-math.Round(q)) > 1e-9*math.Max(1, math.Abs(q)) {
				return fmt.Errorf("%s is not a multiple of %v", at, m)
			}
		}
	case []any:
		if err := c.checkArray(s, x, at, depth); err != nil {
			return err
		}
	case map[string]any:
		if err := c.checkObject(s, x, at, depth); err != nil {
			return err
		}
	}
	if ref, ok := s["$ref"].(string); ok {
		if c.spend(len(ref) / stringBytes) {
			return c.tooMuch(at)
		}
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
			if fits = c.check(sub, v, at, depth+1) == nil; fits || c.steps > maxSteps {
				break
			}
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
			if c.steps > maxSteps {
				return c.tooMuch(at)
			}
		}
		if n != 1 {
			return fmt.Errorf("%s fits %d of the shapes it may take, and must fit exactly one", at, n)
		}
	}
	if not, ok := s["not"]; ok {
		fits := c.check(not, v, at, depth+1) == nil
		if c.steps > maxSteps {
			return c.tooMuch(at)
		}
		if fits {
			return fmt.Errorf("%s is in a shape it must not take", at)
		}
	}
	return nil
}

func (c *checker) tooMuch(at string) error {
	return fmt.Errorf("%s takes more than %d steps to check against its schema", at, maxSteps)
}

// checkString holds a string to its length, its pattern and its format.
func (c *checker) checkString(s map[string]any, x string, at string) error {
	maxLen, hasMax := num(s["maxLength"])
	minLen, hasMin := num(s["minLength"])
	format, _ := s["format"].(string)
	if hasMax || hasMin || (c.formats && format != "") {
		if c.spend(len(x) / stringBytes) {
			return c.tooMuch(at)
		}
	}
	if hasMax || hasMin {
		n := float64(utf8.RuneCountInString(x))
		if hasMax && n > maxLen {
			return fmt.Errorf("%s is longer than %v characters", at, maxLen)
		}
		if hasMin && n < minLen {
			return fmt.Errorf("%s is shorter than %v characters", at, minLen)
		}
	}
	if p, ok := s["pattern"].(string); ok {
		re, err := c.pattern(p, at)
		if err != nil {
			return err
		}
		// What a match costs is counted before it is run, so a pattern of
		// thousands of states over a long string is refused, not run.
		if re.re != nil {
			if c.spend(re.size * (len(x) + 1) / patternWork) {
				return c.tooMuch(at)
			}
			if !re.re.MatchString(x) {
				return fmt.Errorf("%s is not in the form it must be", at)
			}
		}
	}
	if c.formats && format != "" && !inFormat(format, x) {
		return fmt.Errorf("%s is not in the format %s", at, format)
	}
	return nil
}

// pattern compiles a pattern once a check, counting the work: its length
// to read it, and the size of what it compiles to.
func (c *checker) pattern(p string, at string) (compiled, error) {
	if c.spend(len(p) / stringBytes) {
		return compiled{}, c.tooMuch(at)
	}
	if got, ok := c.patterns[p]; ok {
		return got, nil
	}
	if len(p) > maxPattern {
		return compiled{}, fmt.Errorf("%s has a pattern longer than %d bytes, which is more than this checks", at, maxPattern)
	}
	// ECMA-262 and RE2 differ at the edges; a pattern this program cannot
	// compile constrains nothing rather than refusing all.
	var got compiled
	if parsed, err := syntax.Parse(p, syntax.Perl); err == nil {
		if prog, err := syntax.Compile(parsed.Simplify()); err == nil {
			got.size = len(prog.Inst)
			if c.spend(len(p) + got.size) {
				return compiled{}, c.tooMuch(at)
			}
			got.re, _ = regexp.Compile(p)
		}
	}
	c.patterns[p] = got
	return got, nil
}

var (
	reDuration = regexp.MustCompile(`^P(\d+Y)?(\d+M)?(\d+W)?(\d+D)?(T(\d+H)?(\d+M)?(\d+(\.\d+)?S)?)?$`)
	reUUID     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reLabel    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

// inFormat reports whether s is in the form a format names, for the
// formats OpenAI's and Anthropic's structured output hold an answer to.
// Any other format constrains nothing.
func inFormat(format, s string) bool {
	switch format {
	case "date-time":
		_, err := time.Parse(time.RFC3339Nano, s)
		return err == nil
	case "date":
		_, err := time.Parse(time.DateOnly, s)
		return err == nil
	case "time":
		// A fraction of a second is read after the seconds without being
		// in the layout.
		_, err := time.Parse("15:04:05Z07:00", s)
		return err == nil
	case "duration":
		return reDuration.MatchString(s) && s != "P" && !strings.HasSuffix(s, "T")
	case "email":
		if len(s) > 254 {
			return false
		}
		a, err := mail.ParseAddress(s)
		return err == nil && a.Name == "" && a.Address == s
	case "hostname":
		if s == "" || len(s) > 253 {
			return false
		}
		for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
			if !reLabel.MatchString(label) {
				return false
			}
		}
		return true
	case "ipv4":
		a, err := netip.ParseAddr(s)
		return err == nil && a.Is4()
	case "ipv6":
		a, err := netip.ParseAddr(s)
		return err == nil && a.Is6() && a.Zone() == ""
	case "uuid":
		return reUUID.MatchString(s)
	case "uri":
		u, err := url.Parse(s)
		return err == nil && u.Scheme != ""
	}
	return true
}

// same reports whether two values are the same JSON, counting the work of
// comparing them: an enumeration of thousands, or one long value, is
// work, and a reference can ask for it again and again.
func (c *checker) same(a, b any) bool {
	c.steps++
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, xv := range x {
			c.steps += len(k) / stringBytes
			yv, ok := y[k]
			if !ok || !c.same(xv, yv) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !c.same(x[i], y[i]) {
				return false
			}
		}
		return true
	case string:
		y, ok := b.(string)
		if !ok || len(x) != len(y) {
			return false
		}
		c.steps += len(x) / stringBytes
		return x == y
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case nil:
		return b == nil
	}
	return false
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

func (c *checker) checkArray(s map[string]any, x []any, at string, depth int) error {
	if m, ok := num(s["maxItems"]); ok && float64(len(x)) > m {
		return fmt.Errorf("%s has more than %v items", at, m)
	}
	if m, ok := num(s["minItems"]); ok && float64(len(x)) < m {
		return fmt.Errorf("%s has fewer than %v items", at, m)
	}
	if unique, _ := s["uniqueItems"].(bool); unique {
		// Each item as JSON, whose objects are written with their keys in
		// order, so the same item is the same text: one pass, rather than
		// comparing every item with every other.
		seen := make(map[string]int, len(x))
		for i, item := range x {
			b, err := json.Marshal(item)
			if err != nil {
				return err
			}
			if c.spend(1 + len(b)/stringBytes) {
				return c.tooMuch(at)
			}
			if j, ok := seen[string(b)]; ok {
				return fmt.Errorf("%s has the same item twice, at %d and %d", at, j, i)
			}
			seen[string(b)] = i
		}
	}
	// prefixItems are the first items' shapes, one each, and items the
	// shape of every item after them.
	prefix, _ := s["prefixItems"].([]any)
	items, hasItems := s["items"]
	for i, item := range x {
		var sub any
		switch {
		case i < len(prefix):
			sub = prefix[i]
		case hasItems:
			sub = items
		default:
			continue
		}
		if err := c.check(sub, item, fmt.Sprintf("%s[%d]", at, i), depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (c *checker) checkObject(s map[string]any, x map[string]any, at string, depth int) error {
	props, _ := s["properties"].(map[string]any)
	if req, ok := s["required"].([]any); ok {
		if c.spend(len(req)) {
			return c.tooMuch(at)
		}
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
	if m, ok := num(s["minProperties"]); ok && float64(len(x)) < m {
		return fmt.Errorf("%s has fewer than %v properties", at, m)
	}
	extra, hasExtra := s["additionalProperties"]
	if props == nil && !hasExtra {
		return nil
	}
	// Putting the properties in order, so the first one wrong is the same
	// every time, is work in proportion to how many there are.
	if c.spend(len(x)) {
		return c.tooMuch(at)
	}
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

func (c *checker) checkType(t any, v any, at string) error {
	var types []string
	switch x := t.(type) {
	case string:
		types = []string{x}
	case []any:
		if c.spend(len(x)) {
			return c.tooMuch(at)
		}
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
