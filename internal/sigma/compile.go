// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package sigma

import (
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/detect"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Pipeline adapts a rule's field names to a deployment's events.
//
// Sigma rules name fields the way their source names them — CommandLine,
// ParentImage, EventID — and every SIEM stores those under different names.
// The standard's answer is a processing pipeline held separately from the
// rules, so the rules stay portable and the mapping is the thing that
// changes per deployment. This is that, and it is the place a customer
// adjusts rather than editing three thousand rules.
//
// Unmapped names go to raw.<name>, because internal/telemetry keeps
// whatever a connector sent under that prefix so a source cannot shadow a
// normalised field by calling one of its own attributes "severity".
type Pipeline struct {
	// Fields maps a Sigma field name to an event field.
	Fields map[string]string `json:"fields,omitempty"`
	// Source overrides the source a rule reads, for a deployment whose
	// connector is not named the way the rule's logsource is.
	Source string `json:"source,omitempty"`
}

// native are the fields internal/telemetry normalises, which a rule may
// name directly.
var native = map[string]bool{
	"source": true, "class": true, "activity": true, "severity": true,
	"disposition": true, "message": true,
	"actor": true, "actor.issuer": true, "actor.value": true,
	"target": true, "target.issuer": true, "target.value": true,
	"device": true, "device.issuer": true, "device.value": true,
}

func init() {
	// The observable kinds, which Fields exposes by name so a rule can ask
	// for "any ip" without knowing which attribute carried it.
	for k := telemetry.ObservableOther; k <= telemetry.ObservableUserAgent; k++ {
		native[k.String()] = true
	}
}

// field is where a Sigma field name lands in an event.
func (p Pipeline) field(name string) string {
	if to, ok := p.Fields[name]; ok {
		return to
	}
	if native[strings.ToLower(name)] {
		return strings.ToLower(name)
	}
	return "raw." + name
}

// selection compiles one named block of a detection.
//
// A map is a set of field tests that must all hold. A list of maps is a set
// of alternatives, any of which may hold. That asymmetry is the Sigma
// specification's and it is the single thing most often got wrong by people
// reading a rule quickly, which is why it is stated here rather than
// assumed.
func selection(pipe Pipeline, rule, name string, body any) (detect.Predicate, error) {
	switch t := body.(type) {
	case map[string]any:
		return allOf(pipe, rule, name, t)
	case []any:
		var any_ []detect.Predicate
		for i, e := range t {
			switch m := e.(type) {
			case map[string]any:
				p, err := allOf(pipe, rule, name, m)
				if err != nil {
					return detect.Predicate{}, err
				}
				any_ = append(any_, p)
			case string:
				// A bare list of strings is a keyword search across the
				// whole event. Refused rather than guessed: which field it
				// searches is a decision about the data, and a rule that
				// silently searched a field this program happens to call
				// "message" would be a different rule from the one its
				// author reviewed.
				return detect.Predicate{}, &Unsupported{
					Rule: rule, What: "a bare keyword list in " + name,
					Why: "it searches the whole event, and which fields " +
						"that means is a property of the log source rather " +
						"than of the rule. Give the field explicitly",
				}
			default:
				return detect.Predicate{}, fmt.Errorf(
					"%s: item %d of %s is neither a field test nor a "+
						"keyword", rule, i+1, name)
			}
		}
		if len(any_) == 1 {
			return any_[0], nil
		}
		return detect.Predicate{Any: any_}, nil
	case string:
		return detect.Predicate{}, &Unsupported{
			Rule: rule, What: "a bare keyword in " + name,
			Why: "give the field it should be looked for in",
		}
	}
	return detect.Predicate{}, fmt.Errorf("%s: %s is not a selection",
		rule, name)
}

func allOf(pipe Pipeline, rule, name string, m map[string]any) (detect.Predicate, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var all []detect.Predicate
	for _, k := range keys {
		p, err := test(pipe, rule, name, k, m[k])
		if err != nil {
			return detect.Predicate{}, err
		}
		all = append(all, p)
	}
	if len(all) == 1 {
		return all[0], nil
	}
	return detect.Predicate{All: all}, nil
}

// test compiles one "Field|modifiers: value" entry.
func test(pipe Pipeline, rule, name, key string, v any) (detect.Predicate, error) {
	parts := strings.Split(key, "|")
	named := strings.TrimSpace(parts[0])
	field := pipe.field(named)
	mods := parts[1:]

	values := strs(v)
	if len(values) == 0 {
		if s, ok := v.(string); ok {
			values = []string{s}
		}
	}

	op := detect.Equals
	everyValue := false
	expand := func(s string) []string { return []string{s} }

	for _, raw := range mods {
		m := strings.ToLower(strings.TrimSpace(raw))
		switch m {
		case "contains":
			op = detect.Contains
		case "startswith":
			op = detect.Prefix
		case "endswith":
			op = detect.Suffix
		case "re":
			op = detect.Matches
		case "cidr":
			op = detect.Inside
		case "gt":
			op = detect.Above
		case "lt":
			op = detect.Below
		case "all":
			// Every value must match, rather than any of them. Sigma's own
			// note is that this only makes sense with contains, and the
			// commonest mistake in the corpus is using it with an implicit
			// equality, where it asks for one field to equal two things.
			everyValue = true
		case "base64offset":
			expand = b64offsets
		case "windash":
			expand = windash
		case "gte", "lte":
			return detect.Predicate{}, &Unsupported{
				Rule: rule, What: "the " + m + " modifier on " + field,
				Why: "this compares strictly, and an inclusive comparison " +
					"written as a strict one is off by exactly the value " +
					"somebody chose the threshold for. Write it as the " +
					"neighbouring integer, or as two tests",
			}
		case "base64":
			return detect.Predicate{}, &Unsupported{
				Rule: rule, What: "the base64 modifier on " + field,
				Why: "it matches only when the string begins at a " +
					"three-byte boundary, which is one case in three. " +
					"base64offset is the one that works and this refuses " +
					"to pretend they are the same",
			}
		default:
			return detect.Predicate{}, &Unsupported{
				Rule: rule, What: "the " + m + " modifier on " + field,
				Why: "it has no equivalent here",
			}
		}
	}

	// null: true is a test for absence, which is Sigma's way of saying the
	// field must not be there.
	if len(values) == 1 && isNull(v) {
		return detect.Predicate{
			Not: &detect.Predicate{
				Match: &detect.Match{Field: field, Op: detect.Exists},
			},
		}, nil
	}
	if len(values) == 0 {
		return detect.Predicate{}, fmt.Errorf(
			"%s: %s in %s has nothing to compare against", rule, field, name)
	}

	var widened []string
	for _, val := range values {
		widened = append(widened, expand(val)...)
	}
	if len(widened) == 0 {
		return detect.Predicate{}, fmt.Errorf(
			"%s: %s in %s expanded to nothing", rule, field, name)
	}

	if everyValue {
		var all []detect.Predicate
		for _, val := range widened {
			all = append(all, detect.Predicate{
				Match: &detect.Match{Field: field, Op: op,
					Values: []string{val}},
			})
		}
		if len(all) == 1 {
			return all[0], nil
		}
		return detect.Predicate{All: all}, nil
	}
	return detect.Predicate{
		Match: &detect.Match{Field: field, Op: op, Values: widened},
	}, nil
}

func isNull(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "null", "~", "":
		return true
	}
	return false
}

// condition parses Sigma's condition language.
//
// The grammar is small: names, "and", "or", "not", parentheses, and the
// quantifiers "1 of x", "all of x", "any of x", where x is a name, a
// wildcard like selection_* or the word "them". Aggregations — count() by
// something, over a timeframe — are a different shape of question and are
// refused by name rather than approximated.
func condition(rule, src string, sels map[string]detect.Predicate,
	names []string) (detect.Predicate, error) {
	if strings.Contains(src, "|") {
		return detect.Predicate{}, &Unsupported{
			Rule: rule, What: "an aggregation in the condition",
			Why: "counting events over a window is a different question " +
				"from matching one, and answering it by matching each " +
				"event on its own would produce a rule that fires on the " +
				"first occurrence of something defined as a threshold",
		}
	}
	p := &parser{rule: rule, sels: sels, names: names,
		toks: lex(src)}
	out, err := p.expr()
	if err != nil {
		return detect.Predicate{}, err
	}
	if p.at < len(p.toks) {
		return detect.Predicate{}, fmt.Errorf(
			"%s: the condition has %q left over after %q", rule,
			strings.Join(p.toks[p.at:], " "), src)
	}
	return out, nil
}

func lex(s string) []string {
	s = strings.ReplaceAll(s, "(", " ( ")
	s = strings.ReplaceAll(s, ")", " ) ")
	return strings.Fields(s)
}

type parser struct {
	rule  string
	sels  map[string]detect.Predicate
	names []string
	toks  []string
	at    int
}

func (p *parser) peek() string {
	if p.at < len(p.toks) {
		return strings.ToLower(p.toks[p.at])
	}
	return ""
}

func (p *parser) next() string {
	t := p.toks[p.at]
	p.at++
	return t
}

// expr is a sequence of terms joined by "or".
func (p *parser) expr() (detect.Predicate, error) {
	first, err := p.term()
	if err != nil {
		return first, err
	}
	any_ := []detect.Predicate{first}
	for p.peek() == "or" {
		p.next()
		t, err := p.term()
		if err != nil {
			return t, err
		}
		any_ = append(any_, t)
	}
	if len(any_) == 1 {
		return any_[0], nil
	}
	return detect.Predicate{Any: any_}, nil
}

// term is a sequence of factors joined by "and".
func (p *parser) term() (detect.Predicate, error) {
	first, err := p.factor()
	if err != nil {
		return first, err
	}
	all := []detect.Predicate{first}
	for p.peek() == "and" {
		p.next()
		f, err := p.factor()
		if err != nil {
			return f, err
		}
		all = append(all, f)
	}
	if len(all) == 1 {
		return all[0], nil
	}
	return detect.Predicate{All: all}, nil
}

func (p *parser) factor() (detect.Predicate, error) {
	switch t := p.peek(); {
	case t == "":
		return detect.Predicate{}, fmt.Errorf(
			"%s: the condition ends where a selection was expected",
			p.rule)
	case t == "not":
		p.next()
		inner, err := p.factor()
		if err != nil {
			return inner, err
		}
		return detect.Predicate{Not: &inner}, nil
	case t == "(":
		p.next()
		inner, err := p.expr()
		if err != nil {
			return inner, err
		}
		if p.peek() != ")" {
			return inner, fmt.Errorf("%s: a bracket is not closed", p.rule)
		}
		p.next()
		return inner, nil
	case t == "1" || t == "all" || t == "any":
		return p.quantified()
	}
	name := p.next()
	sel, ok := p.sels[name]
	if !ok {
		return detect.Predicate{}, fmt.Errorf(
			"%s: the condition names %q and the detection block does not "+
				"define it. The defined ones are %s", p.rule, name,
			strings.Join(p.names, ", "))
	}
	return sel, nil
}

// quantified handles "1 of x", "all of x" and "any of x".
func (p *parser) quantified() (detect.Predicate, error) {
	q := strings.ToLower(p.next())
	if p.peek() != "of" {
		return detect.Predicate{}, fmt.Errorf(
			"%s: %q is followed by %q where \"of\" was expected", p.rule,
			q, p.peek())
	}
	p.next()
	if p.at >= len(p.toks) {
		return detect.Predicate{}, fmt.Errorf(
			"%s: %q of what?", p.rule, q)
	}
	pattern := p.next()
	matched, err := p.matching(pattern)
	if err != nil {
		return detect.Predicate{}, err
	}
	if q == "all" {
		if len(matched) == 1 {
			return matched[0], nil
		}
		return detect.Predicate{All: matched}, nil
	}
	if len(matched) == 1 {
		return matched[0], nil
	}
	return detect.Predicate{Any: matched}, nil
}

func (p *parser) matching(pattern string) ([]detect.Predicate, error) {
	var out []detect.Predicate
	var used []string
	for _, n := range p.names {
		if pattern == "them" || globs(pattern, n) {
			out = append(out, p.sels[n])
			used = append(used, n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf(
			"%s: %q matches none of the selections, which are %s. A "+
				"quantifier over nothing is a rule that either never fires "+
				"or always does, and neither is what was meant",
			p.rule, pattern, strings.Join(p.names, ", "))
	}
	return out, nil
}

// globs matches a Sigma selection pattern, which uses * as a wildcard.
func globs(pattern, name string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == name
	}
	parts := strings.Split(pattern, "*")
	rest := name
	if parts[0] != "" {
		if !strings.HasPrefix(rest, parts[0]) {
			return false
		}
		rest = rest[len(parts[0]):]
	}
	for i := 1; i < len(parts); i++ {
		p := parts[i]
		if p == "" {
			continue
		}
		if i == len(parts)-1 {
			return strings.HasSuffix(rest, p)
		}
		j := strings.Index(rest, p)
		if j < 0 {
			return false
		}
		rest = rest[j+len(p):]
	}
	return true
}
