// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/plaintext"
)

// The invariants of a field, read from its type and its tag.
//
// The generic record store validates against a schema a person edits, and its
// batch path skips even that. The register cannot rest on either: its records
// are evidence, and a record that was never held to its kind's rules is
// addressable in an append-only store for ever. So the rules are Go, they are
// part of the kind, and Put runs them on every record of every batch.
//
// A field's tag is `reg:"…"`, a comma-separated list:
//
//	required     a record without the field is refused
//	label        a short single line a person reads: a title, a reference
//	slug         a lowercase machine name: letters, digits, dot, dash, underscore
//	host         one exact DNS name, never a pattern or an address
//	oid          the identifier of a store object: 64 hexadecimal characters
//	ref=Kind     the kind an id points at
//	min=N max=N  bounds of a number, or of how many a list holds
//
// and `about:"…"` says what the field is for. A plain string must be a
// label, a slug, a host or an oid. There is no tag for free text, because
// free text does not go in a record: it is a Text, the digest of words kept
// where they can be erased.

var (
	typeID     = reflect.TypeOf(ID(""))
	typeDigest = reflect.TypeOf(Digest(""))
	typeText   = reflect.TypeOf(Text(""))
	typeTime   = reflect.TypeOf(Time(0))
	typeScalar = reflect.TypeOf(Scalar{})
	typeEnum   = reflect.TypeOf((*enumeration)(nil)).Elem()
	typeApprov = reflect.TypeOf(Approval{})

	reSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	reHost = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	reOID  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// MaxLabel is the longest a label may be, in bytes.
const MaxLabel = 200

// ErrInvalid is a record that breaks its kind's invariants. Nothing was
// written.
var ErrInvalid = errors.New("the record is not valid")

// rule is what a tag says of one field.
type rule struct {
	name      string // as written in JSON
	required  bool
	text      string // label, slug, host or oid, for a string
	ref       Kind
	min, max  *int64
	about     string
	omitempty bool
}

// ruleOf reads a struct field's tags. ok is false for a field that is not
// part of the record.
func ruleOf(f reflect.StructField) (r rule, ok bool, err error) {
	tag := f.Tag.Get("json")
	name, opts, _ := strings.Cut(tag, ",")
	if name == "-" || !f.IsExported() {
		return r, false, nil
	}
	if name == "" {
		return r, false, fmt.Errorf("the field %s has no JSON name", f.Name)
	}
	r.name, r.omitempty, r.about = name, strings.Contains(opts, "omitempty") || strings.Contains(opts, "omitzero"), f.Tag.Get("about")
	for _, o := range strings.Split(f.Tag.Get("reg"), ",") {
		key, val, _ := strings.Cut(strings.TrimSpace(o), "=")
		switch key {
		case "":
		case "required":
			r.required = true
		case "label", "slug", "host", "oid":
			r.text = key
		case "ref":
			r.ref = Kind(val)
		case "min", "max":
			n, perr := strconv.ParseInt(val, 10, 64)
			if perr != nil {
				return r, false, fmt.Errorf("the field %s has a %s that is not a number", f.Name, key)
			}
			if key == "min" {
				r.min = &n
			} else {
				r.max = &n
			}
		default:
			return r, false, fmt.Errorf("the field %s has a tag %q nothing reads", f.Name, key)
		}
	}
	return r, true, nil
}

// typeName is what a Go type is called in a schema, with the values of an
// enum and the fields of an object. It refuses a type a record may not hold.
func typeName(t reflect.Type, r rule) (name string, enum []string, sub []Field, err error) {
	switch {
	case t == typeID:
		return "id", nil, nil, nil
	case t == typeDigest:
		return "digest", nil, nil, nil
	case t == typeText:
		return "text", nil, nil, nil
	case t == typeTime:
		return "time", nil, nil, nil
	case t == typeScalar:
		return "scalar", nil, nil, nil
	case t.Kind() == reflect.String && t.Implements(typeEnum):
		return "enum", reflect.Zero(t).Interface().(enumeration).Values(), nil, nil
	}
	switch t.Kind() {
	case reflect.String:
		if r.text == "" {
			return "", nil, nil, fmt.Errorf("the field %q is a plain string: say whether it is a label, a slug, a host or an oid; "+
				"free text is a Text, held as a digest", r.name)
		}
		if r.text == "oid" {
			return "object-id", nil, nil, nil
		}
		return r.text, nil, nil, nil
	case reflect.Int, reflect.Int64:
		return "integer", nil, nil, nil
	case reflect.Float64:
		return "number", nil, nil, nil
	case reflect.Bool:
		return "boolean", nil, nil, nil
	case reflect.Slice:
		inner, enum, sub, err := typeName(t.Elem(), r)
		return "list of " + inner, enum, sub, err
	case reflect.Pointer:
		if t.Elem().Kind() == reflect.Struct {
			sub, err := schemaOf(t.Elem())
			return "object", nil, sub, err
		}
	case reflect.Struct:
		sub, err := schemaOf(t)
		return "object", nil, sub, err
	}
	return "", nil, nil, fmt.Errorf("the field %q has a type a record cannot hold (%s)", r.name, t)
}

// schemaOf is the fields of a struct, as a schema.
func schemaOf(t reflect.Type) ([]Field, error) {
	var out []Field
	seen := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		r, ok, err := ruleOf(t.Field(i))
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if seen[r.name] {
			return nil, fmt.Errorf("two fields are called %q", r.name)
		}
		seen[r.name] = true
		name, enum, sub, err := typeName(t.Field(i).Type, r)
		if err != nil {
			return nil, err
		}
		if r.ref != "" && !strings.HasSuffix(name, "id") {
			return nil, fmt.Errorf("the field %q points at a kind and is not an id", r.name)
		}
		out = append(out, Field{Name: r.name, Type: name, Ref: r.ref, Enum: enum,
			Required: r.required, About: r.about, Fields: sub})
	}
	return out, nil
}

// validate holds a record to what its fields' types and tags say, and then
// to its own Check. The error names the field as JSON writes it.
func validate(rec Record) error {
	v := reflect.Indirect(reflect.ValueOf(rec))
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return fmt.Errorf("%w: it is not a record", ErrInvalid)
	}
	what := strings.ToLower(string(rec.Kind()))
	if err := validStruct(v, ""); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalid, what, err)
	}
	if err := rec.Check(); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalid, what, err)
	}
	return nil
}

func validStruct(v reflect.Value, path string) error {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		r, ok, err := ruleOf(t.Field(i))
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		at := path + r.name
		f := v.Field(i)
		if f.IsZero() {
			if r.required {
				return fmt.Errorf("%q is needed%s", at, aboutOf(r))
			}
			continue
		}
		if err := validValue(f, r, at); err != nil {
			return err
		}
	}
	if t == typeApprov {
		a := v.Interface().(Approval)
		return a.check()
	}
	return nil
}

func aboutOf(r rule) string {
	if r.about == "" {
		return ""
	}
	return ": " + r.about
}

func validValue(f reflect.Value, r rule, at string) error {
	t := f.Type()
	switch {
	case t == typeID:
		if !ID(f.String()).Valid() {
			return fmt.Errorf("%q is not a record's identifier: 32 hexadecimal characters", at)
		}
		return nil
	case t == typeDigest, t == typeText:
		if !reDigest.MatchString(f.String()) {
			return fmt.Errorf("%q is not a digest: sha256: and 64 hexadecimal characters", at)
		}
		return nil
	case t == typeTime:
		if f.Int() < 0 {
			return fmt.Errorf("%q is a time before 1970", at)
		}
		return nil
	case t == typeScalar:
		switch v := f.Interface().(Scalar).v.(type) {
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return fmt.Errorf("%q is not a number a record can hold", at)
			}
		case string:
			return validLabel(v, at)
		case bool:
		default:
			return fmt.Errorf("%q is text, a number or true or false, and nothing else", at)
		}
		return nil
	case t.Kind() == reflect.String && t.Implements(typeEnum):
		values := f.Interface().(enumeration).Values()
		for _, v := range values {
			if v == f.String() {
				return nil
			}
		}
		return fmt.Errorf("%q is %q; it is one of %s", at, f.String(), strings.Join(values, ", "))
	}
	switch t.Kind() {
	case reflect.String:
		s := f.String()
		switch r.text {
		case "label":
			return validLabel(s, at)
		case "slug":
			if !reSlug.MatchString(s) {
				return fmt.Errorf("%q is %q; it is a lowercase name of letters, digits, dots, dashes and underscores", at, clipped(s))
			}
		case "host":
			if !reHost.MatchString(s) || net4(s) {
				return fmt.Errorf("%q is %q; it is one exact host name, not a pattern or an address", at, clipped(s))
			}
		case "oid":
			if !reOID.MatchString(s) {
				return fmt.Errorf("%q is not a store object's identifier: 64 hexadecimal characters", at)
			}
		}
	case reflect.Int, reflect.Int64:
		return inBounds(f.Int(), r, at)
	case reflect.Float64:
		n := f.Float()
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return fmt.Errorf("%q is not a number a record can hold", at)
		}
		if r.min != nil && n < float64(*r.min) || r.max != nil && n > float64(*r.max) {
			return fmt.Errorf("%q is %v, outside what it may be", at, n)
		}
	case reflect.Slice:
		if err := inBounds(int64(f.Len()), r, at); err != nil {
			return fmt.Errorf("%v (how many it holds)", err)
		}
		// The bounds were about how many; each item is held to the rest.
		item := r
		item.min, item.max, item.required = nil, nil, true
		for i := 0; i < f.Len(); i++ {
			e := f.Index(i)
			here := at + "[" + strconv.Itoa(i) + "]"
			if e.IsZero() {
				return fmt.Errorf("%q is empty", here)
			}
			if err := validValue(e, item, here); err != nil {
				return err
			}
		}
	case reflect.Pointer:
		return validStruct(f.Elem(), at+".")
	case reflect.Struct:
		return validStruct(f, at+".")
	}
	return nil
}

func inBounds(n int64, r rule, at string) error {
	if r.min != nil && n < *r.min {
		return fmt.Errorf("%q is %d; it is at least %d", at, n, *r.min)
	}
	if r.max != nil && n > *r.max {
		return fmt.Errorf("%q is %d; it is at most %d", at, n, *r.max)
	}
	return nil
}

// validLabel is a short single line a person reads: no line break, no
// control or invisible character, no space at either end.
func validLabel(s, at string) error {
	switch {
	case !utf8.ValidString(s):
		return fmt.Errorf("%q is not text", at)
	case len(s) > MaxLabel:
		return fmt.Errorf("%q is %d bytes; a label is at most %d", at, len(s), MaxLabel)
	case strings.TrimSpace(s) != s:
		return fmt.Errorf("%q begins or ends with a space", at)
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return fmt.Errorf("%q holds a control character (U+%04X); a label is one plain line", at, c)
		}
	}
	// What draws nothing is how one label is made to read as another: a
	// reference with a zero-width space in it is a second control that
	// looks like the first on every screen.
	if _, hidden := plaintext.Visible(s); hidden > 0 {
		return fmt.Errorf("%q holds %d character(s) that are not shown; a label is one plain line", at, hidden)
	}
	// An address in a label is a person written into a store that cannot
	// forget them. A person is a Subject's pseudonym, and the address is
	// kept in the subject map, where it can be erased.
	if reAddress.MatchString(s) {
		return fmt.Errorf("%q holds what reads as an address or an account name; a person is a Subject's "+
			"pseudonym in a record, and who they are is kept in the subject map, where it can be erased", at)
	}
	return nil
}

// reAddress is an email address or a user principal name, which have one
// shape: a name, an at sign, and a domain whose last part is letters. A
// version pinned with an at sign (lodash@4.17.21) ends in a number and is
// not one.
//
// The letters are any script's. An address may be written in any (RFC
// 6531), and a domain is a name of any script too, so one held to ASCII
// let josé@example.com, anna@bücher.de and an address under .рф through
// as labels like any other. The end of the domain is a character that is
// not a letter, a mark, a digit or an underscore, or the end of the label,
// which is what \b says in ASCII alone.
var reAddress = regexp.MustCompile(`[\p{L}\p{M}\p{N}._%+'-]+@[\p{L}\p{M}\p{N}-]+(\.[\p{L}\p{M}\p{N}-]+)*` +
	`\.\p{L}[\p{L}\p{M}]+(?:[^\p{L}\p{M}\p{N}_]|$)`)

// net4 reports whether a host name is four numbers, which is an address and
// not a name.
func net4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}

// clipped is a value quoted in a refusal, short enough to read.
func clipped(s string) string { return plaintext.Clip(s, 60, "…") }
