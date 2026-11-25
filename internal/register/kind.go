// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

// Kind names one sort of record: Control, Evidence, Risk.
type Kind string

// Record is one typed entry of the register. Every kind is a Go struct that
// answers these three questions about itself, and nothing reaches the store
// that has not been asked all three.
type Record interface {
	// Kind is which kind of record this is.
	Kind() Kind
	// Key is what the record's identifier is derived from: the source it
	// came from and its natural key within that source. Two writers who
	// describe the same thing produce the same key, and so the same record.
	Key() (source, natural string)
	// Check is the invariants that are about more than one field. What a
	// single field may hold is said by its type and its tag, and checked
	// before this is called.
	Check() error
}

// Spec is what the register knows about a kind: where its records live, how
// far they may travel, and what fields they have. It is made once, by define,
// from the kind's own struct, so the schema a screen shows and the schema a
// write is held to cannot be two things.
type Spec struct {
	Kind Kind `json:"kind"`
	// Collection is the name its records are filed under, which always
	// begins with Prefix. The generic record surfaces refuse such a name.
	Collection string `json:"collection"`
	// Summary says, in one sentence, what a record of this kind is.
	Summary string `json:"summary"`
	// Class is how far a record of this kind may travel.
	Class Class `json:"class"`
	// Fields is the schema, in the order the struct declares it.
	Fields []Field `json:"fields"`
	// Signed says a record of this kind is a decision and must carry the
	// approval that made it.
	Signed bool `json:"signed,omitempty"`
	// Immutable says a record of this kind is never changed once written:
	// a decision that was minuted, a metric's value on a day.
	Immutable bool `json:"immutable,omitempty"`
	// Unconfirmed marks a kind that holds what a model read out of a
	// document. No figure, status or coverage is ever drawn from it.
	Unconfirmed bool `json:"unconfirmed,omitempty"`
	// RetainDays is how many days the free text and files its records
	// name are kept in the side store after they were last kept for a
	// record of it. Zero keeps them until a person erases them
	// (retention.go).
	RetainDays int `json:"retain_days,omitempty"`

	typ reflect.Type
}

// Field is one field of a kind, as a person or a program reads the schema.
type Field struct {
	// Name is the field as it is written in JSON.
	Name string `json:"name"`
	// Type is what the field holds: id, text, digest, time, label, slug,
	// host, object-id, enum, scalar, integer, number, boolean, object, or
	// "list of" one of those.
	Type string `json:"type"`
	// Ref is the kind an id points at, when it points at one kind.
	Ref Kind `json:"ref,omitempty"`
	// Enum is the values an enum may hold.
	Enum []string `json:"enum,omitempty"`
	// Required says a record without it is refused.
	Required bool `json:"required,omitempty"`
	// About says what the field is for.
	About string `json:"about,omitempty"`
	// Fields is the schema of an object, or of each object in a list.
	Fields []Field `json:"fields,omitempty"`
}

var (
	kinds       = map[Kind]*Spec{}
	collections = map[string]*Spec{}
	reKindName  = regexp.MustCompile(`^[A-Z][A-Za-z]{1,31}$`)
)

// Prefix begins the name of every collection the register owns. The
// collection package refuses every write to such a name
// (collection.Reserved), so no generic write path can create or change a
// collection of the register's.
const Prefix = "sec_"

// define adds a kind to the register, from its struct. It is called once per
// kind, when the package is initialised, from the file that declares the
// kind, so adding a kind is adding a file and editing no list.
//
// It panics on a kind that is declared wrongly, because that is a mistake in
// the program and not in anybody's data: a name used twice, a field with no
// JSON name, a plain string that does not say what sort of string it is.
func define[T Record](summary string, class Class, opts ...func(*Spec)) Kind {
	var zero T
	k := zero.Kind()
	if !reKindName.MatchString(string(k)) {
		panic(fmt.Sprintf("register: %q is not a kind's name", k))
	}
	if _, dup := kinds[k]; dup {
		panic(fmt.Sprintf("register: the kind %s is defined twice", k))
	}
	typ := reflect.TypeOf(zero)
	if typ.Kind() != reflect.Struct {
		panic(fmt.Sprintf("register: the kind %s is not a struct", k))
	}
	fields, err := schemaOf(typ)
	if err != nil {
		panic(fmt.Sprintf("register: the kind %s: %v", k, err))
	}
	s := &Spec{Kind: k, Collection: Prefix + snake(string(k)), Summary: summary, Class: class,
		Fields: fields, typ: typ}
	for _, o := range opts {
		o(s)
	}
	if s.Signed {
		if _, ok := typ.FieldByName("Approval"); !ok {
			panic(fmt.Sprintf("register: the kind %s is signed and has no Approval", k))
		}
	}
	kinds[k], collections[s.Collection] = s, s
	return k
}

// signed, immutable and unconfirmed are the options define takes.
func signed(s *Spec)      { s.Signed = true }
func immutable(s *Spec)   { s.Immutable = true }
func unconfirmed(s *Spec) { s.Unconfirmed = true }

// snake is a kind's name as a collection is called: ControlTest is
// control_test.
func snake(name string) string {
	var b strings.Builder
	for i, r := range name {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Kinds is every kind, in the alphabet's order.
func Kinds() []Spec {
	out := make([]Spec, 0, len(kinds))
	for _, s := range kinds {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

// SpecOf is what the register knows about a kind, named as the kind is or
// as its collection is, in any letter case: Control, control, sec_control and
// ControlTest, control_test and control-test all find theirs.
func SpecOf(name string) (Spec, bool) {
	want := strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(strings.TrimPrefix(strings.ToLower(name), Prefix)))
	for k, s := range kinds {
		if strings.ToLower(string(k)) == want {
			return *s, true
		}
	}
	return Spec{}, false
}

// specFor is the spec of a record's kind, or an error naming the kind nobody
// defined.
func specFor(k Kind) (*Spec, error) {
	s, ok := kinds[k]
	if !ok {
		return nil, fmt.Errorf("%q is not a kind the register has", k)
	}
	return s, nil
}

// Resource is what the policy gate is asked about for a kind: the register's
// area, and the kind's collection under it. A grant on Area covers every
// kind, and a grant on one kind's resource covers that kind alone.
func (s Spec) Resource() string { return Area + "/" + s.Collection }

// New is an empty record of the kind, as a pointer, for decoding into.
func (s Spec) New() any { return reflect.New(s.typ).Interface() }
