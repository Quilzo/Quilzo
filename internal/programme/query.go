// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/plaintext"
	"github.com/quilzo/quilzo/internal/register"
)

// Typed queries: what a control test and a population select with.
//
// A query names the kind of record it reads, the field that names the
// member each record is about, and terms, each comparing one field of the
// kind's schema by equals, not-equals, in, exists or absent with values of
// the field's own type. There is no expression and nothing is evaluated:
// the terms become a collection.Query, whose NotEquals, In and Exists say
// what each does with a record that lacks the field, and that is matched
// against each record's fields as they are stored.
//
// Code holds a query to the schema before anything runs it (CheckQuery),
// so a query a model drafted is refused for a field the kind does not have,
// a value of the wrong type, a value of an enumeration that is not one of
// its values, or a member field that does not name a record.

// CheckQuery holds a query to the schema of the kind it reads, and fills
// in its digest. The query it returns is the one to file.
func CheckQuery(q register.Query) (register.Query, error) {
	spec, ok := register.SpecOf(q.Of)
	if !ok || string(spec.Kind) != q.Of {
		return q, fmt.Errorf("%w: a query reads a kind of the register, named as `quilzo register kinds` names it, "+
			"and %q is not one", register.ErrInvalid, clip(q.Of))
	}
	if spec.Unconfirmed {
		return q, fmt.Errorf("%w: %s is what a model read, which no test or count reads", register.ErrInvalid, spec.Kind)
	}
	fields := map[string]register.Field{}
	for _, f := range spec.Fields {
		fields[f.Name] = f
	}
	if q.Member != "" {
		f, ok := fields[q.Member]
		if !ok || f.Type != "id" {
			return q, fmt.Errorf("%w: the member field %q is not a field of %s that names a record", register.ErrInvalid,
				clip(q.Member), spec.Kind)
		}
	}
	exists := map[string]register.Op{}
	for _, t := range q.Terms {
		f, ok := fields[t.Field]
		if !ok {
			return q, fmt.Errorf("%w: %s has no field %q", register.ErrInvalid, spec.Kind, clip(t.Field))
		}
		if strings.HasPrefix(f.Type, "list of") || f.Type == "object" {
			return q, fmt.Errorf("%w: the field %q holds more than one value, which a term does not compare",
				register.ErrInvalid, t.Field)
		}
		if t.Op == register.OpExists || t.Op == register.OpAbsent {
			if other, both := exists[t.Field]; both && other != t.Op {
				return q, fmt.Errorf("%w: the field %q is asked to be there and not there", register.ErrInvalid, t.Field)
			}
			exists[t.Field] = t.Op
		}
		for _, v := range t.Values {
			if err := valueFits(f, v); err != nil {
				return q, fmt.Errorf("%w: the term on %q: %v", register.ErrInvalid, t.Field, err)
			}
		}
	}
	q.Of = string(spec.Kind)
	q.Digest = register.QueryDigest(q)
	if err := q.Check(); err != nil {
		return q, fmt.Errorf("%w: %v", register.ErrInvalid, err)
	}
	return q, nil
}

var reSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// valueFits says whether a value is of the type a field holds.
func valueFits(f register.Field, v register.Scalar) error {
	text, isText := v.Value().(string)
	_, isNumber := v.Value().(float64)
	_, isBool := v.Value().(bool)
	switch f.Type {
	case "id":
		if !isText || !register.ID(text).Valid() {
			return fmt.Errorf("it names a record, by 32 hexadecimal characters")
		}
	case "digest", "text":
		if !isText || !register.Digest(text).Valid() {
			return fmt.Errorf("it is a digest: sha256: and 64 hexadecimal characters")
		}
	case "time", "integer", "number":
		if !isNumber {
			return fmt.Errorf("it is a number")
		}
	case "boolean":
		if !isBool {
			return fmt.Errorf("it is true or false")
		}
	case "enum":
		if !isText || !slices.Contains(f.Enum, text) {
			return fmt.Errorf("it is one of %s", strings.Join(f.Enum, ", "))
		}
	case "slug":
		if !isText || !reSlug.MatchString(text) {
			return fmt.Errorf("it is a lowercase name of letters, digits, dots, dashes and underscores")
		}
	case "scalar":
		if v.IsZero() {
			return fmt.Errorf("it is text, a number or true or false")
		}
	default:
		if !isText {
			return fmt.Errorf("it is text")
		}
	}
	// A value is one word. A term compares a field with an identifier, a
	// name, a number or a yes or no; with no spaces, no value a model
	// drafted can be a sentence, so the explanation of a failure, which
	// quotes the query's values, holds nothing that reads as prose.
	if isText && !reToken.MatchString(text) {
		return fmt.Errorf("a value is one word of at most 200 bytes: letters, digits and . _ : @ / + = -, with no spaces")
	}
	return nil
}

var reToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/+=-]{0,199}$`)

// QueryID is the identifier of the query a digest names.
func QueryID(d register.Digest) (register.ID, error) {
	return register.DeriveID(register.KindQuery, register.Local, string(d))
}

// matcher is a query's terms as a collection.Query.
func matcher(q register.Query) collection.Query {
	cq := collection.Query{Equals: map[string]any{}, NotEquals: map[string]any{}, In: map[string][]any{},
		Exists: map[string]bool{}}
	for _, t := range q.Terms {
		switch t.Op {
		case register.OpEquals:
			cq.Equals[t.Field] = t.Values[0].Value()
		case register.OpNotEquals:
			cq.NotEquals[t.Field] = t.Values[0].Value()
		case register.OpIn:
			var vs []any
			for _, v := range t.Values {
				vs = append(vs, v.Value())
			}
			cq.In[t.Field] = vs
		case register.OpExists:
			cq.Exists[t.Field] = true
		case register.OpAbsent:
			cq.Exists[t.Field] = false
		}
	}
	return cq
}

// Selection is what a query found at a view: the members it selected, by
// identifier, and what it read to find them.
type Selection struct {
	// Members is the identifiers of the members selected, each once, in
	// order.
	Members []register.ID
	// Read is every record of the kind the query looked at, with the hash
	// it was stored under, which is what a replay is checked against.
	Read []Read
	// Grades is the grade of each record selected that has one, and
	// Sources the source each was from, where the kind says.
	Grades  []register.Grade
	Sources map[register.ID]bool
}

// Read is one record a query looked at.
type Read struct {
	Kind   register.Kind
	ID     register.ID
	Object string
}

// Select runs a query at a view. from, when it is set, keeps the records
// of a kind that has a source to those from that one source: a
// population's members are read from its source and no other.
func Select(v *register.View, q register.Query, from register.ID) (Selection, error) {
	if _, err := CheckQuery(q); err != nil {
		return Selection{}, err
	}
	if from != "" {
		if err := sourced(q); err != nil {
			return Selection{}, err
		}
	}
	m := matcher(q)
	sel := Selection{Sources: map[register.ID]bool{}}
	seen := map[register.ID]bool{}
	err := v.Each(register.Kind(q.Of), func(e register.Entry, fields map[string]any) error {
		sel.Read = append(sel.Read, Read{Kind: e.Kind, ID: e.ID, Object: e.Object})
		src, _ := fields["source"].(string)
		if from != "" && register.ID(src) != from {
			return nil
		}
		if !m.Match(collection.Record{ID: string(e.ID), Fields: fields}) {
			return nil
		}
		member := e.ID
		if q.Member != "" {
			s, _ := fields[q.Member].(string)
			if member = register.ID(s); !member.Valid() {
				return nil
			}
		}
		if !seen[member] {
			seen[member] = true
			sel.Members = append(sel.Members, member)
		}
		if g, ok := fields["grade"].(string); ok {
			sel.Grades = append(sel.Grades, register.Grade(g))
		}
		if src != "" {
			sel.Sources[register.ID(src)] = true
		}
		return nil
	})
	sort.Slice(sel.Members, func(i, j int) bool { return sel.Members[i] < sel.Members[j] })
	return sel, err
}

// sourced refuses a query a population is read with when its kind does not
// say which source reported each record. A population's members are read
// from its source and no other; records that name no source would all be
// read whatever source the population named, and two such reads would
// agree with each other whatever the two sources knew, so the count and its
// cross-check would both say something nobody checked.
func sourced(q register.Query) error {
	spec, _ := register.SpecOf(q.Of)
	for _, f := range spec.Fields {
		if f.Name == "source" && f.Type == "id" {
			return nil
		}
	}
	return fmt.Errorf("%w: a population is read from a source, and %s records do not say which source reported them",
		register.ErrInvalid, spec.Kind)
}

// digestOf is the digest of a list of lines, each ended by a line break,
// under a domain line of its own.
func digestOf(domain string, lines []string) register.Digest {
	h := sha256.New()
	h.Write([]byte(domain))
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	return register.Digest("sha256:" + hex.EncodeToString(h.Sum(nil)))
}

// membersDigest is the digest of a set of members, which a run and a
// population name.
func membersDigest(ids []register.ID) register.Digest {
	lines := make([]string, len(ids))
	for i, id := range ids {
		lines[i] = string(id)
	}
	sort.Strings(lines)
	return digestOf("quilzo/programme members v1\n", lines)
}

// readDigest is the digest of everything a run read: each record's kind,
// identifier and the hash it was stored under, in order.
func readDigest(reads ...[]Read) register.Digest {
	var lines []string
	for _, rs := range reads {
		for _, r := range rs {
			lines = append(lines, string(r.Kind)+" "+string(r.ID)+" "+r.Object)
		}
	}
	sort.Strings(lines)
	return digestOf("quilzo/programme snapshot v1\n", lines)
}

// clip is a value cut to fit a message.
func clip(s string) string { return plaintext.Clip(s, 60, "…") }
