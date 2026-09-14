// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package schema

import (
	"fmt"
	"sort"
)

// What a new record of this shape starts as.
//
// # The gap
//
// A type has declared its fields, their kinds and their bounds since it
// existed, and nothing used any of that to help somebody write the first
// record. The browser's record form is a textarea and a placeholder —
//
//	{"hostname": "laptop-14", "encrypted": true}
//
// — so writing a record meant remembering the field names, remembering which
// were required, and finding out which you had got wrong by being refused.
// The declaration knew the answer the whole time.
//
// internal/section has had this for twenty section kinds: Kind.Stub is "what a
// new one of these starts as", and the catalogue shows the rule it took to
// arrive at — a stub carries `"image": ""` rather than a placeholder path,
// because a path that looks real is one somebody ships. This is that, one
// level over.
//
// # A starting point, never a bypass
//
// A stub is not validated as a record and is not meant to be one: it carries
// empty values for the fields somebody has to fill in, which is the whole
// point of showing them. What it is checked for is that every key is a field
// the type declares and every value satisfies that field's own rules — so a
// stub cannot ship a value the type would refuse, and cannot name a field that
// does not exist and quietly do nothing.
//
// The gate stays the only authority on whether a record may be stored. That
// distinction is the one Notion's templates blur, and it is the reason this is
// forty lines rather than a feature.

// Blank is the record a person starts from.
//
// Every declared field, so somebody can see what the type has rather than
// discovering it one refusal at a time — with the type's own stub value where
// it declares one, and an empty value of the right shape where it does not.
//
// Empty rather than plausible. A stub that guesses "Acme Ltd" for a company
// name is a stub somebody publishes, and a required field holding a real
// looking value is worse than one holding nothing: the second is obviously
// unfinished.
func (t Type) Blank() map[string]any {
	out := make(map[string]any, len(t.Fields))
	for _, f := range t.Fields {
		if v, declared := t.Stub[f.Name]; declared {
			out[f.Name] = v
			continue
		}
		out[f.Name] = f.empty()
	}
	return out
}

// empty is the zero value of a field's kind, in the shape JSON will carry.
func (f Field) empty() any {
	switch f.Kind {
	case Number:
		return 0
	case Boolean:
		return false
	case List:
		return []any{}
	default:
		// Text, LongText, Slug, URL, Email, Date, Choice and Reference are all
		// strings. A Choice is left empty rather than set to its first option:
		// the options are a decision somebody makes, and prefilling one is how
		// every record ends up being whatever came first in the list.
		return ""
	}
}

// checkStub reports whether a type's stub is one it would accept.
//
// Not Required: a stub is where somebody starts and a required field with
// nothing in it is exactly what it should show. Everything else — the kind,
// the bounds, the choices — is checked, because a stub carrying a value the
// type refuses is a form that cannot be saved as it was handed over.
func checkStub(t Type) error {
	if len(t.Stub) == 0 {
		return nil
	}
	declared := map[string]Field{}
	for _, f := range t.Fields {
		declared[f.Name] = f
	}
	names := make([]string, 0, len(t.Stub))
	for name := range t.Stub {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		f, ok := declared[name]
		if !ok {
			return fmt.Errorf(
				"the starting values name %q, which %q does not declare. A "+
					"stub that names a field nobody has is one that quietly "+
					"does nothing", name, t.Name)
		}
		if problems := checkField(f, t.Stub[name]); len(problems) > 0 {
			return fmt.Errorf(
				"the starting value for %q is one %q would refuse: %s",
				name, t.Name, problems[0].Reason)
		}
	}
	return nil
}
