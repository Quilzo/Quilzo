// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package collection

import (
	"sort"
	"testing"
)

// A query names values to match and bounds to compare, and three more
// ways of matching a field: not equal to a value, equal to one of several,
// and present or absent. None of them is an expression, and each says
// plainly what it does with a record that does not have the field.
func TestQueryNotEqualsInExists(t *testing.T) {
	records := []Record{
		{ID: "a", Fields: map[string]any{"fact": "mfa.registered", "value": true, "grade": "connector"}},
		{ID: "b", Fields: map[string]any{"fact": "mfa.registered", "value": false, "grade": "imported"}},
		{ID: "c", Fields: map[string]any{"fact": "disk.encrypted", "value": true}},
		{ID: "d", Fields: map[string]any{"fact": "mfa.registered", "value": nil, "grade": "uploaded"}},
		{ID: "e", Fields: map[string]any{"fact": "device.count", "value": 3.0, "grade": "connector"}},
	}
	ids := func(q Query) []string {
		var out []string
		for _, r := range q.Matching(records) {
			out = append(out, r.ID)
		}
		sort.Strings(out)
		return out
	}
	cases := []struct {
		name string
		q    Query
		want []string
	}{
		// A field that is not there, or is null, has no value to differ
		// from: not-equals selects only what has a value and a different
		// one, and Exists is how the absent are asked for.
		{"not equals", Query{NotEquals: map[string]any{"value": true}}, []string{"b", "e"}},
		{"not equals with equals", Query{Equals: map[string]any{"fact": "mfa.registered"},
			NotEquals: map[string]any{"value": true}}, []string{"b"}},
		{"not equals a number written as an integer", Query{NotEquals: map[string]any{"value": 3}}, []string{"a", "b", "c"}},
		{"in", Query{In: map[string][]any{"grade": {"connector", "imported"}}}, []string{"a", "b", "e"}},
		{"in a number", Query{In: map[string][]any{"value": {3, false}}}, []string{"b", "e"}},
		{"in nothing", Query{In: map[string][]any{"grade": {}}}, nil},
		{"exists", Query{Exists: map[string]bool{"grade": true}}, []string{"a", "b", "d", "e"}},
		{"absent", Query{Exists: map[string]bool{"grade": false}}, []string{"c"}},
		{"a null is absent", Query{Exists: map[string]bool{"value": false}}, []string{"d"}},
		{"all three", Query{Exists: map[string]bool{"grade": true}, In: map[string][]any{"fact": {"mfa.registered"}},
			NotEquals: map[string]any{"grade": "uploaded"}}, []string{"a", "b"}},
	}
	for _, c := range cases {
		got := ids(c.q)
		if len(got) != len(c.want) {
			t.Errorf("%s selected %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s selected %v, want %v", c.name, got, c.want)
				break
			}
		}
	}
}
