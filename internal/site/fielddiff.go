// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/store"
)

// FieldChange is one field of a page that differs between two versions of
// it, with what it said before and what it says now.
//
// # Why this exists
//
// Review told a publisher approving a model's change to "read the changes
// below before you approve", and below it was a list of page names and the
// word "modified": no surface, not Review, not `quilzo diff`, not the agent
// interface's diff, showed what had changed inside a page. An approval given
// on a page name is the rule satisfied and not kept. So each modified page
// says which fields changed, and how.
type FieldChange struct {
	Field string `json:"field"`
	// Before and After are the field's value, as written when it is text
	// and as JSON otherwise; "" for a field that was not there.
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
	// Lines is a line by line comparison, for text of more than one line,
	// where the words that changed are a few lines among many.
	Lines []LineChange `json:"lines,omitempty"`
}

// LineChange is one line of a comparison: Op is " " for a line both
// versions have, "-" for one only the old has and "+" for one only the new.
type LineChange struct {
	Op   string `json:"op"`
	Text string `json:"text"`
}

// maxLineDiff bounds the lines a comparison is worked out for, since the
// work grows with the product of the two counts. Past it a field is shown
// before and after, whole. The lines both versions begin with and end with
// are not counted: they are not part of the work.
const maxLineDiff = 2000

// FieldChanges is what differs, field by field, in the page a change is to.
// Nil for something that is not a page, such as the records under data.
func FieldChanges(s *store.Store, c Change) ([]FieldChange, error) {
	read := func(oid string) (map[string]any, bool, error) {
		if oid == "" {
			return map[string]any{}, true, nil
		}
		if s.IsTree(oid) {
			return nil, false, nil
		}
		var v any
		if err := s.GetBlob(oid, &v); err != nil {
			return nil, false, err
		}
		m, _ := v.(map[string]any)
		if m == nil {
			m = map[string]any{}
		}
		return m, true, nil
	}
	before, isPage, err := read(c.Before)
	if err != nil || !isPage {
		return nil, err
	}
	after, isPage, err := read(c.After)
	if err != nil || !isPage {
		return nil, err
	}
	keys := map[string]bool{}
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)

	var out []FieldChange
	for _, k := range names {
		was, had := before[k]
		now, has := after[k]
		if had && has && reflect.DeepEqual(was, now) {
			continue
		}
		fc := FieldChange{Field: k}
		if had {
			fc.Before = asText(was)
		}
		if has {
			fc.After = asText(now)
		}
		// The same characters and still a change: a value that changed
		// kind, the number 10 into the text "10" or false into the text
		// "false", which a layout reads as true. Shown as written, both
		// sides said the same and the change read as none, so both are
		// shown as JSON, where text has its quotes.
		if had && has && fc.Before == fc.After {
			fc.Before, fc.After = asJSON(was), asJSON(now)
		}
		if strings.Contains(fc.Before, "\n") || strings.Contains(fc.After, "\n") {
			fc.Lines = lineDiff(fc.Before, fc.After)
		}
		out = append(out, fc)
	}
	return out, nil
}

// asText is a value as a reader reads it: text as written, anything else as
// JSON.
func asText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return asJSON(v)
}

// asJSON is a value as JSON writes it.
func asJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// lineDiff compares two texts line by line, by their longest common
// subsequence; nil when what differs between them is longer than
// maxLineDiff lines on either side.
//
// What they begin with and end with in common is set aside first. An edit
// is most often a few lines somewhere in a text, and counted whole, a long
// text with one line changed was past the bound: it was shown before and
// after in full, and the one changed line among thousands was for the
// reader to find.
func lineDiff(before, after string) []LineChange {
	split := func(s string) []string {
		if s == "" {
			return nil
		}
		return strings.Split(s, "\n")
	}
	a, b := split(before), split(after)
	head := 0
	for head < len(a) && head < len(b) && a[head] == b[head] {
		head++
	}
	same := a[:head]
	a, b = a[head:], b[head:]
	tail := 0
	for tail < len(a) && tail < len(b) && a[len(a)-1-tail] == b[len(b)-1-tail] {
		tail++
	}
	rest := a[len(a)-tail:]
	a, b = a[:len(a)-tail], b[:len(b)-tail]
	if len(a) > maxLineDiff || len(b) > maxLineDiff {
		return nil
	}
	// lcs[i][j] is the length of the longest common subsequence of a[i:]
	// and b[j:].
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	out := make([]LineChange, 0, len(same)+len(a)+len(b)+len(rest))
	for _, l := range same {
		out = append(out, LineChange{" ", l})
	}
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out = append(out, LineChange{" ", a[i]})
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, LineChange{"-", a[i]})
			i++
		default:
			out = append(out, LineChange{"+", b[j]})
			j++
		}
	}
	for ; i < len(a); i++ {
		out = append(out, LineChange{"-", a[i]})
	}
	for ; j < len(b); j++ {
		out = append(out, LineChange{"+", b[j]})
	}
	for _, l := range rest {
		out = append(out, LineChange{" ", l})
	}
	return out
}
