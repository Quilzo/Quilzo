// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package connector

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Reaching into a JSON document, in the smallest language that does the job.
//
// Dotted keys and numeric indexes: user.profile.email, devices.0.serial. No
// wildcards, no filters, no functions, no arithmetic, nothing that can loop.
//
// That is the whole point. A mapping language with expressions in it is a
// program, a manifest carrying one is executable content, and the review that
// makes this package safe — somebody reading four lines and knowing what the
// connector can touch — stops being possible the moment a path can compute.
// Every feature this does not have was left out on purpose, and the cost is
// that a tool with an awkward shape needs a small amount of Go rather than a
// clever line of configuration.

// At returns the value at a path as a string, or empty.
//
// Strings because a mapped record is compared, stored and exported as text,
// and JSON's number-or-string ambiguity is where reconciliation bugs live. A
// number comes back in its shortest exact form rather than in Go's float
// formatting, so an identifier of 1043 is "1043" and never "1.043e+03" — the
// second is a different identifier, and a join on it silently finds nobody.
func At(doc any, path string) string {
	v, ok := lookup(doc, path)
	if !ok {
		return ""
	}
	return asString(v)
}

// Has reports whether a path exists, which is different from being empty.
func Has(doc any, path string) bool {
	_, ok := lookup(doc, path)
	return ok
}

// lookup finds a value, treating an explicit null as absent.
func lookup(doc any, path string) (any, bool) {
	v, ok := lookupNode(doc, path)
	if !ok || v == nil {
		// Present and null. A field a tool explicitly sets to null is a
		// field it has no value for, and mapping it to the string "null"
		// would put that word in a name column.
		return nil, false
	}
	return v, true
}

// lookupNode finds a value, reporting present-and-null as present.
//
// The distinction matters in exactly one place and matters a lot there: a
// tool answering {"results": null} has no records this time, and a tool that
// renamed results has changed shape. Collapsing the two makes every rename
// read as an empty estate.
func lookupNode(doc any, path string) (any, bool) {
	if strings.TrimSpace(path) == "" {
		return nil, false
	}
	cur := doc
	for _, part := range strings.Split(path, ".") {
		if part == "" {
			return nil, false
		}
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[part]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(node) {
				return nil, false
			}
			cur = node[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		// Integers stay integers. encoding/json gives every number as a
		// float64, and an identifier that arrives as 1.043e+03 is a
		// different identifier from 1043.
		if t == float64(int64(t)) && t < 1e15 && t > -1e15 {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	case nil:
		return ""
	default:
		// An object or an array where a scalar was expected. Rendered as
		// nothing rather than as Go's %v, because a name column reading
		// "map[first:Jane last:Doe]" is a mapping mistake that should look
		// like one.
		return ""
	}
}

// Paths lists every leaf path in a document, for showing an author what a
// tool actually returns.
//
// Bounded: a response with a thousand fields is a response somebody should
// look at in a browser, and printing all of them is not help.
func Paths(doc any, limit int) []string {
	var out []string
	walk(doc, "", &out, limit)
	return out
}

func walk(node any, prefix string, out *[]string, limit int) {
	if len(*out) >= limit {
		return
	}
	switch t := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sortStrings(keys)
		for _, k := range keys {
			walk(t[k], join(prefix, k), out, limit)
		}
	case []any:
		// The first element only. Ten thousand records with the same shape
		// produce one shape, which is the question being asked.
		if len(t) > 0 {
			walk(t[0], join(prefix, "0"), out, limit)
		}
	default:
		if prefix != "" {
			*out = append(*out, prefix)
		}
	}
}

func join(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
