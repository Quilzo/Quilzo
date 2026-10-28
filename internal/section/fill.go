// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package section

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Things to fill in.
//
// The site builder never makes up a fact (internal/feature/sitebuild.go).
// Where a page needs one that nobody gave it, such as a price, an address,
// the hours a shop opens or somebody's words, it writes [[what goes here]]
// instead, and the person whose site it is writes the fact in. The publish
// gate refuses a page that still holds one, so a site never goes live
// saying "[[your phone number]]", or a number somebody invented.

// blank is one thing to fill in: two square brackets either side of a short
// description with no brackets or line breaks in it.
var blank = regexp.MustCompile(`\[\[([^\[\]\n]{1,120})\]\]`)

// gap is the run of spaces a left-out blank leaves, and what follows it
// when that is punctuation.
var gap = regexp.MustCompile(`[ \t]+([ \t,.;:!?)])`)

// Blank is one place on a page that is still to be filled in.
type Blank struct {
	// Field is where it is, as a path through the page: hero.lead, or
	// sections.2.features.items.0.body.
	Field string `json:"field"`
	// What is what goes there, in the builder's words.
	What string `json:"what"`
}

// Mark is the blank for what, as the builder writes it.
func Mark(what string) string { return "[[" + what + "]]" }

// first are the fields read before the rest of an entry: a card's title
// comes before its body, a question before its answer.
var first = map[string]int{"title": 1, "name": 2, "label": 3, "q": 4, "eyebrow": 5}

// Unfilled lists the blanks on a page, in the order somebody reads it.
func Unfilled(body any) []Blank {
	var out []Blank
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch t := v.(type) {
		case string:
			for _, m := range blank.FindAllStringSubmatch(t, -1) {
				out = append(out, Blank{Field: path, What: strings.TrimSpace(m[1])})
			}
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool {
				fi, fj := first[keys[i]], first[keys[j]]
				switch {
				case fi > 0 && fj > 0:
					return fi < fj
				case fi > 0 || fj > 0:
					return fi > 0
				}
				return keys[i] < keys[j]
			})
			for _, k := range keys {
				walk(join(path, k), t[k])
			}
		case []any:
			for i, e := range t {
				walk(join(path, strconv.Itoa(i)), e)
			}
		}
	}
	walk("", body)
	return out
}

// Fill writes values in for blanks, by what each blank says goes there, in
// every place on the page it appears. An empty value leaves the blank out:
// the words around it stay, and a paragraph that was only the blank goes.
// It returns a filled copy of the page and how many places it filled; the
// page passed in is not changed.
func Fill(body any, values map[string]string) (any, int) {
	n := 0
	var walk func(v any) (any, bool)
	walk = func(v any) (any, bool) {
		switch t := v.(type) {
		case string:
			left := false
			filled := blank.ReplaceAllStringFunc(t, func(m string) string {
				val, ok := values[strings.TrimSpace(m[2:len(m)-2])]
				if !ok {
					return m
				}
				n++
				left = left || val == ""
				return val
			})
			if !left {
				return filled, true
			}
			// Where a blank was left out, the spaces either side of it close up.
			filled = strings.TrimSpace(gap.ReplaceAllString(filled, "$1"))
			return filled, filled != ""
		case map[string]any:
			out := make(map[string]any, len(t))
			for k, e := range t {
				out[k], _ = walk(e)
			}
			return out, true
		case []any:
			out := make([]any, 0, len(t))
			for _, e := range t {
				if f, keep := walk(e); keep {
					out = append(out, f)
				}
			}
			return out, true
		default:
			return v, true
		}
	}
	out, _ := walk(body)
	return out, n
}
