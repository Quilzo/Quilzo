// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package seo

import (
	"strings"
)

// Suggest is the published page a missing address most likely meant, for a
// person to confirm as a redirect: one whose last segment is the same, or
// close to it by spelling, or sharing most of its words. Never applied by
// itself: a wrong redirect is worse than an honest 404.
func Suggest(missing string, pages []string) (string, bool) {
	want := strings.ToLower(strings.Trim(missing, "/"))
	want = strings.TrimSuffix(strings.TrimSuffix(want, ".html"), ".htm")
	if want == "" {
		return "", false
	}
	leaf := want[strings.LastIndex(want, "/")+1:]
	best, bestScore := "", 0.0
	for _, p := range pages {
		cand := strings.ToLower(p)
		cleaf := cand[strings.LastIndex(cand, "/")+1:]
		score := 0.0
		switch {
		case cand == want:
			score = 1
		case cleaf == leaf:
			score = 0.9
		default:
			if d := distance(leaf, cleaf); d <= max(1, len(leaf)/4) {
				score = 0.8 - 0.05*float64(d)
			}
			if o := overlap(words(want), words(cand)); o > score {
				score = o
			}
		}
		if score > bestScore || (score == bestScore && p < best) {
			best, bestScore = p, score
		}
	}
	return best, bestScore >= 0.6
}

func words(s string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == '-' || r == '_' || r == '.' }) {
		if len(w) > 2 {
			out[w] = true
		}
	}
	return out
}

// overlap is how much of the larger set of words the two share.
func overlap(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	n := 0
	for w := range a {
		if b[w] {
			n++
		}
	}
	return float64(n) / float64(max(len(a), len(b)))
}

// distance is the edit distance with a swapped pair of letters counting as
// one edit, as a typing slip does (optimal string alignment), bounded to
// short names.
func distance(a, b string) int {
	if len(a) > 64 || len(b) > 64 {
		return 64
	}
	d := make([][]int, len(a)+1)
	for i := range d {
		d[i] = make([]int, len(b)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(a)][len(b)]
}
