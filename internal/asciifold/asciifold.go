// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package asciifold finds a word in text without regard to ASCII case, and
// answers with an offset into the text it was given.
//
// # Why it exists
//
// HTML names its tags and attributes in ASCII and compares them without
// regard to case, so <HEAD>, <Head> and <head> are one element and a search
// for one has to find all three. The obvious way to write that,
// strings.Index(strings.ToLower(page), "</head>"), answers with an offset
// into the lowered copy, and every place written that way cut the page
// itself at it.
//
// The copy is not the page. Lowering rewrites a character in however many
// bytes its lower case takes: İ (U+0130) is two bytes and lowers to i, one;
// the Kelvin sign is three and lowers to k; Ⱥ grows from two to three; and a
// byte that is not UTF-8 at all comes back as U+FFFD, three. A Turkish title
// ahead of </head> put the manifest link and the provenance marking inside
// the </title> before it, one byte early for every İ, and text that grew put
// the offset past the end of the page, where cutting it panicked. Nothing
// failed on English, which is every page the tests had.
//
// # What it matches
//
// Only the ASCII letters fold, and every other byte matches only itself.
// That is the rule HTML's own tokeniser follows for tag and attribute names,
// so a non-ASCII character that the lowered copy turned into a letter (the
// Kelvin sign into k, İ into i) is no longer a match anybody should have
// found: <İmg is not an image.
//
// # What it costs
//
// Nothing is copied. Lowering a whole page for each search was most of what
// these searches cost: a page served with its assistant's button was lowered
// four times over, and twice more for every form on it, and strings.ToLower
// of a page that is not pure ASCII (a dash, a pound sign, a ©) goes through
// unicode.ToLower one character at a time. That was about a ninth of the CPU
// of serving the fullest starter page.
package asciifold

import "strings"

// Index is the offset in s of the first place sub appears, its ASCII letters
// compared without regard to case, or -1 when it does not appear.
func Index(s, sub string) int {
	n := len(sub)
	if n == 0 {
		return 0
	}
	first := lower(sub[0])
	for i := 0; i+n <= len(s); i++ {
		j := indexByte(s[i:len(s)-n+1], first)
		if j < 0 {
			return -1
		}
		i += j
		if equal(s[i:i+n], sub) {
			return i
		}
	}
	return -1
}

// LastIndex is the offset in s of the last place sub appears, its ASCII
// letters compared without regard to case, or -1 when it does not appear.
func LastIndex(s, sub string) int {
	n := len(sub)
	if n == 0 {
		return len(s)
	}
	first := lower(sub[0])
	for i := len(s) - n; i >= 0; i-- {
		j := lastIndexByte(s[:i+1], first)
		if j < 0 {
			return -1
		}
		i = j
		if equal(s[i:i+n], sub) {
			return i
		}
	}
	return -1
}

// HasPrefix reports whether s begins with prefix, its ASCII letters compared
// without regard to case. When it does, s[len(prefix):] is what follows it.
func HasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && equal(s[:len(prefix)], prefix)
}

// equal reports whether a and b, the same length, differ only in the case of
// their ASCII letters.
func equal(a, b string) bool {
	for i := 0; i < len(a); i++ {
		if x, y := a[i], b[i]; x != y && lower(x) != lower(y) {
			return false
		}
	}
	return true
}

// indexByte is the first offset of c, already lower case, in s in either
// case. A byte that is not a letter has one form, and strings.IndexByte is
// the fast way to look for it: the tags this is mostly asked about all start
// with "<".
func indexByte(s string, c byte) int {
	u := upper(c)
	if u == c {
		return strings.IndexByte(s, c)
	}
	for i := 0; i < len(s); i++ {
		if b := s[i]; b == c || b == u {
			return i
		}
	}
	return -1
}

// lastIndexByte is indexByte from the end.
func lastIndexByte(s string, c byte) int {
	u := upper(c)
	if u == c {
		return strings.LastIndexByte(s, c)
	}
	for i := len(s) - 1; i >= 0; i-- {
		if b := s[i]; b == c || b == u {
			return i
		}
	}
	return -1
}

func lower(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func upper(c byte) byte {
	if 'a' <= c && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c
}
