// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package plaintext keeps text a model reads to what a person reading it
// would see.
//
// Unicode has characters that draw nothing: the tag block, which mirrors
// ASCII invisibly (U+E0000 to U+E007F); zero-width spaces and joiners;
// controls that reverse the direction text is shown in; variation
// selectors, which can carry a byte each after any character; private-use
// characters. A page can look ordinary to the person who reviewed and
// published it while carrying a sentence only a model reads, and a model
// reads it. That is "ASCII smuggling", and the defence everybody arrives
// at is the plain one: take them out before the model sees the text.
//
// What is kept: a single zero-width joiner or non-joiner between two
// letters, which Persian, the Indic scripts and emoji need to be written at
// all. A run of them is not writing anything, and goes.
package plaintext

import (
	"strings"
	"unicode"
)

// invisible reports a character that draws nothing and is not ordinary
// space.
func invisible(r rune) bool {
	switch {
	case r >= 0xE0000 && r <= 0xE007F: // tags
		return true
	case r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF: // variation selectors
		return true
	case r >= 0xE000 && r <= 0xF8FF, r >= 0xF0000: // private use, planes 15 and 16 included
		return true
	case r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0: // Hangul fillers, which draw nothing
		return true
	case r == 0x034F, r == 0x17B4, r == 0x17B5, r == 0x180E: // grapheme joiner, Khmer inherent vowels, Mongolian separator
		return true
	case unicode.Is(unicode.Cf, r): // every format character: zero-width, bidirectional, soft hyphen, word joiner
		return true
	case unicode.IsControl(r) && r != '\n' && r != '\t':
		return true
	}
	return false
}

// joiner is a zero-width joiner or non-joiner.
func joiner(r rune) bool { return r == 0x200C || r == 0x200D }

// writes reports a character a joiner may sit between: a letter, a mark,
// or the symbols and pictographs emoji are made of.
func writes(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsMark(r) || unicode.Is(unicode.So, r) ||
		(r >= 0x1F000 && r <= 0x1FAFF)
}

// Visible is text with what draws nothing taken out, and how many
// characters that was.
func Visible(s string) (string, int) {
	if !strings.ContainsFunc(s, func(r rune) bool { return r > 0x7E || (r < 0x20 && r != '\n' && r != '\t' && r != '\r') }) {
		return s, 0 // plain ASCII, the common case, untouched
	}
	rs := []rune(s)
	var b strings.Builder
	b.Grow(len(s))
	removed := 0
	for i, r := range rs {
		if r == '\r' {
			b.WriteRune(r)
			continue
		}
		if joiner(r) && i > 0 && i+1 < len(rs) && writes(rs[i-1]) && writes(rs[i+1]) {
			b.WriteRune(r)
			continue
		}
		if invisible(r) {
			removed++
			continue
		}
		b.WriteRune(r)
	}
	return b.String(), removed
}

// Clean is Visible without the count.
func Clean(s string) string {
	out, _ := Visible(s)
	return out
}
