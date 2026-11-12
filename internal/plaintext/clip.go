// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package plaintext

import "unicode/utf8"

// Clip is s cut to at most n bytes, ending in mark when anything was cut,
// and never inside a character.
//
// Bytes, because every bound it serves is one: a field a store accepts, a
// request a provider takes, a line in a log. The mark counts toward n, so a
// caller's bound stays the length of what it gets back, and swapping s[:n]
// for Clip never makes anyone's output longer.
//
// s[:n] cuts inside a character whenever the one at byte n is longer than a
// byte, which is every character of most of the world's writing. What is
// left ends in bytes that are not text: shown as U+FFFD, refused by a
// strict decoder, or stored as something different from what the person
// wrote. So the cut moves back to where that character starts, which is
// never more than three bytes.
//
// Text that was not UTF-8 to begin with is cut where asked: there is no
// character there to keep whole.
func Clip(s string, n int, mark string) string {
	if len(s) <= n {
		return s
	}
	if n <= 0 {
		return ""
	}
	keep := n - len(mark)
	if keep < 0 {
		// A mark longer than the whole bound would be all that came back,
		// and it says nothing about text that is not there.
		keep, mark = n, ""
	}
	return s[:boundary(s, keep)] + mark
}

// boundary is i, moved back to the start of the character it falls inside.
func boundary(s string, i int) int {
	if i >= len(s) || utf8.RuneStart(s[i]) {
		return i
	}
	for j := i - 1; j >= 0 && j > i-utf8.UTFMax; j-- {
		if !utf8.RuneStart(s[j]) {
			continue
		}
		// Only a character that runs past i is moved back over. A stray
		// continuation byte after an ordinary letter is not part of that
		// letter, and backing over the letter would lose text for nothing.
		if _, size := utf8.DecodeRuneInString(s[j:]); j+size > i {
			return j
		}
		return i
	}
	return i
}
