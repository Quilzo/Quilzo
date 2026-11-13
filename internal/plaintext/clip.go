// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package plaintext

import "unicode/utf8"

// Clip shortens s to at most n bytes, never inside a character, and puts
// mark after what it kept. Text of n bytes or fewer comes back as it is.
//
// It is the one clip, for every surface that bounds text for a list, a
// message, an audit note or a model. There were about twenty copies, and
// most cut at the nth byte: `quilzo schedule add` stored the first byte of
// an é and then "…", which reads back as U+FFFD in a hash-chained record
// that is meant to be evidence, and JSON turns into a character nobody
// wrote. A cut that lands inside a character goes back to where that
// character starts, so the output is at most n bytes and the mark, as it
// was with every copy, and no caller's bound moves.
//
// It is measured in bytes because the bounds it keeps are bytes: a
// record's size, a header's, a column's. Text that is not UTF-8 to begin
// with is cut at n, since there is no character there to keep whole.
func Clip(s string, n int, mark string) string {
	n = max(n, 0)
	if len(s) <= n {
		return s
	}
	cut := n
	if !utf8.RuneStart(s[n]) {
		for i := n - 1; i >= 0 && i > n-utf8.UTFMax; i-- {
			if utf8.RuneStart(s[i]) {
				if _, size := utf8.DecodeRuneInString(s[i:]); i+size > n {
					cut = i
				}
				break
			}
		}
	}
	return s[:cut] + mark
}
