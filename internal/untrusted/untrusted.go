// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package untrusted prepares text somebody else wrote (a policy's name in
// an identity provider, a repository's description, a tool's answer) for
// the two places it is allowed to go: into a prompt as data, or onto a
// screen marked as somebody else's words.
//
// Two things have to hold for that to be safe, and both were learned the
// hard way rather than guessed:
//
// First, nothing that draws nothing may survive. A zero-width space inside
// "<<<" makes it look like every other fence while the bytes say otherwise,
// and a tag character carries a whole sentence only a model reads. plaintext
// takes those out; this package runs it first, because stripping fences
// before the characters that hide inside them is stripping fences from
// text that can still grow new ones.
//
// Second, what looks like the edge of a block must be the edge of a block,
// or not look like it. The fullwidth "＜" is not "<", but a model reading
// a prompt cannot be relied on to care, so the imitators are folded to the
// ASCII they imitate before any fence is looked for, and then the fence
// itself is removed by whoever is building the block, because a package
// that both folded and removed would not know whether its caller wanted the
// fence kept as a marker.
//
// It was copied, with its tests, from the connector engine Quilzo shares
// its manifest format with (internal/connector), so the two clean what a
// connected tool says the same way.
package untrusted

import (
	"strings"

	"github.com/quilzo/quilzo/internal/plaintext"
)

// confusable folds characters that imitate the ASCII a fence is made of.
// The guillemets are legitimate quotation marks in French and German; they
// are folded anyway, because in the one place they appear beside a fence
// they are far more likely to be a fence trying not to be one than a
// quotation.
var confusable = map[rune]rune{
	'＜': '<', '＞': '>', // fullwidth
	'«': '<', '»': '>', '‹': '<', '›': '>', // guillemets, single and double
	'｀': '`', // fullwidth grave accent
}

// Clean is text with what draws nothing taken out and fence imitators
// folded to the ASCII they imitate. What a fence-builder does with the
// result is its business; this only makes the bytes honest about what they
// look like.
func Clean(s string) string {
	s = plaintext.Clean(s)
	if !strings.ContainsFunc(s, func(r rune) bool { _, ok := confusable[r]; return ok }) {
		return s
	}
	rs := []rune(s)
	for i, r := range rs {
		if c, ok := confusable[r]; ok {
			rs[i] = c
		}
	}
	return string(rs)
}

// Tame is text made safe to hand to a model as data: cleaned, on one line,
// with the fence tokens gone and nothing split by the truncation. limit is
// in bytes; the cut lands on a whole rune.
func Tame(s string, limit int) string {
	s = Clean(s)
	s = strings.Join(strings.Fields(s), " ")
	for _, mark := range []string{"<<<", ">>>", "```"} {
		s = strings.ReplaceAll(s, mark, " ")
	}
	s = strings.Join(strings.Fields(s), " ")
	return Truncate(s, limit)
}

// Truncate cuts text to limit bytes without splitting a rune, marking the
// cut with an ellipsis, which counts towards the limit. Text that already
// fits is returned as it is.
//
// The cut is plaintext.Clip's, the one clip in this program, given the
// room the ellipsis leaves.
func Truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return plaintext.Clip(s, limit-len("…"), "…")
}
