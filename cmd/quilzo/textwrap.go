// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import "strings"

// Small helpers for laying text out in a terminal, which several commands
// share. They lived beside the call demonstrations that first needed them,
// and stayed when those left, because the flows and the standing register
// print through them too.

// wrapAt breaks a sentence to a width, indenting continuations.
func wrapAt(s string, width int, indent string) string {
	out, line := "", ""
	for _, word := range splitWords(s) {
		if len(line)+len(word)+1 > width && line != "" {
			out += line + "\n" + indent
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	return out + line
}

// splitWords is the words of s between spaces. Only a space separates, so a
// line break written into a sentence stays inside its word, as it always
// has here.
func splitWords(s string) []string {
	var out []string
	start := -1
	for i, r := range s {
		if r == ' ' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

// firstLine is an error's first line, for a list that gives each refusal
// one row and leaves the advice that follows it to the command itself.
func firstLine(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}
