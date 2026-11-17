// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import "strings"

// Content on its way to a terminal.
//
// # What this is for
//
// Several commands echo content back: a search excerpt, a scan finding, a
// commit message. That content was written by whoever can write content,
// which on a site with contributors is not the person running the command.
//
// A terminal is not a text box. A string carrying ESC sequences can move the
// cursor, clear the line above, change what is already on the screen, or set
// the window title -- so a page whose body begins with the right escape can
// make `quilzo search` print something other than what is in the store, and
// the operator reading the output has no way to tell. It is the same shape as
// log injection, on a surface where the reader is a person rather than a
// parser.
//
// # What it does
//
// Removes the C0 and C1 control characters, keeping tab and newline, which
// are the two that mean something in this output. Everything else is
// replaced with a visible marker rather than dropped: content that contained
// a control character is a fact worth seeing, and silently removing it hides
// both the escape and the reason somebody put it there.
//
// It does not attempt to be a sanitiser for anything else. Content going into
// a page is escaped by the template engine, which knows the context it is
// landing in; this knows only that the destination is a terminal.
func forTerminal(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			// C0, and DEL.
			b.WriteString("�")
		case r >= 0x80 && r <= 0x9f:
			// C1, which some terminals accept as escapes in their own right.
			b.WriteString("�")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// onOneLine is forTerminal for a value that is printed inside one line of
// output: a name, an identifier, a sentence of detail. A line break is
// replaced as well, because in that position it lets whatever wrote the
// value start a line of its own, and a line of this program's output is
// read as this program speaking.
func onOneLine(s string) string {
	// forTerminal first, because it keeps a newline on purpose; the line
	// breaks are replaced last so that nothing after this can put one back.
	s = forTerminal(s)
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.ReplaceAll(s, "\n", " ")
}

// indentedForTerminal is forTerminal for a value of several lines printed
// under a heading of its own, such as a message under the line that says who
// wrote it. Each line after the first starts with indent, so a line break in
// the value cannot start a line at the heading's depth: a visitor who copied
// the inbox's own layout into a handoff printed a line reading as a member of
// staff's reply, and a note printed one reading as a colleague's note.
//
// A carriage return before a line feed is the same line break: it is how a
// browser sends one from a text box, which is where a note in the admin and
// a visitor's message are typed. Left to forTerminal it was marked as the
// control character it is alone, and every line of an honest note of several
// lines ended in the mark that says somebody put an escape there. Taken out
// before forTerminal, so one that is not before a line feed is still marked.
func indentedForTerminal(s, indent string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(forTerminal(s), "\n", "\n"+indent)
}
