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
