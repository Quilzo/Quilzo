package main

import (
	"strings"
	"testing"
)

// A terminal is not a text box.
//
// Content is written by whoever can write content, which on a site with
// contributors is not the person running the command. A string carrying ESC
// sequences can move the cursor, clear the line above, or change what is
// already on screen — so a page whose body begins with the right escape makes
// `quilzo search` print something other than what is in the store, and the
// operator reading the output has no way to tell.
func TestContentCannotDriveTheTerminal(t *testing.T) {
	attacks := map[string]string{
		"clear the line above": "\x1b[1A\x1b[2Kall clear, nothing to see",
		"colour the output":    "\x1b[31mFAILED\x1b[0m",
		"set the window title": "\x1b]0;something else\x07",
		"carriage return":      "real text\rforged text",
		"a bare escape":        "\x1bZ",
		"a C1 escape":          "\u009bJ",
		"a null":               "text\x00more",
	}
	for name, payload := range attacks {
		got := forTerminal(payload)
		for _, r := range got {
			if (r < 0x20 && r != '\t' && r != '\n') || r == 0x7f ||
				(r >= 0x80 && r <= 0x9f) {
				t.Errorf("%s: %q still carries control character %U",
					name, got, r)
			}
		}
	}
}

// The text itself survives, which is the point of printing it.
func TestOrdinaryContentIsUnchanged(t *testing.T) {
	for _, s := range []string{
		"a perfectly ordinary excerpt",
		"indigo, woad and madder — dyed in a railway arch",
		"a tab\tand a newline\nsurvive",
		"日本語のテキストも",
		"emoji stay too 🪴",
	} {
		if got := forTerminal(s); got != s {
			t.Errorf("ordinary text was changed:\n  in:  %q\n  out: %q", s, got)
		}
	}
}

// A control character is replaced rather than dropped, because content that
// contained one is a fact worth seeing — dropping it hides both the escape and
// the reason somebody put it there.
func TestAStrippedEscapeLeavesAMark(t *testing.T) {
	got := forTerminal("before\x1b[31mafter")
	if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Fatalf("the surrounding text was lost: %q", got)
	}
	if got == "beforeafter" {
		t.Error("the escape vanished without trace; a reader cannot tell " +
			"the content carried one")
	}
}
